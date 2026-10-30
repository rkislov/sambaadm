package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Repair stages an entire policy tree. The original directory is retained on
// the destination DC, and both snapshots are durably stored on the application.
// Directory cutover is recoverable, not an atomic multi-directory transaction.
type repairObject struct {
	Path      string
	Directory bool
	Data, ACL []byte
}
type repairSnapshot struct {
	Objects   []repairObject
	Signature string
}
type RepairInput struct {
	Operation string `json:"operation"`
	Source    string `json:"source,omitempty"`
	Target    string `json:"target,omitempty"`
	Record    string `json:"record,omitempty"`
	Preview   string `json:"preview,omitempty"`
}
type RepairRecord struct {
	Format                                                int
	ID, GPO, Source, Target, Base, LDAP, State, Direction string
	Created                                               time.Time
	Before, After                                         *repairSnapshot
	Stage                                                 string
	Attempts                                              int
}
type RepairSummary struct {
	ID      string    `json:"id"`
	Source  string    `json:"source"`
	Target  string    `json:"target"`
	State   string    `json:"state"`
	Created time.Time `json:"created"`
}
type RepairACLChange struct {
	Path                                             string `json:"path"`
	Before, After                                    []GPFilterACE
	OwnerBefore, OwnerAfter, GroupBefore, GroupAfter string
	ProtectedBefore, ProtectedAfter                  bool
}
type RepairPlan struct {
	ACLChanges []RepairACLChange       `json:"aclChanges"`
	Preview    string                  `json:"preview"`
	Operation  string                  `json:"operation"`
	Source     string                  `json:"source"`
	Target     string                  `json:"target"`
	Record     string                  `json:"record,omitempty"`
	Changes    []ConsistencyDifference `json:"changes"`
	Warnings   []string                `json:"warnings"`
	record     *RepairRecord
}
type RepairResult struct {
	Record            string             `json:"record"`
	State             string             `json:"state"`
	Report            *ConsistencyReport `json:"report,omitempty"`
	VerificationError string             `json:"verificationError,omitempty"`
}

const repairRecordLimit = 200 << 20

func captureRepair(ctx context.Context, root policyStore) (*repairSnapshot, error) {
	first, e := scanPolicyTree(ctx, root, true)
	if e != nil {
		return nil, e
	}
	if first.Pending {
		return nil, fmt.Errorf("unfinished editor operation")
	}
	out := &repairSnapshot{Signature: first.Signature}
	sec := root.(policySecurityStore)
	for _, f := range first.Files {
		acl, e := sec.GetACL(f.Path)
		if e != nil {
			return nil, e
		}
		item := repairObject{Path: f.Path, Directory: f.Kind == "directory", ACL: acl}
		if !item.Directory {
			file, e := root.Open(f.Path)
			if e != nil {
				return nil, e
			}
			item.Data, e = io.ReadAll(io.LimitReader(file, consistencyBytes+1))
			e = errors.Join(e, file.Close())
			if e != nil {
				return nil, e
			}
			if len(item.Data) > consistencyBytes {
				return nil, fmt.Errorf("file exceeds limit")
			}
		}
		out.Objects = append(out.Objects, item)
	}
	second, e := scanPolicyTree(ctx, root, true)
	if e != nil {
		return nil, e
	}
	if second.Pending || first.Signature != second.Signature || repairSignature(out) != first.Signature {
		return nil, errConsistencyChanged
	}
	return out, nil
}
func repairSignature(s *repairSnapshot) string {
	if s == nil {
		return "missing"
	}
	files := []ConsistencyFile{}
	for _, o := range s.Objects {
		a, e := consistencyACL(o.ACL)
		if e != nil {
			return "invalid"
		}
		f := ConsistencyFile{Path: o.Path, Kind: "directory", ACL: a}
		if !o.Directory {
			f.Kind = "file"
			f.Size = int64(len(o.Data))
			f.SHA256 = fmt.Sprintf("%x", sha256.Sum256(o.Data))
		}
		files = append(files, f)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	var version *uint32
	for _, o := range s.Objects {
		if strings.EqualFold(o.Path, "GPT.INI") {
			v, _, e := gptVersion(o.Data, nil)
			if e == nil {
				version = &v
			}
		}
	}
	return consistencyHash([]any{files, version, false})
}
func repairStateRoot(parent *os.Root) (*os.Root, error) {
	if e := parent.Mkdir("repair", 0700); e != nil && !os.IsExist(e) {
		return nil, e
	}
	info, e := parent.Lstat("repair")
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("repair state must be private (0700)")
	}
	return parent.OpenRoot("repair")
}
func saveRepair(root *os.Root, r *RepairRecord) error {
	name, e := delegationRecordName(r.ID)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if len(raw) > repairRecordLimit {
		return fmt.Errorf("repair journal too large")
	}
	tmp := r.ID + "-" + uuid.NewString() + ".tmp"
	f, e := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	if e = root.Rename(tmp, name); e != nil {
		return e
	}
	d, e := root.Open(".")
	if e != nil {
		return e
	}
	return errors.Join(d.Sync(), d.Close())
}
func readRepair(root *os.Root, id string) (*RepairRecord, error) {
	name, e := delegationRecordName(id)
	if e != nil {
		return nil, e
	}
	st, e := root.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > repairRecordLimit {
		return nil, fmt.Errorf("invalid repair journal")
	}
	raw, e := root.ReadFile(name)
	if e != nil {
		return nil, e
	}
	r := &RepairRecord{}
	if e = json.Unmarshal(raw, r); e != nil {
		return nil, e
	}
	if (r.State != "pending" && r.State != "complete" && r.State != "rolled-back") || (r.Direction != "complete" && r.Direction != "rollback") || (r.Stage != "" && (!strings.HasPrefix(r.Stage, ".sambaadm-repair-"+r.ID+"-") || strings.ContainsAny(r.Stage, `/\:`))) {
		return nil, fmt.Errorf("invalid repair journal state")
	}
	if r.Format != 1 || r.ID != id || r.After == nil || len(r.After.Signature) != 64 || repairSignature(r.After) != r.After.Signature || (r.Before != nil && (len(r.Before.Signature) != 64 || repairSignature(r.Before) != r.Before.Signature)) {
		return nil, fmt.Errorf("invalid repair snapshot")
	}
	for _, snap := range []*repairSnapshot{r.Before, r.After} {
		if snap == nil {
			continue
		}
		if len(snap.Objects) == 0 || len(snap.Objects) > consistencyObjects {
			return nil, fmt.Errorf("invalid repair objects")
		}
		for _, o := range snap.Objects {
			if o.Path != "." && (path.Clean(o.Path) != o.Path || strings.HasPrefix(o.Path, "../") || path.IsAbs(o.Path) || strings.ContainsAny(o.Path, `\:`)) {
				return nil, fmt.Errorf("invalid repair path")
			}
		}
	}
	return r, nil
}
func repairRecords(root *os.Root, gpo string) ([]RepairSummary, error) {
	d, e := root.Open(".")
	if e != nil {
		return nil, e
	}
	entries, e := d.ReadDir(4097)
	d.Close()
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(entries) > 4096 {
		return nil, fmt.Errorf("repair history limit exceeded")
	}
	out := []RepairSummary{}
	for _, f := range entries {
		if !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		r, e := readRepair(root, strings.TrimSuffix(f.Name(), ".json"))
		if e != nil {
			return nil, e
		}
		if r.GPO == gpo {
			out = append(out, RepairSummary{r.ID, r.Source, r.Target, r.State, r.Created})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}

func repairACLChanges(a, b *repairSnapshot) []RepairACLChange {
	old := map[string]repairObject{}
	if a != nil {
		for _, o := range a.Objects {
			old[o.Path] = o
		}
	}
	out := []RepairACLChange{}
	if b == nil {
		return out
	}
	id := func(raw []byte, at int) string {
		if len(raw) < 20 {
			return ""
		}
		off := int(binary.LittleEndian.Uint32(raw[at:]))
		if off == 0 || off+8 > len(raw) {
			return ""
		}
		end := off + 8 + 4*int(raw[off+1])
		if end > len(raw) {
			return ""
		}
		return sidString(raw[off:end])
	}
	protected := func(raw []byte) bool { return len(raw) >= 4 && binary.LittleEndian.Uint16(raw[2:])&0x1000 != 0 }
	for _, n := range b.Objects {
		o := old[n.Path]
		x, _ := consistencyACL(o.ACL)
		y, _ := consistencyACL(n.ACL)
		if x == y {
			continue
		}
		c := RepairACLChange{Path: n.Path, Before: []GPFilterACE{}, After: []GPFilterACE{}, OwnerBefore: id(o.ACL, 4), OwnerAfter: id(n.ACL, 4), GroupBefore: id(o.ACL, 8), GroupAfter: id(n.ACL, 8), ProtectedBefore: protected(o.ACL), ProtectedAfter: protected(n.ACL)}
		for _, pair := range []struct {
			raw []byte
			dst *[]GPFilterACE
		}{{o.ACL, &c.Before}, {n.ACL, &c.After}} {
			aces, _ := policyACEs(pair.raw)
			for _, ace := range aces {
				*pair.dst = append(*pair.dst, filterACE(ace))
			}
		}
		out = append(out, c)
	}
	return out
}
