package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

const delegationRecordLimit = 16 << 20
const delegationPathLimit = 2048

type DelegationObject struct {
	Path      string `json:"path"`
	Directory bool   `json:"directory"`
	Before    []byte `json:"before"`
	After     []byte `json:"after"`
}
type DelegationRecord struct {
	Format     int                `json:"format"`
	ID         string             `json:"id"`
	Host       string             `json:"host"`
	DN         string             `json:"dn"`
	ObjectID   string             `json:"objectID"`
	Operation  string             `json:"operation"`
	Source     string             `json:"source,omitempty"`
	Profile    string             `json:"profile"`
	SID        string             `json:"sid"`
	State      string             `json:"state"`
	Created    time.Time          `json:"created"`
	LDAPBefore []byte             `json:"ldapBefore"`
	LDAPAfter  []byte             `json:"ldapAfter"`
	Files      []DelegationObject `json:"files"`
}
type DelegationOperation struct {
	Operation string `json:"operation"` // grant, revoke, complete, rollback
	Principal string `json:"principal,omitempty"`
	Profile   string `json:"profile,omitempty"` // read, read-apply, edit
	Source    string `json:"source,omitempty"`
	Preview   string `json:"preview,omitempty"`
}
type DelegationSummary struct {
	ID        string    `json:"id"`
	Operation string    `json:"operation"`
	Source    string    `json:"source,omitempty"`
	Profile   string    `json:"profile"`
	SID       string    `json:"sid"`
	State     string    `json:"state"`
	Created   time.Time `json:"created"`
	Revoked   bool      `json:"revoked"`
}
type DelegationState struct {
	Records []DelegationSummary `json:"records"`
	Pending string              `json:"pending,omitempty"`
}
type DelegationPlanFile struct {
	Path    string        `json:"path"`
	State   string        `json:"state"`
	Changed bool          `json:"changed"`
	Added   []GPFilterACE `json:"added"`
	Removed []GPFilterACE `json:"removed"`
}
type DelegationPlan struct {
	Preview      string               `json:"preview"`
	Operation    string               `json:"operation"`
	Source       string               `json:"source,omitempty"`
	DN           string               `json:"dn"`
	SID          string               `json:"sid"`
	Profile      string               `json:"profile"`
	LDAPState    string               `json:"ldapState"`
	LDAPChanged  bool                 `json:"ldapChanged"`
	LDAPAdded    []GPFilterACE        `json:"ldapAdded"`
	LDAPRemoved  []GPFilterACE        `json:"ldapRemoved"`
	Files        []DelegationPlanFile `json:"files"`
	Conflicts    []string             `json:"conflicts"`
	record       *DelegationRecord
	ldapRevision string
	currentLDAP  []byte
	currentFiles []DelegationObject
}

// normalizeDACL compares only the DACL and its protection bit. Owner/group/SACL
// are neither rewritten nor restored by delegation.
func normalizeDACL(sd []byte) ([]byte, error) {
	aces, err := policyACEs(sd)
	if err != nil {
		return nil, err
	}
	base := make([]byte, 28)
	base[0] = 1
	base[20] = 4
	binary.LittleEndian.PutUint16(base[2:], 0x8004|(binary.LittleEndian.Uint16(sd[2:])&0x1000))
	binary.LittleEndian.PutUint32(base[16:], 20)
	binary.LittleEndian.PutUint16(base[22:], 8)
	return daclDescriptor(base, aces)
}
func delegationFileACE(sid []byte, profile string, dir bool) ([]byte, error) {
	if sidString(sid) == "" {
		return nil, topologyBad("invalid SID")
	}
	mask := uint32(0x1200a9) // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE.
	switch profile {
	case "read", "read-apply":
	case "edit":
		mask = 0x1301bf
	default:
		return nil, topologyBad("unknown delegation profile")
	}
	a := make([]byte, 8)
	if dir {
		a[1] = 3
	}
	// Do not grant DELETE on the GPO root itself; DELETE_CHILD suffices for files.
	if dir && profile == "edit" {
		mask = (mask &^ 0x10000) | 0x40
	}
	binary.LittleEndian.PutUint16(a[2:], uint16(8+len(sid)))
	binary.LittleEndian.PutUint32(a[4:], mask)
	return append(a, sid...), nil
}
func delegationTree(root policyStore) ([]DelegationObject, error) {
	secure, ok := root.(policySecurityStore)
	if !ok {
		return nil, fmt.Errorf("SYSVOL ACL access unavailable")
	}
	out := []DelegationObject{}
	total := 0
	var walk func(string, int) error
	walk = func(name string, depth int) error {
		if depth > 64 || len(out) >= delegationPathLimit {
			return fmt.Errorf("delegation tree limit exceeded")
		}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("unsupported SYSVOL object %s", name)
		}
		raw, err := secure.GetACL(name)
		if err != nil {
			return err
		}
		acl, err := normalizeDACL(raw)
		if err != nil {
			return err
		}
		total += len(acl)
		if total > 4<<20 {
			return fmt.Errorf("SYSVOL ACL snapshot exceeds limit")
		}
		out = append(out, DelegationObject{Path: name, Directory: info.IsDir(), Before: acl, After: acl})
		if info.IsDir() {
			entries, err := root.ReadDir(name)
			if err != nil {
				return err
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			for _, entry := range entries {
				n := entry.Name()
				if name == "." && strings.HasPrefix(strings.ToLower(n), ".sambaadm-") {
					continue
				}
				if n == "." || n == ".." || strings.ContainsAny(n, `/\:`) {
					return fmt.Errorf("invalid SYSVOL name")
				}
				if err := walk(path.Join(name, n), depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	err := walk(".", 0)
	return out, err
}
func (s *GPOService) delegationStateRoot() (*os.Root, error) {
	dir := s.gpoCfg.DelegationStateDir
	if dir == "" || !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("configure absolute gpo.delegation_state_dir")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("delegation state directory must be a private directory (0700)")
	}
	return os.OpenRoot(dir)
}
func delegationRecordName(id string) (string, error) {
	parsed, err := uuid.Parse(id)
	if err != nil || parsed.String() != id {
		return "", topologyBad("invalid delegation record ID")
	}
	return id + ".json", nil
}
func readDelegationRecord(root *os.Root, id string) (*DelegationRecord, error) {
	name, err := delegationRecordName(id)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > delegationRecordLimit {
		return nil, fmt.Errorf("invalid delegation record")
	}
	raw, err := root.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var rec DelegationRecord
	if err = json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	if rec.Format != 1 || rec.ID != id || len(rec.Files) == 0 || len(rec.Files) > delegationPathLimit {
		return nil, fmt.Errorf("invalid delegation record format")
	}
	return &rec, nil
}
func saveDelegationRecord(root *os.Root, rec *DelegationRecord) error {
	name, err := delegationRecordName(rec.ID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if len(raw) > delegationRecordLimit {
		return fmt.Errorf("delegation record too large")
	}
	tmp := rec.ID + "-" + uuid.NewString() + ".tmp"
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(raw)
	err = writeErr
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = root.Rename(tmp, name); err != nil {
		return err
	}
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
func delegationRecords(root *os.Root, host, dn string, objectID ...string) ([]DelegationRecord, error) {
	d, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return nil, err
	}
	if len(entries) > 4096 {
		return nil, fmt.Errorf("delegation history exceeds limit")
	}
	out := []DelegationRecord{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		rec, err := readDelegationRecord(root, strings.TrimSuffix(e.Name(), ".json"))
		if err != nil {
			return nil, err
		}
		if (host == "" || rec.Host == host) && dnEqual(rec.DN, dn) && (len(objectID) == 0 || rec.ObjectID == objectID[0]) {
			out = append(out, *rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out, nil
}
func delegationHistory(records []DelegationRecord) DelegationState {
	state := DelegationState{Records: []DelegationSummary{}}
	revoked := map[string]bool{}
	for _, r := range records {
		if r.State == "complete" && r.Operation == "revoke" {
			revoked[r.Source] = true
		}
	}
	for _, r := range records {
		state.Records = append(state.Records, DelegationSummary{r.ID, r.Operation, r.Source, r.Profile, r.SID, r.State, r.Created, revoked[r.ID]})
		if r.State == "pending" {
			state.Pending = r.ID
		}
	}
	return state
}
func aclState(current, before, after []byte) string {
	if bytes.Equal(current, before) {
		if bytes.Equal(before, after) {
			return "unchanged"
		}
		return "before"
	}
	if bytes.Equal(current, after) {
		return "after"
	}
	return "conflict"
}
func sameDelegationTree(a, b []DelegationObject) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Path != b[i].Path || a[i].Directory != b[i].Directory {
			return false
		}
	}
	return true
}

func buildDelegationPlan(root policyStore, local *os.Root, host string, entry *ldap.Entry, in DelegationOperation, sid []byte) (*DelegationPlan, error) {
	if len(entry.GetRawAttributeValue("objectGUID")) != 16 {
		return nil, fmt.Errorf("GPO objectGUID is required for trusted recovery")
	}
	objectID := fmt.Sprintf("%x", entry.GetRawAttributeValue("objectGUID"))
	records, err := delegationRecords(local, host, entry.DN, objectID)
	if err != nil {
		return nil, err
	}
	history := delegationHistory(records)
	if in.Operation == "grant" || in.Operation == "revoke" {
		if _, e := root.Lstat(editorJournal); !os.IsNotExist(e) {
			if e != nil {
				return nil, e
			}
			return nil, fmt.Errorf("recover existing policy journal before changing ACLs")
		}
	}
	current, err := normalizeDACL(entry.GetRawAttributeValue("nTSecurityDescriptor"))
	if err != nil {
		return nil, err
	}
	files, err := delegationTree(root)
	if err != nil {
		return nil, err
	}
	p := &DelegationPlan{Operation: in.Operation, Source: in.Source, DN: entry.DN, Files: []DelegationPlanFile{}, Conflicts: []string{}, ldapRevision: entry.GetAttributeValue("uSNChanged"), currentLDAP: current, currentFiles: files}
	switch in.Operation {
	case "grant":
		if history.Pending != "" {
			return nil, fmt.Errorf("recover pending delegation %s first", history.Pending)
		}
		profile := in.Profile
		if profile == "edit" {
			profile = "edit-ldap"
		}
		additions, err := delegationACEs(sid, profile)
		if err != nil {
			return nil, err
		}
		after, _, err := delegationDescriptor(current, additions)
		if err != nil {
			return nil, err
		}
		rec := &DelegationRecord{Format: 1, Host: host, DN: entry.DN, ObjectID: objectID, Operation: "grant", Profile: in.Profile, SID: sidString(sid), State: "pending", LDAPBefore: current, LDAPAfter: after, Files: append([]DelegationObject(nil), files...)}
		for i := range rec.Files {
			ace, err := delegationFileACE(sid, in.Profile, rec.Files[i].Directory)
			if err != nil {
				return nil, err
			}
			rec.Files[i].After, _, err = delegationDescriptor(rec.Files[i].Before, [][]byte{ace})
			if err != nil {
				return nil, err
			}
		}
		p.record = rec
	case "revoke", "complete", "rollback":
		rec, err := readDelegationRecord(local, in.Source)
		if err != nil {
			return nil, err
		}
		if rec.Host != host || !dnEqual(rec.DN, entry.DN) || rec.ObjectID != objectID {
			return nil, topologyBad("record belongs to another GPO/controller")
		}
		if in.Operation == "revoke" {
			if history.Pending != "" {
				return nil, fmt.Errorf("recover pending delegation first")
			}
			if rec.Operation != "grant" || rec.State != "complete" {
				return nil, topologyBad("only a completed grant can be revoked")
			}
			for _, r := range history.Records {
				if r.ID == rec.ID && r.Revoked {
					return nil, topologyBad("grant already revoked")
				}
			}
			copyRec := *rec
			copyRec.ID = ""
			copyRec.State = "pending"
			copyRec.Operation = "revoke"
			copyRec.Source = rec.ID
			copyRec.LDAPBefore, copyRec.LDAPAfter = rec.LDAPAfter, rec.LDAPBefore
			copyRec.Files = append([]DelegationObject(nil), rec.Files...)
			for i := range copyRec.Files {
				copyRec.Files[i].Before, copyRec.Files[i].After = rec.Files[i].After, rec.Files[i].Before
			}
			p.record = &copyRec
		} else {
			if rec.State != "pending" || history.Pending != rec.ID {
				return nil, topologyBad("only pending operations can be recovered")
			}
			p.record = rec
		}
	default:
		return nil, topologyBad("operation must be grant, revoke, complete or rollback")
	}
	rec := p.record
	p.SID = rec.SID
	p.Profile = rec.Profile
	if !sameDelegationTree(files, rec.Files) {
		p.Conflicts = append(p.Conflicts, "SYSVOL tree changed")
	}
	p.LDAPState = aclState(current, rec.LDAPBefore, rec.LDAPAfter)
	ldapTarget := rec.LDAPAfter
	if in.Operation == "rollback" {
		ldapTarget = rec.LDAPBefore
	}
	p.LDAPChanged = !bytes.Equal(current, ldapTarget)
	p.LDAPAdded, p.LDAPRemoved = delegationACLDiff(current, ldapTarget)
	if p.LDAPState == "conflict" || (in.Operation == "revoke" && p.LDAPState == "after") {
		p.Conflicts = append(p.Conflicts, "LDAP DACL")
	}
	byPath := map[string]DelegationObject{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	for _, f := range rec.Files {
		state := aclState(byPath[f.Path].Before, f.Before, f.After)
		target := f.After
		if in.Operation == "rollback" {
			target = f.Before
		}
		added, removed := delegationACLDiff(byPath[f.Path].Before, target)
		p.Files = append(p.Files, DelegationPlanFile{Path: f.Path, State: state, Changed: !bytes.Equal(byPath[f.Path].Before, target), Added: added, Removed: removed})
		if state == "conflict" || (in.Operation == "revoke" && state == "after") {
			p.Conflicts = append(p.Conflicts, f.Path)
		}
	}
	raw, _ := json.Marshal([]any{in.Operation, in.Source, in.Principal, in.Profile, rec, files, current, p.ldapRevision})
	p.Preview = fmt.Sprintf("%x", sha256.Sum256(raw))
	return p, nil
}

type delegationDACLStore interface{ SetDACL(string, []byte) error }

func delegationLock(root policyStore, id string, recovery bool) error {
	f, err := root.OpenFile(editorJournal, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if !os.IsExist(err) || !recovery {
			return fmt.Errorf("policy journal already exists or is unavailable: %w", err)
		}
		data, e := readPolicyFile(root, editorJournal)
		if e != nil {
			return e
		}
		var marker struct {
			Format     int
			Delegation string
		}
		if json.Unmarshal(data, &marker) != nil || marker.Format != 3 || marker.Delegation != id {
			return fmt.Errorf("journal does not belong to this delegation; inspect it before recovery")
		}
		return nil
	}
	raw, _ := json.Marshal(struct {
		Format     int
		Delegation string
	}{3, id})
	n, writeErr := f.Write(raw)
	err = writeErr
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

// A failed operation retains both the trusted local record and SYSVOL marker.
// Recovery accepts only exact before/after ACLs; it never overwrites a third state.
func applyDelegationPlan(root policyStore, local *os.Root, p *DelegationPlan, readLDAP func() ([]byte, string, error), writeLDAP func([]byte, string) error) error {
	if len(p.Conflicts) > 0 {
		return ErrTopologyConflict
	}
	secure, ok := root.(delegationDACLStore)
	if !ok {
		return fmt.Errorf("DACL-only writes unavailable")
	}
	rec := p.record
	recovery := p.Operation == "complete" || p.Operation == "rollback"
	if !recovery {
		rec.ID = uuid.NewString()
		rec.Created = time.Now().UTC()
		if err := saveDelegationRecord(local, rec); err != nil {
			return err
		}
	}
	pending := func(err error) error {
		return fmt.Errorf("delegation %s pending; recover on this sambaadm instance: %w", rec.ID, err)
	}
	if err := delegationLock(root, rec.ID, recovery); err != nil {
		return pending(err)
	}
	// Recheck after taking the cooperative journal, before the first ACL write.
	current, rev, err := readLDAP()
	if err != nil {
		return pending(err)
	}
	tree, err := delegationTree(root)
	if err != nil {
		return pending(err)
	}
	if rev != p.ldapRevision || !bytes.Equal(current, p.currentLDAP) || !sameDelegationTree(tree, p.currentFiles) {
		return pending(ErrTopologyConflict)
	}
	for i := range tree {
		if !bytes.Equal(tree[i].Before, p.currentFiles[i].Before) {
			return pending(ErrTopologyConflict)
		}
	}
	rollback := p.Operation == "rollback"
	// Children first, root last. Existing ACLs are edited individually; directory
	// ACEs also carry inheritance for future descendants.
	for i := len(rec.Files) - 1; i >= 0; i-- {
		f := rec.Files[i]
		target := f.After
		if rollback {
			target = f.Before
		}
		raw, err := root.(policySecurityStore).GetACL(f.Path)
		if err != nil {
			return pending(err)
		}
		current, err := normalizeDACL(raw)
		if err != nil {
			return pending(err)
		}
		if aclState(current, f.Before, f.After) == "conflict" {
			return pending(ErrTopologyConflict)
		}
		if !bytes.Equal(current, target) {
			if err := secure.SetDACL(f.Path, target); err != nil {
				return pending(err)
			}
		}
	}
	// Verify all files before committing LDAP, including the unchanged tree.
	if err := verifyDelegationFiles(root, rec, rollback); err != nil {
		return pending(err)
	}
	target := rec.LDAPAfter
	if rollback {
		target = rec.LDAPBefore
	}
	if !bytes.Equal(p.currentLDAP, target) {
		if err := writeLDAP(target, p.ldapRevision); err != nil {
			return pending(err)
		}
	}
	current, _, err = readLDAP()
	if err != nil {
		return pending(err)
	}
	if !bytes.Equal(current, target) {
		return pending(ErrTopologyConflict)
	}
	if err = verifyDelegationFiles(root, rec, rollback); err != nil {
		return pending(err)
	}
	if err = root.Remove(editorJournal); err != nil {
		return pending(err)
	}
	rec.State = "complete"
	if rollback {
		rec.State = "rolled-back"
	}
	if err = saveDelegationRecord(local, rec); err != nil {
		rec.State = "pending"
		return pending(err)
	}
	return nil
}
func verifyDelegationFiles(root policyStore, rec *DelegationRecord, rollback bool) error {
	current, err := delegationTree(root)
	if err != nil {
		return err
	}
	if !sameDelegationTree(current, rec.Files) {
		return ErrTopologyConflict
	}
	for i := range current {
		target := rec.Files[i].After
		if rollback {
			target = rec.Files[i].Before
		}
		if !bytes.Equal(current[i].Before, target) {
			return fmt.Errorf("ACL verification failed: %s: %w", current[i].Path, ErrTopologyConflict)
		}
	}
	return nil
}

func (s *GPOService) withDelegation(ctx context.Context, gpo string, fn func(policyStore, *os.Root, *ldap.Entry) error) error {
	if s.remote == nil {
		return fmt.Errorf("SYSVOL credentials required")
	}
	local, err := s.delegationStateRoot()
	if err != nil {
		return err
	}
	defer local.Close()
	return s.scriptMaintenanceContext(ctx, gpo, func(root policyStore, _ *ldap.Entry) error {
		entry, err := s.filterEntry(ctx, gpo)
		if err != nil {
			return err
		}
		return fn(root, local, entry)
	})
}
func (s *GPOService) FullDelegationState(ctx context.Context, gpo string) (out *DelegationState, err error) {
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	err = s.withDelegation(ctx, gpo, func(_ policyStore, local *os.Root, entry *ldap.Entry) error {
		records, e := delegationRecords(local, s.remote.Host, entry.DN, fmt.Sprintf("%x", entry.GetRawAttributeValue("objectGUID")))
		if e != nil {
			return e
		}
		state := delegationHistory(records)
		out = &state
		return nil
	})
	return
}
func (s *GPOService) FullDelegationPreview(ctx context.Context, gpo string, in DelegationOperation) (out *DelegationPlan, err error) {
	if err = validateDelegationOperation(in); err != nil {
		return nil, err
	}
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	err = s.withDelegation(ctx, gpo, func(root policyStore, local *os.Root, entry *ldap.Entry) error {
		var sid []byte
		var e error
		if in.Operation == "grant" {
			sid, e = s.delegationSID(ctx, in.Principal)
			if e != nil {
				return e
			}
		}
		out, e = buildDelegationPlan(root, local, s.remote.Host, entry, in, sid)
		return e
	})
	return
}
func (s *GPOService) FullDelegationApply(ctx context.Context, gpo string, in DelegationOperation, actor, ip string) (err error) {
	if err = validateDelegationOperation(in); err != nil {
		return err
	}
	if in.Preview == "" {
		return topologyBad("preview required")
	}
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	defer func() {
		if err != nil {
			s.audit.Failure(actor, "gpo.delegation."+in.Operation, gpo, ip, err)
		} else {
			s.audit.Success(actor, "gpo.delegation."+in.Operation, gpo, ip)
		}
	}()
	return s.withDelegation(ctx, gpo, func(root policyStore, local *os.Root, entry *ldap.Entry) error {
		var sid []byte
		var e error
		if in.Operation == "grant" {
			sid, e = s.delegationSID(ctx, in.Principal)
			if e != nil {
				return e
			}
		}
		plan, e := buildDelegationPlan(root, local, s.remote.Host, entry, in, sid)
		if e != nil {
			return e
		}
		if plan.Preview != in.Preview {
			return ErrTopologyConflict
		}
		return applyDelegationPlan(root, local, plan, func() ([]byte, string, error) {
			entry, e := s.filterEntry(ctx, gpo)
			if e != nil {
				return nil, "", e
			}
			acl, e := normalizeDACL(entry.GetRawAttributeValue("nTSecurityDescriptor"))
			return acl, entry.GetAttributeValue("uSNChanged"), e
		}, func(data []byte, revision string) error {
			controls, e := assertion(revision)
			if e != nil {
				return e
			}
			controls = append(controls, daclControl)
			req := ldap.NewModifyRequest(entry.DN, controls)
			req.Replace("nTSecurityDescriptor", []string{string(data)})
			return topologyError(s.ldap.Modify(ctx, req))
		})
	})
}

func (s *GPOService) ensureNoDelegationPending(dn string) error {
	if s.gpoCfg.DelegationStateDir == "" || s.remote == nil {
		return nil
	}
	if _, err := os.Lstat(s.gpoCfg.DelegationStateDir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	root, err := s.delegationStateRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	records, err := delegationRecords(root, s.remote.Host, dn)
	if err != nil {
		return err
	}
	if pending := delegationHistory(records).Pending; pending != "" {
		return fmt.Errorf("recover pending delegation %s before changing LDAP permissions", pending)
	}
	return nil
}
func validateDelegationOperation(in DelegationOperation) error {
	switch in.Operation {
	case "grant":
		if in.Principal == "" || in.Source != "" || (in.Profile != "read" && in.Profile != "read-apply" && in.Profile != "edit") {
			return topologyBad("grant requires principal and read/read-apply/edit profile")
		}
	case "revoke", "complete", "rollback":
		if _, err := delegationRecordName(in.Source); err != nil {
			return err
		}
		if in.Principal != "" || in.Profile != "" {
			return topologyBad("recovery/revoke accepts a source ID only")
		}
	default:
		return topologyBad("invalid delegation operation")
	}
	return nil
}

func delegationACLDiff(before, after []byte) (added, removed []GPFilterACE) {
	added = []GPFilterACE{}
	removed = []GPFilterACE{}
	a, e := policyACEs(before)
	if e != nil {
		return
	}
	b, e := policyACEs(after)
	if e != nil {
		return
	}
	oldCount, newCount := map[string]int{}, map[string]int{}
	for _, v := range a {
		oldCount[filterACE(v).ID]++
	}
	for _, v := range b {
		newCount[filterACE(v).ID]++
	}
	for _, v := range b {
		ace := filterACE(v)
		if oldCount[ace.ID] > 0 {
			oldCount[ace.ID]--
		} else {
			added = append(added, ace)
		}
	}
	for _, v := range a {
		ace := filterACE(v)
		if newCount[ace.ID] > 0 {
			newCount[ace.ID]--
		} else {
			removed = append(removed, ace)
		}
	}
	return
}
