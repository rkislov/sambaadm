package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
)

var errConsistencyChanged = errors.New("SYSVOL changed during read")
var ErrConsistencyBusy = errors.New("another GPO consistency check is running")

const consistencyObjects = 2048
const consistencyBytes = 64 << 20
const consistencyDiffs = 500

type ConsistencyInput struct {
	Reference string `json:"reference,omitempty"`
}
type ConsistencyFile struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
	ACL    string `json:"acl"`
}
type ConsistencyDifference struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	Reference string `json:"reference,omitempty"`
	Value     string `json:"value,omitempty"`
}
type ConsistencyDC struct {
	Name            string                  `json:"name"`
	DNS             string                  `json:"dns"`
	Status          string                  `json:"status"`
	LDAP            string                  `json:"ldap"`
	SYSVOL          string                  `json:"sysvol"`
	LDAPVersion     *uint32                 `json:"ldapVersion,omitempty"`
	GPTVersion      *uint32                 `json:"gptVersion,omitempty"`
	LDAPACL         string                  `json:"ldapACL,omitempty"`
	Metadata        string                  `json:"metadata,omitempty"`
	MetadataFields  map[string]string       `json:"metadataFields,omitempty"`
	Pending         bool                    `json:"pending"`
	Files           []ConsistencyFile       `json:"files"`
	Errors          []string                `json:"errors"`
	Differences     []ConsistencyDifference `json:"differences"`
	DifferenceCount int                     `json:"differenceCount"`
	checked         bool
}
type ConsistencyReport struct {
	GPO            string          `json:"gpo"`
	Started        time.Time       `json:"started"`
	Finished       time.Time       `json:"finished"`
	Status         string          `json:"status"`
	Complete       bool            `json:"complete"`
	HasDifferences bool            `json:"hasDifferences"`
	Reference      string          `json:"reference"`
	Controllers    []ConsistencyDC `json:"controllers"`
	Limitations    []string        `json:"limitations"`
}
type consistencySnapshot struct {
	Files     []ConsistencyFile
	GPT       *uint32
	Pending   bool
	Signature string
}

func consistencyHash(v any) string {
	raw, _ := json.Marshal(v)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// Owner/group and ordered DACL are compared structurally; SACL/effective access
// are deliberately not inferred. Ignore descriptor offsets and ACL revision.
func consistencyACL(sd []byte) (string, error) {
	dacl, err := normalizeDACL(sd)
	if err != nil {
		return "", err
	}
	ids := []string{}
	for _, at := range []int{4, 8} {
		off := int(binary.LittleEndian.Uint32(sd[at:]))
		if off == 0 {
			ids = append(ids, "")
			continue
		}
		if off < 20 || off+8 > len(sd) {
			return "", fmt.Errorf("invalid security descriptor SID")
		}
		end := off + 8 + 4*int(sd[off+1])
		if end > len(sd) {
			return "", fmt.Errorf("invalid SID size")
		}
		sid := sidString(sd[off:end])
		if sid == "" {
			return "", fmt.Errorf("invalid SID")
		}
		ids = append(ids, sid)
	}
	return consistencyHash([]any{ids, dacl}), nil
}
func scanConsistencyTree(ctx context.Context, root policyStore) (*consistencySnapshot, error) {
	secure, ok := root.(policySecurityStore)
	if !ok {
		return nil, fmt.Errorf("SYSVOL ACL read unavailable")
	}
	snap := &consistencySnapshot{Files: []ConsistencyFile{}}
	total := int64(0)
	seen := map[string]bool{}
	var walk func(string, int) error
	walk = func(name string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > 64 || len(snap.Files) >= consistencyObjects {
			return fmt.Errorf("SYSVOL object/depth limit exceeded")
		}
		key := strings.ToLower(name)
		if seen[key] {
			return fmt.Errorf("ambiguous case-insensitive SYSVOL path: %s", name)
		}
		seen[key] = true
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("unsupported SYSVOL object: %s", name)
		}
		raw, err := secure.GetACL(name)
		if err != nil {
			return fmt.Errorf("read ACL %s: %w", name, err)
		}
		acl, err := consistencyACL(raw)
		if err != nil {
			return err
		}
		item := ConsistencyFile{Path: name, Kind: "directory", ACL: acl}
		if !info.IsDir() {
			item.Kind = "file"
			item.Size = info.Size()
			if item.Size < 0 || item.Size > consistencyBytes-total {
				return fmt.Errorf("SYSVOL content exceeds 64 MiB")
			}
			f, err := root.Open(name)
			if err != nil {
				return err
			}
			h := sha256.New()
			n, err := io.Copy(h, io.LimitReader(f, consistencyBytes-total+1))
			after, se := f.Stat()
			ce := f.Close()
			if err = errors.Join(err, se, ce); err != nil {
				return err
			}
			if n > consistencyBytes-total {
				return fmt.Errorf("SYSVOL content exceeds 64 MiB")
			}
			total += n
			if n != item.Size || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
				return fmt.Errorf("%w: %s", errConsistencyChanged, name)
			}
			item.SHA256 = fmt.Sprintf("%x", h.Sum(nil))
			if strings.EqualFold(name, "GPT.INI") {
				data, err := readPolicyFile(root, name)
				if err != nil {
					return err
				}
				if fmt.Sprintf("%x", sha256.Sum256(data)) != item.SHA256 {
					return fmt.Errorf("%w: GPT.INI", errConsistencyChanged)
				}
				v, _, err := gptVersion(data, nil)
				if err != nil {
					return err
				}
				snap.GPT = &v
			}
		}
		snap.Files = append(snap.Files, item)
		if info.IsDir() {
			entries, err := root.ReadDir(name)
			if err != nil {
				return err
			}
			sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
			for _, e := range entries {
				n := e.Name()
				if name == "." && strings.HasPrefix(strings.ToLower(n), ".sambaadm-") {
					if strings.EqualFold(n, editorJournal) {
						snap.Pending = true
					}
					continue
				}
				if n == "." || n == ".." || strings.ContainsAny(n, `/\:`) {
					return fmt.Errorf("invalid SYSVOL entry")
				}
				if err := walk(path.Join(name, n), depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(".", 0); err != nil {
		return snap, err
	}
	if snap.GPT == nil {
		return snap, fmt.Errorf("GPT.INI is missing")
	}
	sort.Slice(snap.Files, func(i, j int) bool { return snap.Files[i].Path < snap.Files[j].Path })
	snap.Signature = consistencyHash([]any{snap.Files, snap.GPT, snap.Pending})
	return snap, nil
}

var consistencyAttributes = []string{"name", "objectGUID", "gPCFileSysPath", "versionNumber", "flags", "gPCMachineExtensionNames", "gPCUserExtensionNames", "gPCWQLFilter", "uSNChanged", "nTSecurityDescriptor"}

func readConsistencyLDAP(ctx context.Context, client *GPOService, guid string) (*ldap.Entry, error) {
	conn, err := client.ldap.Conn(ctx)
	if err != nil {
		return nil, err
	}
	dn := "CN=" + ldap.EscapeDN(braceGUID(guid)) + ",CN=Policies,CN=System," + client.ldap.BaseDN()
	control := ldap.NewControlString("1.2.840.113556.1.4.801", true, string([]byte{0x30, 0x03, 0x02, 0x01, 0x07}))
	result, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=groupPolicyContainer)", consistencyAttributes, []ldap.Control{control}))
	if err != nil {
		return nil, err
	}
	if len(result.Entries) != 1 {
		return nil, fmt.Errorf("GPO not visible in LDAP")
	}
	return result.Entries[0], nil
}
func consistencyMetadata(entry *ldap.Entry) (string, error) {
	if len(entry.GetRawAttributeValue("objectGUID")) != 16 {
		return "", fmt.Errorf("objectGUID unavailable")
	}
	values := []any{entry.GetRawAttributeValue("objectGUID")}
	for _, name := range []string{"flags", "gPCMachineExtensionNames", "gPCUserExtensionNames", "gPCWQLFilter"} {
		values = append(values, entry.GetAttributeValues(name))
	}
	return consistencyHash(values), nil
}
func consistencyPeerURI(uri, host string) (string, error) {
	// Only discovery-provided DNS names may be used, never arbitrary URL input.
	if host == "" || strings.ContainsAny(host, "/:\\@?# \t\r\n") || strings.HasPrefix(host, "-") {
		return "", topologyBad("invalid DC DNS name")
	}
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
		return "", fmt.Errorf("network LDAP/LDAPS configuration required")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "ldaps" {
			port = "636"
		} else {
			port = "389"
		}
	}
	return (&url.URL{Scheme: u.Scheme, Host: net.JoinHostPort(host, port)}).String(), nil
}
func (s *GPOService) probeConsistency(ctx context.Context, guid, base string, dc Controller, primary string) ConsistencyDC {
	out := ConsistencyDC{Name: dc.Name, DNS: dc.DNS, Status: "incomplete", LDAP: "unavailable", SYSVOL: "unavailable", Files: []ConsistencyFile{}, Errors: []string{}, Differences: []ConsistencyDifference{}}
	uri, err := consistencyPeerURI(s.ldap.URI(), dc.DNS)
	if err != nil {
		out.Errors = append(out.Errors, err.Error())
		return out
	}
	remote := *s.remote
	remote.Host = dc.DNS
	if strings.EqualFold(primary, dc.DNS) {
		uri = s.ldap.URI()
		remote.Host = s.remote.Host
	}
	peer := s.ldap.ServicePeer(uri)
	defer peer.Close()
	other := &GPOService{ldap: peer, remote: &remote, gpoCfg: s.gpoCfg}
	var before *ldap.Entry
	conn, e := peer.Conn(ctx)
	if e == nil {
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer stop()
		out.LDAP = "error"
		root, er := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"dNSHostName"}, nil))
		e = er
		if e == nil && (len(root.Entries) != 1 || !strings.EqualFold(root.Entries[0].GetEqualFoldAttributeValue("dNSHostName"), dc.DNS)) {
			e = fmt.Errorf("LDAP endpoint identity does not match selected DC")
		}
	}
	if e == nil {
		before, e = readConsistencyLDAP(ctx, other, guid)
	}
	if e != nil {
		if ldap.IsErrorWithCode(e, ldap.LDAPResultNoSuchObject) {
			out.LDAP = "missing"
		}
		out.Errors = append(out.Errors, "LDAP: "+e.Error())
	} else {
		out.LDAP = "error"
		n, er := strconv.ParseUint(before.GetAttributeValue("versionNumber"), 10, 32)
		if er == nil {
			v := uint32(n)
			out.LDAPVersion = &v
			out.LDAPACL, er = consistencyACL(before.GetRawAttributeValue("nTSecurityDescriptor"))
		}
		if er == nil {
			out.Metadata, er = consistencyMetadata(before)
			out.MetadataFields = map[string]string{"objectGUID": fmt.Sprintf("%x", before.GetRawAttributeValue("objectGUID"))}
			for _, key := range []string{"flags", "gPCMachineExtensionNames", "gPCUserExtensionNames", "gPCWQLFilter"} {
				out.MetadataFields[key] = strings.Join(before.GetAttributeValues(key), "; ")
			}
		}
		if er == nil {
			_, er = other.policyPath(ctx, before)
		}
		if er == nil {
			out.LDAP = "ok"
		} else {
			out.Errors = append(out.Errors, "LDAP: "+er.Error())
		}
	}
	e = remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		out.SYSVOL = "error"
		store := &smbPolicyStore{share: sh, base: strings.ReplaceAll(base, `\`, "/")}
		first, err := scanConsistencyTree(ctx, store)
		if first != nil {
			out.Pending = first.Pending
		}
		if err != nil {
			return err
		}
		second, err := scanConsistencyTree(ctx, store)
		if second != nil {
			out.Pending = out.Pending || second.Pending
		}
		if err != nil {
			return err
		}
		out.Files = second.Files
		out.GPTVersion = second.GPT
		out.Pending = first.Pending || second.Pending
		if first.Signature != second.Signature {
			out.Status = "changing"
			return fmt.Errorf("SYSVOL changed between reads")
		}
		out.SYSVOL = "ok"
		return nil
	})
	if e != nil {
		if errors.Is(e, errConsistencyChanged) {
			out.Status = "changing"
		}
		if os.IsNotExist(e) {
			out.SYSVOL = "missing"
		}
		out.Errors = append(out.Errors, "SYSVOL: "+e.Error())
	}
	if before != nil && out.LDAP == "ok" {
		after, e := readConsistencyLDAP(ctx, other, guid)
		if e != nil {
			out.LDAP = "error"
			out.Errors = append(out.Errors, "LDAP recheck: "+e.Error())
		} else if after.GetAttributeValue("uSNChanged") != before.GetAttributeValue("uSNChanged") {
			out.Status = "changing"
			out.Errors = append(out.Errors, "LDAP changed during read")
		}
	}
	if out.Status != "changing" {
		if out.Pending {
			out.Status = "pending"
		} else if out.LDAP == "ok" && out.SYSVOL == "ok" {
			out.Status = "ready"
			out.checked = true
		} else if out.LDAP == "unavailable" && out.SYSVOL == "unavailable" {
			out.Status = "unavailable"
		}
	}
	return out
}

func (s *GPOService) CheckConsistency(ctx context.Context, guid string, in ConsistencyInput) (*ConsistencyReport, error) {
	if !looksLikeGUID(guid) {
		return nil, topologyBad("GPO GUID required")
	}
	if !s.consistencyMu.TryLock() {
		return nil, ErrConsistencyBusy
	}
	defer s.consistencyMu.Unlock()
	if s.remote == nil {
		return nil, fmt.Errorf("SYSVOL service credentials required")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	controllers, err := (&SiteService{ldap: s.ldap}).Controllers(ctx)
	if err != nil {
		return nil, err
	}
	if len(controllers) == 0 || len(controllers) > 32 {
		return nil, topologyBad("consistency check requires 1..32 discovered controllers")
	}
	sort.Slice(controllers, func(i, j int) bool { return controllers[i].DNS < controllers[j].DNS })
	reference := ""
	seen := map[string]bool{}
	for _, dc := range controllers {
		key := strings.ToLower(dc.DNS)
		if seen[key] {
			return nil, topologyBad("duplicate DC DNS identity")
		}
		seen[key] = true
		if in.Reference != "" && (strings.EqualFold(dc.DNS, in.Reference) || strings.EqualFold(dc.Name, in.Reference)) {
			reference = dc.DNS
		}
	}
	if in.Reference != "" && reference == "" {
		return nil, topologyBad("reference must be a discovered controller")
	}
	entry, err := s.policyEntry(ctx, guid)
	if err != nil {
		return nil, err
	}
	base, err := s.policyPath(ctx, entry)
	if err != nil {
		return nil, err
	}
	conn, err := s.ldap.Conn(ctx)
	if err != nil {
		return nil, err
	}
	root, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"dNSHostName"}, nil))
	if err != nil {
		return nil, err
	}
	if len(root.Entries) != 1 {
		return nil, fmt.Errorf("missing RootDSE")
	}
	primary := root.Entries[0].GetEqualFoldAttributeValue("dNSHostName")
	report := &ConsistencyReport{GPO: braceGUID(guid), Started: time.Now().UTC(), Reference: reference, Controllers: make([]ConsistencyDC, len(controllers)), Limitations: []string{"read-only; no replication or repair", "reference is a comparison baseline, not an authoritative copy", "non-atomic snapshot; two reads detect many but not all concurrent changes", "owner/group/ordered DACL compared; SACL and effective access not evaluated", "root .sambaadm-* metadata excluded; pending journal reported separately", "limits: 32 DCs, 2048 objects and 64 MiB per pass/DC, 45-second context budget; connection timeouts may extend elapsed time"}}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, dc := range controllers {
		wg.Add(1)
		go func(i int, dc Controller) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				report.Controllers[i] = ConsistencyDC{Name: dc.Name, DNS: dc.DNS, Status: "incomplete", LDAP: "not-checked", SYSVOL: "not-checked", Files: []ConsistencyFile{}, Errors: []string{ctx.Err().Error()}, Differences: []ConsistencyDifference{}}
				return
			}
			probeCtx, stop := context.WithTimeout(ctx, 15*time.Second)
			defer stop()
			report.Controllers[i] = s.probeConsistency(probeCtx, guid, base, dc, primary)
		}(i, dc)
	}
	wg.Wait()
	compareConsistency(report)
	report.Finished = time.Now().UTC()
	return report, nil
}

func addConsistencyDifference(dc *ConsistencyDC, kind, p, reference, value string) {
	dc.DifferenceCount++
	if len(dc.Differences) < consistencyDiffs {
		dc.Differences = append(dc.Differences, ConsistencyDifference{kind, p, reference, value})
	}
}
func compareConsistency(report *ConsistencyReport) {
	report.Complete = true
	report.HasDifferences = false
	ref := -1
	for i := range report.Controllers {
		dc := &report.Controllers[i]
		if !dc.checked {
			report.Complete = false
		}
		if dc.Differences == nil {
			dc.Differences = []ConsistencyDifference{}
		}
		if report.Reference == "" && dc.checked && ref < 0 {
			ref = i
		}
		if report.Reference != "" && strings.EqualFold(dc.DNS, report.Reference) && dc.checked {
			ref = i
		}
		if dc.checked && dc.LDAPVersion != nil && dc.GPTVersion != nil && *dc.LDAPVersion != *dc.GPTVersion {
			addConsistencyDifference(dc, "local-version", "LDAP/GPT.INI", strconv.FormatUint(uint64(*dc.LDAPVersion), 10), strconv.FormatUint(uint64(*dc.GPTVersion), 10))
			report.HasDifferences = true
		}
	}
	if ref < 0 {
		for i := range report.Controllers {
			dc := &report.Controllers[i]
			if dc.checked {
				dc.Status = "not-compared"
				if dc.DifferenceCount > 0 {
					dc.Status = "different"
				}
			}
		}
		report.Complete = false
		report.Status = "incomplete"
		return
	}
	baseline := &report.Controllers[ref]
	report.Reference = baseline.DNS
	files := map[string]ConsistencyFile{}
	for _, f := range baseline.Files {
		files[strings.ToLower(f.Path)] = f
	}
	version := func(v *uint32) string {
		if v == nil {
			return "unknown"
		}
		return strconv.FormatUint(uint64(*v), 10)
	}
	for i := range report.Controllers {
		dc := &report.Controllers[i]
		if dc.Status == "pending" || dc.Status == "changing" {
			continue
		}
		if i != ref {
			for _, item := range []struct{ kind, path, ref, value string }{{"ldap-version", "LDAP/versionNumber", version(baseline.LDAPVersion), version(dc.LDAPVersion)}, {"gpt-version", "GPT.INI/Version", version(baseline.GPTVersion), version(dc.GPTVersion)}, {"ldap-acl", "LDAP/nTSecurityDescriptor", baseline.LDAPACL, dc.LDAPACL}, {"ldap-metadata", "LDAP/metadata", baseline.Metadata, dc.Metadata}} {
				if strings.HasPrefix(item.kind, "ldap-") && dc.LDAP != "ok" {
					continue
				}
				if item.kind == "gpt-version" && dc.SYSVOL != "ok" {
					continue
				}
				if item.ref != item.value {
					if item.kind == "ldap-metadata" && len(baseline.MetadataFields) > 0 && len(dc.MetadataFields) > 0 {
						for _, key := range []string{"objectGUID", "flags", "gPCMachineExtensionNames", "gPCUserExtensionNames", "gPCWQLFilter"} {
							if baseline.MetadataFields[key] != dc.MetadataFields[key] {
								addConsistencyDifference(dc, item.kind, "LDAP/"+key, baseline.MetadataFields[key], dc.MetadataFields[key])
							}
						}
						continue
					}
					addConsistencyDifference(dc, item.kind, item.path, item.ref, item.value)
				}
			}
			if dc.SYSVOL == "ok" {
				seen := map[string]bool{}
				for _, f := range dc.Files {
					key := strings.ToLower(f.Path)
					seen[key] = true
					other, ok := files[key]
					if !ok {
						addConsistencyDifference(dc, "extra", f.Path, "", f.Kind)
						continue
					}
					if f.Path != other.Path {
						addConsistencyDifference(dc, "path-case", f.Path, other.Path, f.Path)
					}
					if f.Kind != other.Kind {
						addConsistencyDifference(dc, "type", f.Path, other.Kind, f.Kind)
					} else if f.Kind == "file" && (f.Size != other.Size || f.SHA256 != other.SHA256) {
						addConsistencyDifference(dc, "content", f.Path, other.SHA256, f.SHA256)
					}
					if f.ACL != other.ACL {
						addConsistencyDifference(dc, "sysvol-acl", f.Path, other.ACL, f.ACL)
					}
				}
				for _, f := range baseline.Files {
					if !seen[strings.ToLower(f.Path)] {
						addConsistencyDifference(dc, "missing", f.Path, f.Kind, "")
					}
				}
			}
		}
		if dc.DifferenceCount > 0 {
			report.HasDifferences = true
		}
		if !dc.checked {
			continue
		}
		if dc.DifferenceCount > 0 {
			dc.Status = "different"
			report.HasDifferences = true
		} else if i == ref {
			dc.Status = "reference"
		} else {
			dc.Status = "consistent"
		}
	}
	switch {
	case !report.Complete:
		report.Status = "incomplete"
	case report.HasDifferences:
		report.Status = "different"
	case len(report.Controllers) < 2:
		report.Status = "single-controller"
	default:
		report.Status = "consistent"
	}
}
