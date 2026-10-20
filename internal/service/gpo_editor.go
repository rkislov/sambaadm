package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"io"
	"os"
	"path/filepath"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/policy"
	"sambaadm/internal/samba"
	"strconv"
	"strings"
)

var ErrPolicyConflict = errors.New("policy changed; reload before saving")
var ErrEditorUnavailable = errors.New("ALT editor requires editor_enabled, an installed ALT ADMX template and local writable DC SYSVOL")

const editorJournal = ".sambaadm-editor.pending"
const registryCSE = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"

type ALTSetting struct {
	policy.Definition
	State string `json:"state"`
}
type ALTPolicy struct {
	Version         uint32       `json:"version"`
	Revision        string       `json:"revision"`
	Settings        []ALTSetting `json:"settings"`
	Scope           string       `json:"scope"`
	MachineDisabled bool         `json:"machineDisabled"`
}
type ALTChange struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Revision string `json:"revision"`
}
type editorSnapshot struct {
	root             *os.Root
	entry            *ldap.Entry
	pol, ini         []byte
	exists           bool
	records          []policy.Record
	version          uint32
	definitions      []policy.Definition
	revision         string
	polPath, iniPath string
}

func policyChild(root *os.Root, parent, name string, optional bool) (string, error) {
	dir, e := root.Open(parent)
	if e != nil {
		return "", e
	}
	defer dir.Close()
	entries, e := dir.ReadDir(-1)
	if e != nil {
		return "", e
	}
	found := ""
	for _, entry := range entries {
		if strings.EqualFold(entry.Name(), name) {
			if found != "" {
				return "", fmt.Errorf("ambiguous policy filename %q", name)
			}
			found = entry.Name()
		}
	}
	if found == "" {
		if !optional {
			return "", fmt.Errorf("missing policy path %s", name)
		}
		found = name
	}
	return filepath.Join(parent, found), nil
}

// Create over SMB so Samba assigns the inherited NT ACL, ownership and DOS
// attributes. Local POSIX creation would bypass Samba ACL inheritance.
func (s *GPOService) createRegistry(ctx context.Context, root *os.Root, path string, entry *ldap.Entry) error {
	if s.tool == nil || s.tool.Username == "" || s.tool.Password == nil {
		return fmt.Errorf("configured Samba service credentials required to create Registry.pol")
	}
	runner := samba.NewRunner("python3")
	runner.Username = s.tool.Username
	runner.Password = s.tool.Password
	unc := strings.Split(strings.TrimPrefix(entry.GetAttributeValue("gPCFileSysPath"), `\\`), `\`)
	remote := strings.Join(append(unc[2:], strings.Split(filepath.ToSlash(path), "/")...), `\`)
	script := `import os,sys
from samba.param import LoadParm
from samba.credentials import Credentials
from samba.netcmd.gpo import smb_connection
from samba.dcerpc import security
lp=LoadParm();lp.load_default()
creds=Credentials();creds.guess(lp)
creds.parse_string(next(a.split("=",1)[1] for a in sys.argv if a.startswith("--username=")))
with open(os.environ["PASSWD_FILE"]) as password: creds.set_password(password.read())
conn=smb_connection(sys.argv[1],"sysvol",lp=lp,creds=creds)
handle=conn.create(sys.argv[2],CreateDisposition=2,DesiredAccess=security.SEC_FILE_WRITE_DATA)
conn.close(handle)
`
	if _, e := runner.Run(ctx, "-c", script, s.localDCName(), remote); e != nil {
		return fmt.Errorf("create Registry.pol with inherited Samba ACL: %w", e)
	}
	f, e := root.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func readPolicyFile(root *os.Root, path string) ([]byte, error) {
	info, e := root.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("policy path must be a regular file without symlinks")
	}
	f, e := root.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e = f.Stat()
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("policy path is not a regular file")
	}
	b, e := io.ReadAll(io.LimitReader(f, policy.MaxFileSize+1))
	if e == nil && len(b) > policy.MaxFileSize {
		e = fmt.Errorf("policy file exceeds size limit")
	}
	return b, e
}
func gptVersion(data []byte, replace *uint32) (uint32, []byte, error) {
	if strings.ContainsRune(string(data), 0) {
		return 0, nil, fmt.Errorf("unsupported GPT.INI encoding; expected UTF-8")
	}
	lines := strings.Split(string(data), "\n")
	general := false
	found := false
	var v uint64
	for i, line := range lines {
		trim := strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		if strings.HasPrefix(trim, "[") {
			general = strings.EqualFold(trim, "[General]")
			continue
		}
		key, val, ok := strings.Cut(trim, "=")
		if !general || !ok || !strings.EqualFold(strings.TrimSpace(key), "Version") {
			continue
		}
		if found {
			return 0, nil, fmt.Errorf("duplicate GPT.INI version")
		}
		found = true
		var e error
		v, e = strconv.ParseUint(strings.TrimSpace(val), 10, 32)
		if e != nil {
			return 0, nil, e
		}
		if replace != nil {
			suffix := ""
			if strings.HasSuffix(line, "\r") {
				suffix = "\r"
			}
			lines[i] = "Version=" + strconv.FormatUint(uint64(*replace), 10) + suffix
		}
	}
	if !found {
		return 0, nil, fmt.Errorf("GPT.INI version is missing")
	}
	return uint32(v), []byte(strings.Join(lines, "\n")), nil
}
func (s *GPOService) editorSnapshot(ctx context.Context, gpo string) (*editorSnapshot, error) {
	if !s.gpoCfg.EditorEnabled {
		return nil, ErrEditorUnavailable
	}
	defs, e := policy.SystemdDefinitions(s.gpoCfg.ADMXPath)
	if e != nil {
		return nil, fmt.Errorf("%w: %v", ErrEditorUnavailable, e)
	}
	if !looksLikeGUID(gpo) {
		return nil, fmt.Errorf("GPO GUID required")
	}
	entry, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{Filter: "(&(objectClass=groupPolicyContainer)(cn=" + ldap.EscapeFilter(braceGUID(gpo)) + "))", Attributes: []string{"cn", "versionNumber", "gPCMachineExtensionNames", "gPCFileSysPath", "flags"}})
	if e != nil {
		return nil, e
	}
	cn := entry.GetAttributeValue("cn")
	if !looksLikeGUID(cn) {
		return nil, fmt.Errorf("invalid LDAP GPO identifier")
	}
	var domain []string
	for _, p := range strings.Split(s.ldap.BaseDN(), ",") {
		if len(p) > 3 && strings.EqualFold(p[:3], "DC=") {
			domain = append(domain, p[3:])
		}
	}
	dns := strings.ToLower(strings.Join(domain, "."))
	if dns == "" || strings.ContainsAny(dns, "/\\") {
		return nil, fmt.Errorf("invalid domain")
	}
	// Local mode must address this domain's SYSVOL, never a path supplied by HTTP.
	unc := strings.Split(strings.TrimPrefix(entry.GetAttributeValue("gPCFileSysPath"), `\\`), `\`)
	if len(unc) != 5 || !strings.EqualFold(unc[1], "sysvol") || !strings.EqualFold(unc[2], dns) || !strings.EqualFold(unc[3], "Policies") || !strings.EqualFold(unc[4], cn) {
		return nil, fmt.Errorf("GPO SYSVOL path does not match configured domain")
	}
	parent, e := os.OpenRoot(s.sysvol())
	if e != nil {
		return nil, fmt.Errorf("%w: %v", ErrEditorUnavailable, e)
	}
	defer parent.Close()
	root, e := parent.OpenRoot(filepath.Join(dns, "Policies", cn))
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			root.Close()
		}
	}()
	if _, e = root.Stat(editorJournal); !os.IsNotExist(e) {
		return nil, fmt.Errorf("unfinished policy save: inspect %s before further edits", editorJournal)
	}
	machinePath, e := policyChild(root, ".", "Machine", false)
	if e != nil {
		return nil, e
	}
	machine, e := root.Lstat(machinePath)
	if e != nil || !machine.IsDir() {
		return nil, fmt.Errorf("Machine must be a real directory")
	}
	iniPath, e := policyChild(root, ".", "GPT.INI", false)
	if e != nil {
		return nil, e
	}
	polPath, e := policyChild(root, machinePath, "Registry.pol", true)
	if e != nil {
		return nil, e
	}
	ini, e := readPolicyFile(root, iniPath)
	if e != nil {
		return nil, e
	}
	version, _, e := gptVersion(ini, nil)
	if e != nil {
		return nil, e
	}
	adVersion, e := strconv.ParseUint(entry.GetAttributeValue("versionNumber"), 10, 32)
	if e != nil || version != uint32(adVersion) {
		return nil, fmt.Errorf("LDAP and GPT.INI versions disagree; repair replication before editing")
	}
	data, e := readPolicyFile(root, polPath)
	exists := e == nil
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	var records []policy.Record
	if exists {
		records, e = policy.Parse(data)
		if e != nil {
			return nil, e
		}
	}
	// Include the template and registry metadata in the optimistic revision.
	encoded, _ := json.Marshal(struct {
		Defs              []policy.Definition
		Version           uint32
		Extensions, Flags string
	}{defs, version, entry.GetAttributeValue("gPCMachineExtensionNames"), entry.GetAttributeValue("flags")})
	h := sha256.New()
	h.Write(ini)
	h.Write(data)
	h.Write(encoded)
	revision := fmt.Sprintf("%x", h.Sum(nil))
	ok = true
	return &editorSnapshot{root: root, entry: entry, pol: data, ini: ini, exists: exists, records: records, version: version, definitions: defs, revision: revision, polPath: polPath, iniPath: iniPath}, nil
}
func (snap *editorSnapshot) view() *ALTPolicy {
	out := &ALTPolicy{Version: snap.version, Revision: snap.revision, Scope: "Machine", Settings: []ALTSetting{}}
	flags, _ := strconv.ParseUint(snap.entry.GetAttributeValue("flags"), 10, 32)
	out.MachineDisabled = flags&2 != 0
	for _, d := range snap.definitions {
		state := "not-configured"
		for _, r := range snap.records {
			if strings.EqualFold(r.Key, d.Key) && strings.EqualFold(r.Name, d.Value) {
				state = "unsupported"
				if r.Type == 4 && len(r.Data) == 4 {
					switch binary.LittleEndian.Uint32(r.Data) {
					case 0:
						state = "disabled"
					case 1:
						state = "enabled"
					}
				}
			}
		}
		out.Settings = append(out.Settings, ALTSetting{d, state})
	}
	return out
}
func (s *GPOService) ALTSettings(ctx context.Context, gpo string) (*ALTPolicy, error) {
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	snap, e := s.editorSnapshot(ctx, gpo)
	if e != nil {
		return nil, e
	}
	defer snap.root.Close()
	return snap.view(), nil
}

// writePolicyFile updates existing files in place so their ownership, ACL and
// extended attributes survive. A durable journal allows detecting interrupted saves.
func syncPolicyDirectory(root *os.Root, path string) error {
	dir, e := root.Open(path)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func writePolicyFile(root *os.Root, path string, data []byte) error {
	f, e := root.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0644)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular policy file")
	}
	if _, e = f.WriteAt(data, 0); e != nil {
		return e
	}
	if e = f.Truncate(int64(len(data))); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	return syncPolicyDirectory(root, filepath.Dir(path))
}
func (s *GPOService) SetALTSetting(ctx context.Context, gpo string, change ALTChange, actor, ip string) (out *ALTPolicy, err error) {
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	defer func() {
		if err != nil {
			s.audit.Failure(actor, "gpo.alt.set", gpo+"/"+change.ID, ip, err)
		}
	}()
	snap, e := s.editorSnapshot(ctx, gpo)
	if e != nil {
		return nil, e
	}
	defer snap.root.Close()
	if change.Revision == "" || change.Revision != snap.revision {
		return nil, ErrPolicyConflict
	}
	var def *policy.Definition
	for i := range snap.definitions {
		if snap.definitions[i].ID == change.ID {
			def = &snap.definitions[i]
			break
		}
	}
	if def == nil {
		return nil, fmt.Errorf("unsupported ALT template policy")
	}
	if change.State != "enabled" && change.State != "disabled" && change.State != "not-configured" {
		return nil, fmt.Errorf("invalid policy state")
	}
	records := []policy.Record{}
	for _, r := range snap.records {
		if strings.EqualFold(r.Key, def.Key) && strings.EqualFold(r.Name, def.Value) {
			if r.Type != 4 || len(r.Data) != 4 || binary.LittleEndian.Uint32(r.Data) > 1 {
				return nil, fmt.Errorf("existing setting has unsupported type or value; edit with GPUI")
			}
			continue
		}
		records = append(records, r)
	}
	if change.State != "not-configured" {
		data := make([]byte, 4)
		if change.State == "enabled" {
			binary.LittleEndian.PutUint32(data, 1)
		}
		records = append(records, policy.Record{Key: def.Key, Name: def.Value, Type: 4, Data: data})
	}
	data, e := policy.Encode(records)
	if e != nil {
		return nil, e
	}
	if uint16(snap.version) == 65535 {
		return nil, fmt.Errorf("machine GPO version exhausted")
	}
	next := snap.version + 1
	_, ini, e := gptVersion(snap.ini, &next)
	if e != nil {
		return nil, e
	}
	// Store recovery data before changing either file. Never silently continue
	// after an interrupted save. Administrators can inspect this journal locally.
	journal, e := snap.root.OpenFile(editorJournal, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, e
	}
	recovery, _ := json.Marshal(struct {
		Version, NextVersion                         uint32
		RegistryExisted                              bool
		Registry, GPTINI, RegistryAfter, GPTINIAfter []byte
		RegistryPath, GPTINIPath                     string
	}{snap.version, next, snap.exists, snap.pol, snap.ini, data, ini, snap.polPath, snap.iniPath})
	_, e = journal.Write(recovery)
	if e == nil {
		e = journal.Sync()
	}
	closeErr := journal.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return nil, e
	}
	if e = syncPolicyDirectory(snap.root, "."); e != nil {
		return nil, e
	}
	rollback := func(cause error) (*ALTPolicy, error) {
		var a error
		if snap.exists {
			a = writePolicyFile(snap.root, snap.polPath, snap.pol)
		} else {
			a = snap.root.Remove(snap.polPath)
			if os.IsNotExist(a) {
				a = nil
			}
		}
		b := writePolicyFile(snap.root, snap.iniPath, snap.ini)
		if a != nil || b != nil {
			return nil, fmt.Errorf("save failed (%v); recovery required using %s: %v %v", cause, editorJournal, a, b)
		}
		if e := snap.root.Remove(editorJournal); e != nil {
			return nil, fmt.Errorf("save failed (%v); journal cleanup: %w", cause, e)
		}
		if e = syncPolicyDirectory(snap.root, "."); e != nil {
			return nil, fmt.Errorf("rollback complete but journal directory sync failed: %w", e)
		}
		return nil, cause
	}
	if !snap.exists {
		if e = s.createRegistry(ctx, snap.root, snap.polPath, snap.entry); e != nil {
			return nil, fmt.Errorf("retain %s and inspect file creation outcome: %w", editorJournal, e)
		}
	}
	if e = writePolicyFile(snap.root, snap.polPath, data); e != nil {
		return rollback(e)
	}
	if e = writePolicyFile(snap.root, snap.iniPath, ini); e != nil {
		return rollback(e)
	}
	assertion, _ := ldap.CompileFilter("(versionNumber=" + strconv.FormatUint(uint64(snap.version), 10) + ")")
	req := ldap.NewModifyRequest(snap.entry.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(assertion.Bytes()))})
	req.Replace("versionNumber", []string{strconv.FormatUint(uint64(next), 10)})
	ext := snap.entry.GetAttributeValue("gPCMachineExtensionNames")
	if !strings.Contains(strings.ToUpper(ext), "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") {
		req.Replace("gPCMachineExtensionNames", []string{ext + registryCSE})
	}
	if e = s.ldap.Modify(ctx, req); e != nil {
		var ldapErr *ldap.Error
		if !errors.As(e, &ldapErr) || ldapErr.ResultCode >= 200 {
			return nil, fmt.Errorf("LDAP commit outcome unknown; retain %s and verify LDAP/GPT.INI before recovery: %w", editorJournal, e)
		}
		return rollback(fmt.Errorf("save LDAP version: %w", e))
	}
	// LDAP success commits the save. Leave the journal if cleanup fails, rather
	// than roll back files after the domain version has already advanced.
	if e = snap.root.Remove(editorJournal); e != nil {
		return nil, fmt.Errorf("policy saved; remove completed journal after verification: %w", e)
	}
	if e = syncPolicyDirectory(snap.root, "."); e != nil {
		return nil, fmt.Errorf("policy saved; journal directory sync failed: %w", e)
	}
	s.audit.Success(actor, "gpo.alt.set", gpo+"/"+change.ID+"="+change.State, ip)
	// Return fresh revision including the updated LDAP extension metadata.
	fresh, e := s.editorSnapshot(ctx, gpo)
	if e != nil {
		return nil, e
	}
	defer fresh.root.Close()
	return fresh.view(), nil
}
