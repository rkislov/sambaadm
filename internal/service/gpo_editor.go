package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
	"io"
	"os"
	"path"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/policy"
	"strconv"
	"strings"
)

var ErrPolicyConflict = errors.New("policy changed; reload before saving")
var ErrEditorUnavailable = errors.New("ALT editor unavailable")

const editorJournal = ".sambaadm-editor.pending"
const registryCSE = "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"

type ALTSetting struct {
	policy.Definition
	State  string         `json:"state"`
	Values map[string]any `json:"values,omitempty"`
}
type ALTPolicy struct {
	Version         uint32       `json:"version"`
	Revision        string       `json:"revision"`
	Settings        []ALTSetting `json:"settings"`
	Scope           string       `json:"scope"`
	Controller      string       `json:"controller"`
	TemplateSource  string       `json:"templateSource"`
	MachineDisabled bool         `json:"machineDisabled"`
	SectionDisabled bool         `json:"sectionDisabled"`
}
type ALTChange struct {
	ID       string                     `json:"id"`
	State    string                     `json:"state"`
	Revision string                     `json:"revision"`
	Scope    string                     `json:"scope,omitempty"`
	Values   map[string]json.RawMessage `json:"values,omitempty"`
}
type editorSnapshot struct {
	root                       policyStore
	templateSource, controller string
	scope                      string
	entry                      *ldap.Entry
	pol, ini                   []byte
	exists                     bool
	records                    []policy.Record
	version                    uint32
	definitions                []policy.Definition
	revision                   string
	polPath, iniPath           string
}

func policyChild(root policyStore, parent, name string, optional bool) (string, error) {
	entries, e := root.ReadDir(parent)
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
			return "", fmt.Errorf("missing policy path %s: %w", name, os.ErrNotExist)
		}
		found = name
	}
	return path.Join(parent, found), nil
}

func readPolicyFile(root policyStore, path string) ([]byte, error) {
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
	text, wide, err := decodePolicyText(data)
	if err != nil {
		return 0, nil, err
	}
	lines := strings.Split(text, "\n")
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
	return uint32(v), encodePolicyText(strings.Join(lines, "\n"), wide), nil
}
func (s *GPOService) editorSnapshot(ctx context.Context, gpo string, share *smb2.Share, locked bool, scope string) (*editorSnapshot, error) {
	if !s.gpoCfg.EditorEnabled {
		return nil, fmt.Errorf("%w: enable gpo.editor_enabled to edit administrative templates", ErrEditorUnavailable)
	}
	if !looksLikeGUID(gpo) {
		return nil, fmt.Errorf("GPO GUID required")
	}
	entry, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{Filter: "(&(objectClass=groupPolicyContainer)(cn=" + ldap.EscapeFilter(braceGUID(gpo)) + "))", Attributes: []string{"cn", "versionNumber", "gPCMachineExtensionNames", "gPCUserExtensionNames", "gPCFileSysPath", "flags", "uSNChanged"}})
	if e != nil {
		return nil, e
	}
	cn := entry.GetAttributeValue("cn")
	if !looksLikeGUID(cn) {
		return nil, fmt.Errorf("invalid LDAP GPO identifier")
	}
	dns, e := s.domainDNS(ctx)
	if e != nil {
		return nil, e
	}
	if dns == "" || strings.ContainsAny(dns, "/\\:") {
		return nil, fmt.Errorf("invalid domain")
	}
	defs, source, e := s.editorDefinitions(share, dns)
	if e != nil {
		return nil, fmt.Errorf("%w: %v", ErrEditorUnavailable, e)
	}
	filtered := []policy.Definition{}
	for _, d := range defs {
		if d.Scope == scope {
			filtered = append(filtered, d)
		}
	}
	defs = filtered
	// Use the configured DC, never follow a host or path supplied by HTTP/UNC.
	unc := strings.Split(strings.TrimPrefix(entry.GetAttributeValue("gPCFileSysPath"), `\\`), `\`)
	if len(unc) != 5 || !strings.EqualFold(unc[1], "sysvol") || !strings.EqualFold(unc[2], dns) || !strings.EqualFold(unc[3], "Policies") || !strings.EqualFold(unc[4], cn) {
		return nil, fmt.Errorf("GPO SYSVOL path does not match configured domain")
	}
	root := &smbPolicyStore{share: share, base: path.Join(dns, "Policies", cn)}
	if !locked {
		if _, e = root.Lstat(editorJournal); !os.IsNotExist(e) {
			if e != nil {
				return nil, e
			}
			return nil, fmt.Errorf("unfinished policy save: inspect SYSVOL/%s/%s before further edits", root.base, editorJournal)
		}
	}
	machinePath, e := policyChild(root, ".", scope, false)
	if e != nil {
		return nil, e
	}
	machine, e := root.Lstat(machinePath)
	if e != nil || !machine.IsDir() {
		return nil, fmt.Errorf("%s must be a real directory", scope)
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
		Defs                     []policy.Definition
		Version                  uint32
		Extensions, Flags, Scope string
	}{defs, version, entry.GetAttributeValue("gPC" + scope + "ExtensionNames"), entry.GetAttributeValue("flags"), scope})
	h := sha256.New()
	h.Write(ini)
	h.Write(data)
	h.Write(encoded)
	revision := fmt.Sprintf("%x", h.Sum(nil))
	return &editorSnapshot{root: root, scope: scope, templateSource: source, controller: s.remote.Host, entry: entry, pol: data, ini: ini, exists: exists, records: records, version: version, definitions: defs, revision: revision, polPath: polPath, iniPath: iniPath}, nil
}
func (snap *editorSnapshot) view() *ALTPolicy {
	scope := snap.scope
	if scope == "" {
		scope = "Machine"
	}
	out := &ALTPolicy{Version: snap.version, Revision: snap.revision, Scope: scope, Controller: snap.controller, TemplateSource: snap.templateSource, Settings: []ALTSetting{}}
	flags, _ := strconv.ParseUint(snap.entry.GetAttributeValue("flags"), 10, 32)
	out.MachineDisabled = flags&2 != 0
	out.SectionDisabled = out.MachineDisabled
	if scope == "User" {
		out.SectionDisabled = flags&1 != 0
	}
	for _, d := range snap.definitions {
		state, values := policy.SettingState(d, snap.records)
		out.Settings = append(out.Settings, ALTSetting{Definition: d, State: state, Values: values})
	}
	return out
}
func (s *GPOService) ALTSettingsScope(ctx context.Context, gpo, scope string) (*ALTPolicy, error) {
	if scope == "" {
		scope = "Machine"
	}
	if scope != "Machine" && scope != "User" {
		return nil, fmt.Errorf("%w: invalid scope", policy.ErrInvalidValue)
	}
	return s.altSettings(ctx, gpo, scope)
}
func (s *GPOService) ALTSettings(ctx context.Context, gpo string) (*ALTPolicy, error) {
	return s.altSettings(ctx, gpo, "Machine")
}
func (s *GPOService) altSettings(ctx context.Context, gpo, scope string) (*ALTPolicy, error) {
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	var out *ALTPolicy
	if !s.gpoCfg.EditorEnabled {
		return nil, fmt.Errorf("%w: set gpo.editor_enabled: true; installed ADMX files alone do not enable the editor", ErrEditorUnavailable)
	}
	if s.remote == nil {
		return nil, fmt.Errorf("%w: configure service credentials for SMB SYSVOL access", ErrEditorUnavailable)
	}
	err := s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(share *smb2.Share) error {
		snap, e := s.editorSnapshot(ctx, gpo, share, false, scope)
		if e != nil {
			return e
		}
		out = snap.view()
		return nil
	})
	return out, err
}

// writePolicyFile updates existing files in place so their ownership, ACL and
// extended attributes survive. A durable journal allows detecting interrupted saves.
func writePolicyFile(root policyStore, path string, data []byte) (err error) {
	f, e := root.OpenFile(path, os.O_RDWR, 0644)
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular policy file")
	}
	if n, e := f.WriteAt(data, 0); e != nil {
		return e
	} else if n != len(data) {
		return io.ErrShortWrite
	}
	if e = f.Truncate(int64(len(data))); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	return nil
}
func (s *GPOService) SetALTSetting(ctx context.Context, gpo string, change ALTChange, actor, ip string) (out *ALTPolicy, err error) {
	if change.Scope == "" {
		change.Scope = "Machine"
	}
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	defer func() {
		if err != nil {
			s.audit.Failure(actor, "gpo.alt.set", gpo+"/"+change.Scope+"/"+change.ID, ip, err)
		}
	}()
	if !s.gpoCfg.EditorEnabled {
		return nil, fmt.Errorf("%w: set gpo.editor_enabled: true; installed ADMX files alone do not enable the editor", ErrEditorUnavailable)
	}
	if s.remote == nil {
		return nil, fmt.Errorf("%w: configure service credentials for SMB SYSVOL access", ErrEditorUnavailable)
	}
	err = s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(share *smb2.Share) error {
		out, err = s.setALTSetting(ctx, gpo, change, actor, ip, share)
		return err
	})
	return out, err
}

func (s *GPOService) setALTSetting(ctx context.Context, gpo string, change ALTChange, actor, ip string, share *smb2.Share) (*ALTPolicy, error) {
	scope := change.Scope
	if scope == "" {
		scope = "Machine"
	}
	if scope != "Machine" && scope != "User" {
		return nil, fmt.Errorf("%w: invalid scope", policy.ErrInvalidValue)
	}
	snap, e := s.editorSnapshot(ctx, gpo, share, false, scope)
	if e != nil {
		return nil, e
	}
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
		return nil, fmt.Errorf("%w: unknown ALT policy", policy.ErrInvalidValue)
	}
	records, e := policy.ApplySetting(*def, snap.records, change.State, change.Values)
	if e != nil {
		return nil, e
	}
	data, e := policy.Encode(records)
	if e != nil {
		return nil, e
	}
	next, e := nextPolicyVersion(snap.version, scope)
	if e != nil {
		return nil, e
	}
	_, ini, e := gptVersion(snap.ini, &next)
	if e != nil {
		return nil, e
	}
	// Store recovery data before changing either file. Never silently continue
	// after an interrupted save. The exclusive SMB create also serializes cooperating remote editors.
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
	// The snapshot might predate another editor's completed save. Recheck
	// under the exclusive journal before touching either policy file.
	current, e := s.editorSnapshot(ctx, gpo, share, true, scope)
	if e != nil || current.revision != snap.revision {
		cleanup := snap.root.Remove(editorJournal)
		if e == nil {
			e = ErrPolicyConflict
		}
		return nil, errors.Join(e, cleanup)
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
		return nil, cause
	}
	if !snap.exists {
		f, createErr := snap.root.OpenFile(snap.polPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if createErr == nil {
			createErr = f.Close()
		}
		if e = createErr; e != nil {
			return nil, fmt.Errorf("retain %s and inspect file creation outcome: %w", editorJournal, e)
		}
	}
	if e = writePolicyFile(snap.root, snap.polPath, data); e != nil {
		return rollback(e)
	}
	if e = writePolicyFile(snap.root, snap.iniPath, ini); e != nil {
		return rollback(e)
	}
	assertion, _ := ldap.CompileFilter("(&(versionNumber=" + strconv.FormatUint(uint64(snap.version), 10) + ")(uSNChanged=" + ldap.EscapeFilter(snap.entry.GetAttributeValue("uSNChanged")) + "))")
	req := ldap.NewModifyRequest(snap.entry.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(assertion.Bytes()))})
	req.Replace("versionNumber", []string{strconv.FormatUint(uint64(next), 10)})
	ext := snap.entry.GetAttributeValue("gPC" + scope + "ExtensionNames")
	if !strings.Contains(strings.ToUpper(ext), "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}") {
		req.Replace("gPC"+scope+"ExtensionNames", []string{ext + registryCSE})
	}
	if e = s.ldap.Modify(ctx, req); e != nil {
		var ldapErr *ldap.Error
		if !errors.As(e, &ldapErr) || ldapErr.ResultCode >= 200 {
			return nil, fmt.Errorf("LDAP commit outcome unknown; retain %s and verify LDAP/GPT.INI before recovery: %w", editorJournal, e)
		}
		if ldapErr.ResultCode == ldap.LDAPResultAssertionFailed {
			return rollback(ErrPolicyConflict)
		}
		return rollback(fmt.Errorf("save LDAP version: %w", e))
	}
	// LDAP success commits the save. Leave the journal if cleanup fails, rather
	// than roll back files after the domain version has already advanced.
	if e = snap.root.Remove(editorJournal); e != nil {
		return nil, fmt.Errorf("policy saved; remove completed journal after verification: %w", e)
	}
	s.audit.Success(actor, "gpo.alt.set", gpo+"/"+change.Scope+"/"+change.ID+"="+change.State, ip)
	// Return fresh revision including the updated LDAP extension metadata.
	fresh, e := s.editorSnapshot(ctx, gpo, share, false, scope)
	if e != nil {
		return nil, e
	}
	return fresh.view(), nil
}

func nextPolicyVersion(version uint32, scope string) (uint32, error) {
	if scope == "User" {
		if version>>16 == 65535 {
			return 0, fmt.Errorf("user GPO version exhausted")
		}
		return version + 65536, nil
	}
	if uint16(version) == 65535 {
		return 0, fmt.Errorf("machine GPO version exhausted")
	}
	return version + 1, nil
}
