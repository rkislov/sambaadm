package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"sambaadm/internal/policy"
)

type ScriptFileInfo struct {
	Scope string `json:"scope"`
	Event string `json:"event"`
	Name  string `json:"name"`
	Size  int    `json:"size"`
}

type scriptSnapshot struct {
	root    policyStore
	entry   *ldap.Entry
	files   map[string][]byte
	gptPath string
	view    *GPOScripts
}

// Case-insensitive lookup preserves names created by GPUI on Samba's
// case-sensitive backing filesystem. Missing directories are planned, not made.
func scriptPath(root policyStore, parts ...string) (string, []string, error) {
	dir := "."
	missing := false
	dirs := []string{}
	for i, part := range parts {
		var err error
		if missing {
			dir = path.Join(dir, part)
		} else {
			dir, err = policyChild(root, dir, part, true)
			if err != nil {
				return "", nil, err
			}
			info, statErr := root.Lstat(dir)
			err = statErr
			if errors.Is(err, os.ErrNotExist) {
				missing = true
			} else if err != nil {
				return "", nil, err
			} else if info.Mode()&os.ModeSymlink != 0 || (i < len(parts)-1 && !info.IsDir()) {
				return "", nil, fmt.Errorf("script paths must not contain symlinks or non-directories")
			}
		}
		if missing && i < len(parts)-1 {
			dirs = append(dirs, dir)
		}
	}
	return dir, dirs, nil
}

func loadScriptSnapshot(root policyStore, entry *ldap.Entry, controller string, locked bool) (*scriptSnapshot, error) {
	if !locked {
		if _, err := root.Lstat(editorJournal); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("unfinished policy save: inspect %s before editing", editorJournal)
		}
	}
	gpt, err := policyChild(root, ".", "GPT.INI", false)
	if err != nil {
		return nil, err
	}
	data, err := readPolicyFile(root, gpt)
	if err != nil {
		return nil, err
	}
	version, _, err := gptVersion(data, nil)
	if err != nil {
		return nil, err
	}
	adVersion, err := strconv.ParseUint(entry.GetAttributeValue("versionNumber"), 10, 32)
	if err != nil || uint32(adVersion) != version {
		return nil, fmt.Errorf("%w: LDAP and GPT.INI versions disagree; reload after replication is consistent", ErrPolicyConflict)
	}
	flags, _ := strconv.ParseUint(entry.GetAttributeValue("flags"), 10, 32)
	snap := &scriptSnapshot{root: root, entry: entry, gptPath: gpt, files: map[string][]byte{gpt: data}, view: &GPOScripts{Controller: controller, Version: version, MachineDisabled: flags&2 != 0, UserDisabled: flags&1 != 0, Scripts: []GPOScript{}, Files: []ScriptFileInfo{}}}
	total := len(data)
	var walk func(string, int) error
	walk = func(dir string, depth int) error {
		if depth > 8 {
			return fmt.Errorf("script directory nesting exceeds limit")
		}
		entries, err := root.ReadDir(dir)
		if err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, info := range entries {
			name := info.Name()
			if !validScriptFilename(name) || seen[strings.ToLower(name)] {
				return fmt.Errorf("ambiguous or unsupported script filename %q", name)
			}
			seen[strings.ToLower(name)] = true
			file := path.Join(dir, name)
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("script paths must not contain symlinks")
			}
			if info.IsDir() {
				if err := walk(file, depth+1); err != nil {
					return err
				}
				continue
			}
			if !info.Mode().IsRegular() || info.Size() > 2<<20 || len(snap.files) >= 128 {
				return fmt.Errorf("script file count or size exceeds limit")
			}
			b, err := readPolicyFile(root, file)
			if err != nil {
				return err
			}
			total += len(b)
			if total > 16<<20 {
				return fmt.Errorf("script policy exceeds 16 MiB")
			}
			snap.files[file] = b
		}
		return nil
	}
	for _, scope := range []string{"Machine", "User"} {
		dir, _, err := scriptPath(root, scope, "Scripts")
		if err != nil {
			return nil, err
		}
		if _, err := root.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		if err := walk(dir, 0); err != nil {
			return nil, err
		}
	}
	keys := make([]string, 0, len(snap.files))
	for name := range snap.files {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, file := range keys {
		parts := strings.Split(file, "/")
		if len(parts) < 3 {
			continue
		}
		scope := "Machine"
		if strings.EqualFold(parts[0], "User") {
			scope = "User"
		}
		if len(parts) == 3 && (strings.EqualFold(parts[2], "scripts.ini") || strings.EqualFold(parts[2], "psscripts.ini")) {
			rows, err := parseGPOScripts(snap.files[file], scope, file)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
			snap.view.Scripts = append(snap.view.Scripts, rows...)
		} else if len(parts) >= 4 && validScriptEvent(scope, strings.ToLower(parts[2])) {
			snap.view.Files = append(snap.view.Files, ScriptFileInfo{Scope: scope, Event: strings.ToLower(parts[2]), Name: strings.Join(parts[3:], "/"), Size: len(snap.files[file])})
		}
	}
	encoded, _ := json.Marshal(struct {
		Files                     map[string][]byte
		USN, Machine, User, Flags string
	}{snap.files, entry.GetAttributeValue("uSNChanged"), entry.GetAttributeValue("gPCMachineExtensionNames"), entry.GetAttributeValue("gPCUserExtensionNames"), entry.GetAttributeValue("flags")})
	snap.view.Revision = fmt.Sprintf("%x", sha256.Sum256(encoded))
	return snap, nil
}

func (s *GPOService) scriptRoot(ctx context.Context, gpo string, sh *smb2.Share) (*smbPolicyStore, *ldap.Entry, error) {
	entry, err := s.policyEntry(ctx, gpo)
	if err != nil {
		return nil, nil, err
	}
	base, err := s.policyPath(ctx, entry)
	if err != nil {
		return nil, nil, err
	}
	return &smbPolicyStore{share: sh, base: strings.ReplaceAll(base, `\`, "/")}, entry, nil
}

func (s *GPOService) Scripts(ctx context.Context, gpo string) (*GPOScripts, error) {
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	if s.remote == nil {
		return nil, fmt.Errorf("SYSVOL service credentials are required")
	}
	var out *GPOScripts
	err := s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		root, entry, err := s.scriptRoot(ctx, gpo, sh)
		if err != nil {
			return err
		}
		snap, err := loadScriptSnapshot(root, entry, s.remote.Host, false)
		if err == nil {
			out = snap.view
		}
		return err
	})
	return out, err
}

func (s *GPOService) ScriptFile(ctx context.Context, gpo, revision, scope, event, name string) ([]byte, error) {
	if !validScriptEvent(scope, event) || revision == "" {
		return nil, fmt.Errorf("%w: revision and script event required", policy.ErrInvalidValue)
	}
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	if s.remote == nil {
		return nil, fmt.Errorf("SYSVOL service credentials are required")
	}
	var out []byte
	err := s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		root, entry, err := s.scriptRoot(ctx, gpo, sh)
		if err != nil {
			return err
		}
		snap, err := loadScriptSnapshot(root, entry, s.remote.Host, false)
		if err != nil {
			return err
		}
		if revision != snap.view.Revision {
			return ErrPolicyConflict
		}
		for _, file := range snap.view.Files {
			if file.Scope == scope && file.Event == event && file.Name == name {
				for p, data := range snap.files {
					if strings.EqualFold(p, scope+"/Scripts/"+scriptEventTitle(event)+"/"+name) {
						out = data
						return nil
					}
				}
			}
		}
		return fmt.Errorf("%w: script file not found", policy.ErrInvalidValue)
	})
	return out, err
}

// Every mutation stores before/after images before touching files. The same
// journal serializes our registry and script editors. Other tools use optimistic
// version/file checks and the LDAP assertion; they do not participate in this lock.
type scriptDelta struct {
	Path                string
	Existed             bool
	Before, After       []byte
	Remove              bool
	BeforeACL, AfterACL []byte `json:",omitempty"`
}
type scriptRecovery struct {
	Format                     int
	DN, Scope, USN, Extensions string
	Version, NextVersion       uint32
	Directories                []string
	Files                      []scriptDelta
	CreatedAt                  time.Time
}

var scriptExtensionGroup = regexp.MustCompile(`^\[(\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})+\]$`)

func scriptExtension(raw, scope string) (string, error) {
	ase := "{40B6664F-4972-11D1-A7CA-0000F87571E3}"
	if scope == "User" {
		ase = "{40B66650-4972-11D1-A7CA-0000F87571E3}"
	}
	cse := "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}"
	groups := []string{}
	found := false
	for rest := raw; rest != ""; {
		end := strings.IndexByte(rest, ']')
		if !strings.HasPrefix(rest, "[") || end < 0 {
			return "", fmt.Errorf("unsupported GPO extension metadata")
		}
		group := rest[:end+1]
		if !scriptExtensionGroup.MatchString(group) {
			return "", fmt.Errorf("unsupported GPO extension metadata")
		}
		rest = rest[end+1:]
		if strings.HasPrefix(strings.ToUpper(group), "["+cse) {
			if found {
				return "", fmt.Errorf("duplicate scripts CSE metadata")
			}
			found = true
			ases := []string{}
			for i := 1 + len(cse); i < len(group)-1; i += 38 {
				ases = append(ases, group[i:i+38])
			}
			if !strings.Contains(strings.ToUpper(group), ase) {
				ases = append(ases, ase)
			}
			sort.SliceStable(ases, func(i, j int) bool { return strings.ToUpper(ases[i]) < strings.ToUpper(ases[j]) })
			group = group[:1+len(cse)] + strings.Join(ases, "") + "]"
		}
		groups = append(groups, group)
	}
	if !found {
		groups = append(groups, "["+cse+ase+"]")
	}
	sort.SliceStable(groups, func(i, j int) bool { return strings.ToUpper(groups[i]) < strings.ToUpper(groups[j]) })
	return strings.Join(groups, ""), nil
}

func createDurablePolicyFile(root policyStore, name string, data []byte) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n != len(data) {
		err = fmt.Errorf("short policy write")
	}
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func saveScriptTransaction(snap *scriptSnapshot, in ScriptChange, recheck func() error, commit func(uint32, string) error) (string, error) {
	if err := validateScriptChange(in); err != nil {
		return "", err
	}
	if in.Revision != snap.view.Revision {
		return "", ErrPolicyConflict
	}
	root := snap.root
	ini, dirs, err := scriptPath(root, in.Scope, "Scripts", scriptININame(in.Kind))
	if err != nil {
		return "", err
	}
	data, err := patchScriptINI(snap.files[ini], in.Scope, in.Event, in.Kind, in.Entries)
	if err != nil {
		return "", err
	}
	deltas := []scriptDelta{}
	add := func(name string, after []byte) {
		before, existed := snap.files[name]
		if !existed || !bytes.Equal(before, after) {
			deltas = append(deltas, scriptDelta{Path: name, Existed: existed, Before: before, After: after})
		}
	}
	add(ini, data)
	for _, file := range in.Files {
		name, more, err := scriptPath(root, in.Scope, "Scripts", scriptEventTitle(in.Event), file.Name)
		if err != nil {
			return "", err
		}
		dirs = append(dirs, more...)
		add(name, file.Data)
	}
	ext, err := scriptExtension(snap.entry.GetAttributeValue("gPC"+in.Scope+"ExtensionNames"), in.Scope)
	if err != nil {
		return "", err
	}
	if len(deltas) == 0 && ext == snap.entry.GetAttributeValue("gPC"+in.Scope+"ExtensionNames") {
		return "", nil
	}
	next, err := nextPolicyVersion(snap.view.Version, in.Scope)
	if err != nil {
		return "", err
	}
	_, gpt, err := gptVersion(snap.files[snap.gptPath], &next)
	if err != nil {
		return "", err
	}
	add(snap.gptPath, gpt)
	unique := []string{}
	seen := map[string]bool{}
	for _, dir := range dirs {
		if !seen[dir] {
			seen[dir] = true
			unique = append(unique, dir)
		}
	}
	recovery := scriptRecovery{Format: 1, DN: snap.entry.DN, Scope: in.Scope, USN: snap.entry.GetAttributeValue("uSNChanged"), Extensions: snap.entry.GetAttributeValue("gPC" + in.Scope + "ExtensionNames"), Version: snap.view.Version, NextVersion: next, Directories: unique, Files: deltas}
	recovery.CreatedAt = time.Now().UTC()
	if secure, ok := root.(policySecurityStore); ok {
		for i := range recovery.Files {
			if recovery.Files[i].Existed {
				acl, e := secure.GetACL(recovery.Files[i].Path)
				if e != nil {
					return "", e
				}
				recovery.Files[i].BeforeACL = acl
				recovery.Files[i].AfterACL = acl
			}
		}
	}
	encoded, _ := json.Marshal(recovery)
	if err := createDurablePolicyFile(root, editorJournal, encoded); err != nil {
		return "", fmt.Errorf("cannot acquire durable policy journal: %w", err)
	}
	if err := recheck(); err != nil {
		return "", errors.Join(err, root.Remove(editorJournal))
	}
	backup := ".sambaadm-scripts-backup-" + uuid.NewString() + ".json"
	if err := createDurablePolicyFile(root, backup, encoded); err != nil {
		return "", errors.Join(err, root.Remove(editorJournal))
	}
	pending := func(cause error) (string, error) {
		return "", fmt.Errorf("script save requires recovery; retain %s and %s: %w", editorJournal, backup, cause)
	}
	for _, dir := range unique {
		if err := root.Mkdir(dir, 0755); err != nil {
			return pending(err)
		}
	}
	for _, delta := range deltas {
		if !delta.Existed {
			f, err := root.OpenFile(delta.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
			if err != nil {
				return pending(err)
			}
			if err := f.Close(); err != nil {
				return pending(err)
			}
		}
		if err := writePolicyFile(root, delta.Path, delta.After); err != nil {
			return pending(err)
		}
	}
	// Do not undo a concurrent GPUI write. If files changed under us, retain
	// both images for recovery rather than overwriting the external editor again.
	ours := func() bool {
		for _, delta := range deltas {
			now, err := readPolicyFile(root, delta.Path)
			if err != nil || !bytes.Equal(now, delta.After) {
				return false
			}
		}
		return true
	}
	if !ours() {
		return pending(ErrPolicyConflict)
	}
	if err := commit(next, ext); err != nil {
		var le *ldap.Error
		if !errors.As(err, &le) || le.ResultCode >= 200 || !ours() {
			return pending(err)
		}
		for i := len(deltas) - 1; i >= 0; i-- {
			delta := deltas[i]
			var e error
			if delta.Existed {
				e = writePolicyFile(root, delta.Path, delta.Before)
			} else {
				e = root.Remove(delta.Path)
			}
			if e != nil {
				return pending(errors.Join(err, e))
			}
		}
		for i := len(unique) - 1; i >= 0; i-- {
			if e := root.Remove(unique[i]); e != nil {
				return pending(errors.Join(err, e))
			}
		}
		if le.ResultCode == ldap.LDAPResultAssertionFailed {
			err = ErrPolicyConflict
		}
		return "", errors.Join(err, root.Remove(editorJournal))
	}
	if err := root.Remove(editorJournal); err != nil {
		return "", fmt.Errorf("scripts saved; verify completed journal %s before removing it: %w", editorJournal, err)
	}
	return backup, nil
}

func (s *GPOService) SetScripts(ctx context.Context, gpo string, in ScriptChange, actor, ip string) (out *GPOScripts, err error) {
	if err = validateScriptChange(in); err != nil {
		return nil, err
	}
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	defer func() {
		if err != nil {
			s.audit.Failure(actor, "gpo.scripts.set", gpo+"/"+in.Scope+"/"+in.Event, ip, err)
		}
	}()
	if s.remote == nil {
		return nil, fmt.Errorf("SYSVOL service credentials are required")
	}
	err = s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		root, entry, e := s.scriptRoot(ctx, gpo, sh)
		if e != nil {
			return e
		}
		snap, e := loadScriptSnapshot(root, entry, s.remote.Host, false)
		if e != nil {
			return e
		}
		backup, e := saveScriptTransaction(snap, in, func() error {
			freshEntry, e := s.policyEntry(ctx, gpo)
			if e != nil {
				return e
			}
			fresh, e := loadScriptSnapshot(root, freshEntry, s.remote.Host, true)
			if e != nil {
				return e
			}
			if fresh.view.Revision != in.Revision {
				return ErrPolicyConflict
			}
			return nil
		}, func(version uint32, extensions string) error {
			filter, e := ldap.CompileFilter("(&(versionNumber=" + strconv.FormatUint(uint64(snap.view.Version), 10) + ")(uSNChanged=" + ldap.EscapeFilter(entry.GetAttributeValue("uSNChanged")) + "))")
			if e != nil {
				return e
			}
			req := ldap.NewModifyRequest(entry.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(filter.Bytes()))})
			req.Replace("versionNumber", []string{strconv.FormatUint(uint64(version), 10)})
			req.Replace("gPC"+in.Scope+"ExtensionNames", []string{extensions})
			return s.ldap.Modify(ctx, req)
		})
		if e != nil {
			return e
		}
		fresh, e := s.policyEntry(ctx, gpo)
		if e != nil {
			return e
		}
		result, e := loadScriptSnapshot(root, fresh, s.remote.Host, false)
		if e != nil {
			return e
		}
		out = result.view
		out.Backup = backup
		if _, e := pruneScriptBackups(root, s.gpoCfg); e != nil {
			out.BackupWarning = e.Error()
		}
		return nil
	})
	if err == nil {
		s.audit.Success(actor, "gpo.scripts.set", gpo+"/"+in.Scope+"/"+in.Event, ip)
	}
	return out, err
}
