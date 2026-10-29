package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"sambaadm/internal/config"
	"sambaadm/internal/policy"
)

var scriptBackupName = regexp.MustCompile(`^\.sambaadm-scripts-backup-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.json$`)

const maxScriptRecoveryBytes = 48 << 20

type ScriptBackupInfo struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	Modified  time.Time `json:"modified"`
	Protected bool      `json:"protected"`
}
type ScriptMaintenance struct {
	Revision      string             `json:"revision"`
	Backups       []ScriptBackupInfo `json:"backups"`
	Pending       bool               `json:"pending"`
	RecoveryError string             `json:"recoveryError,omitempty"`
	Keep          int                `json:"keep"`
	MaxBytes      int64              `json:"maxBytes"`
	TotalBytes    int64              `json:"totalBytes"`
	Prunable      []string           `json:"prunable"`
}
type ScriptRestoreFile struct {
	Path   string `json:"path"`
	State  string `json:"state"`
	Action string `json:"action"`
	Size   int    `json:"size"`
}
type ScriptRestorePreview struct {
	Revision    string              `json:"revision"`
	Source      string              `json:"source"`
	Mode        string              `json:"mode"`
	Scope       string              `json:"scope"`
	Version     uint32              `json:"version"`
	NextVersion uint32              `json:"nextVersion"`
	Files       []ScriptRestoreFile `json:"files"`
	Conflicts   []string            `json:"conflicts"`
}
type ScriptMaintenanceChange struct {
	Operation      string `json:"operation"`
	Revision       string `json:"revision"`
	Source         string `json:"source,omitempty"`
	Mode           string `json:"mode,omitempty"`
	AllowConflicts bool   `json:"allowConflicts,omitempty"`
}

func scriptBackupLimits(cfg config.GPOConfig) (int, int64) {
	keep := cfg.ScriptBackupKeep
	if keep <= 0 {
		keep = 10
	}
	if keep > 100 {
		keep = 100
	}
	mib := cfg.ScriptBackupMaxMiB
	if mib <= 0 {
		mib = 64
	}
	if mib > 1024 {
		mib = 1024
	}
	return keep, int64(mib) << 20
}

func readScriptRecoveryFile(root policyStore, name string) ([]byte, error) {
	if name != editorJournal && !scriptBackupName.MatchString(name) {
		return nil, fmt.Errorf("%w: invalid backup name", policy.ErrInvalidValue)
	}
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxScriptRecoveryBytes {
		return nil, fmt.Errorf("unsupported backup file or size")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxScriptRecoveryBytes+1))
	if len(b) > maxScriptRecoveryBytes {
		return nil, fmt.Errorf("backup exceeds size limit")
	}
	return b, err
}

func validateScriptRecovery(raw []byte, dn string) (scriptRecovery, error) {
	var rec scriptRecovery
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, fmt.Errorf("invalid recovery JSON: %w", err)
	}
	a, err := ldap.ParseDN(dn)
	if err != nil {
		return rec, err
	}
	b, err := ldap.ParseDN(rec.DN)
	if err != nil || !a.EqualFold(b) || rec.Format != 1 || (rec.Scope != "Machine" && rec.Scope != "User") || len(rec.Files) == 0 || len(rec.Files) > 129 || len(rec.Directories) > 256 {
		return rec, fmt.Errorf("unsupported recovery record or GPO mismatch")
	}
	next, err := nextPolicyVersion(rec.Version, rec.Scope)
	if err != nil || next != rec.NextVersion {
		return rec, fmt.Errorf("invalid recovery versions")
	}
	if _, err := scriptExtension(rec.Extensions, rec.Scope); err != nil {
		return rec, err
	}
	seen := map[string]bool{}
	hasGPT := false
	total := 0
	for _, delta := range rec.Files {
		key := strings.ToLower(delta.Path)
		if seen[key] || !safeScriptRecoveryPath(delta.Path, rec.Scope, false) {
			return rec, fmt.Errorf("invalid or duplicate recovery path")
		}
		seen[key] = true
		if key == "gpt.ini" {
			if !delta.Existed || delta.Remove {
				return rec, fmt.Errorf("GPT.INI cannot be deleted")
			}
			hasGPT = true
		}
		if len(delta.Before) > 4<<20 || len(delta.After) > 4<<20 || len(delta.BeforeACL) > 1<<20 || len(delta.AfterACL) > 1<<20 {
			return rec, fmt.Errorf("recovery file too large")
		}
		total += len(delta.Before) + len(delta.After)
	}
	if !hasGPT || total > 32<<20 {
		return rec, fmt.Errorf("recovery is missing GPT.INI or exceeds limit")
	}
	for _, dir := range rec.Directories {
		if !safeScriptRecoveryPath(dir, rec.Scope, true) {
			return rec, fmt.Errorf("invalid recovery directory")
		}
	}
	return rec, nil
}

func safeScriptRecoveryPath(name, scope string, directory bool) bool {
	if name == "" || path.Clean(name) != name || path.IsAbs(name) || strings.ContainsAny(name, `\:`) {
		return false
	}
	parts := strings.Split(name, "/")
	for _, p := range parts {
		if !validScriptFilename(p) {
			return false
		}
	}
	if !directory && strings.EqualFold(name, "GPT.INI") {
		return true
	}
	if !strings.EqualFold(parts[0], scope) {
		return false
	}
	if len(parts) == 1 {
		return directory
	}
	if !strings.EqualFold(parts[1], "Scripts") {
		return false
	}
	if len(parts) == 2 {
		return directory
	}
	if len(parts) == 3 && !directory {
		return strings.EqualFold(parts[2], "scripts.ini") || strings.EqualFold(parts[2], "psscripts.ini")
	}
	return validScriptEvent(scope, strings.ToLower(parts[2])) && len(parts) <= 11
}

func scriptMaintenanceState(root policyStore, entry *ldap.Entry, cfg config.GPOConfig) (*ScriptMaintenance, error) {
	items, err := root.ReadDir(".")
	if err != nil {
		return nil, err
	}
	keep, budget := scriptBackupLimits(cfg)
	out := &ScriptMaintenance{Backups: []ScriptBackupInfo{}, Keep: keep, MaxBytes: budget, Prunable: []string{}}
	for _, info := range items {
		if scriptBackupName.MatchString(info.Name()) && info.Mode().IsRegular() {
			out.Backups = append(out.Backups, ScriptBackupInfo{Name: info.Name(), Size: info.Size(), Modified: info.ModTime()})
			out.TotalBytes += info.Size()
		}
	}
	sort.Slice(out.Backups, func(i, j int) bool {
		if out.Backups[i].Modified.Equal(out.Backups[j].Modified) {
			return out.Backups[i].Name > out.Backups[j].Name
		}
		return out.Backups[i].Modified.After(out.Backups[j].Modified)
	})
	var pending []byte
	if _, e := root.Lstat(editorJournal); !errors.Is(e, os.ErrNotExist) {
		if e != nil {
			return nil, e
		}
		out.Pending = true
		pending, e = readScriptRecoveryFile(root, editorJournal)
		if e != nil {
			out.RecoveryError = e.Error()
		} else if _, e = validateScriptRecovery(pending, entry.DN); e != nil {
			out.RecoveryError = e.Error()
		}
	}
	var retained int64
	for i := range out.Backups {
		out.Backups[i].Protected = i == 0 || out.Pending
		retained += out.Backups[i].Size
		if !out.Pending && i > 0 && (i >= keep || retained > budget) {
			out.Prunable = append(out.Prunable, out.Backups[i].Name)
		}
	}
	encoded, _ := json.Marshal(struct {
		State   *ScriptMaintenance
		Pending []byte
		USN     string
	}{out, pending, entry.GetAttributeValue("uSNChanged")})
	out.Revision = fmt.Sprintf("%x", sha256.Sum256(encoded))
	return out, nil
}

func pruneScriptBackups(root policyStore, cfg config.GPOConfig) ([]string, error) {
	state, err := scriptMaintenanceState(root, ldap.NewEntry("", nil), cfg)
	if err != nil {
		return nil, err
	}
	if state.Pending {
		return nil, fmt.Errorf("retention is suspended while recovery is pending")
	}
	removed := []string{}
	for _, name := range state.Prunable {
		if _, e := root.Lstat(editorJournal); !errors.Is(e, os.ErrNotExist) {
			return removed, ErrPolicyConflict
		}
		if e := root.Remove(name); e != nil {
			return removed, e
		}
		removed = append(removed, name)
	}
	return removed, nil
}

type scriptRestorePlan struct {
	view         *ScriptRestorePreview
	rec          scriptRecovery
	deltas       []scriptDelta
	dirs         []string
	raw, pending []byte
}

func buildScriptRestorePlan(root policyStore, entry *ldap.Entry, source, mode string) (*scriptRestorePlan, error) {
	if mode != "before" && mode != "after" {
		return nil, fmt.Errorf("%w: choose before or after", policy.ErrInvalidValue)
	}
	name := source
	if source == "pending" {
		name = editorJournal
	} else if mode != "before" {
		return nil, fmt.Errorf("%w: backups restore the prior state", policy.ErrInvalidValue)
	}
	raw, err := readScriptRecoveryFile(root, name)
	if err != nil {
		return nil, err
	}
	rec, err := validateScriptRecovery(raw, entry.DN)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", policy.ErrInvalidValue, err)
	}
	version64, err := strconv.ParseUint(entry.GetAttributeValue("versionNumber"), 10, 32)
	if err != nil {
		return nil, err
	}
	version := uint32(version64)
	var pending []byte
	if _, e := root.Lstat(editorJournal); !errors.Is(e, os.ErrNotExist) {
		if e != nil {
			return nil, e
		}
		pending, e = readScriptRecoveryFile(root, editorJournal)
		if e != nil {
			return nil, e
		}
	}
	if source == "pending" && version != rec.Version && version != rec.NextVersion {
		return nil, fmt.Errorf("%w: LDAP version changed outside the pending operation", ErrPolicyConflict)
	}
	if source != "pending" && json.Valid(pending) {
		var header struct{ Format int }
		if json.Unmarshal(pending, &header) == nil && header.Format != 1 {
			return nil, fmt.Errorf("%w: pending journal belongs to a different editor; script recovery cannot replace it", policy.ErrInvalidValue)
		}
	}
	next, err := nextPolicyVersion(version, rec.Scope)
	if err != nil {
		return nil, err
	}
	plan := &scriptRestorePlan{rec: rec, raw: raw, pending: pending, view: &ScriptRestorePreview{Source: source, Mode: mode, Scope: rec.Scope, Version: version, NextVersion: next, Files: []ScriptRestoreFile{}, Conflicts: []string{}}}
	if source != "pending" && pending != nil {
		plan.view.Conflicts = append(plan.view.Conflicts, editorJournal)
	}
	seenDirs := map[string]bool{}
	for _, delta := range rec.Files {
		actual, dirs, e := scriptPath(root, strings.Split(delta.Path, "/")...)
		if e != nil {
			return nil, e
		}
		info, e := root.Lstat(actual)
		exists := e == nil
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		var current []byte
		if exists {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("restore target is not a regular file")
			}
			current, e = readPolicyFile(root, actual)
			if e != nil {
				return nil, e
			}
		}
		var currentACL []byte
		if secure, ok := root.(policySecurityStore); ok && exists {
			currentACL, e = secure.GetACL(actual)
			if e != nil {
				return nil, e
			}
		}
		state := "changed"
		before := exists == delta.Existed && (!exists || bytes.Equal(current, delta.Before)) && (len(delta.BeforeACL) == 0 || bytes.Equal(currentACL, delta.BeforeACL))
		after := exists == !delta.Remove && (!exists || bytes.Equal(current, delta.After)) && (len(delta.AfterACL) == 0 || bytes.Equal(currentACL, delta.AfterACL))
		if before {
			state = "before"
		} else if after {
			state = "after"
		} else {
			plan.view.Conflicts = append(plan.view.Conflicts, actual)
		}
		target, remove, acl := delta.Before, !delta.Existed, delta.BeforeACL
		if mode == "after" {
			target, remove, acl = delta.After, delta.Remove, delta.AfterACL
		}
		if strings.EqualFold(actual, "GPT.INI") {
			if remove {
				return nil, fmt.Errorf("cannot remove GPT.INI")
			}
			_, target, e = gptVersion(target, &next)
			if e != nil {
				return nil, fmt.Errorf("backup GPT.INI is invalid: %w", e)
			}
		}
		if !remove && len(strings.Split(actual, "/")) == 3 && (strings.EqualFold(path.Base(actual), "scripts.ini") || strings.EqualFold(path.Base(actual), "psscripts.ini")) {
			if _, err := parseGPOScripts(target, rec.Scope, actual); err != nil {
				return nil, fmt.Errorf("%w: backup script INI is invalid: %v", policy.ErrInvalidValue, err)
			}
		}
		for _, dir := range dirs {
			if !remove && !seenDirs[dir] {
				seenDirs[dir] = true
				plan.dirs = append(plan.dirs, dir)
			}
		}
		change := scriptDelta{Path: actual, Existed: exists, Before: current, After: target, Remove: remove, AfterACL: acl}
		change.BeforeACL = currentACL
		plan.deltas = append(plan.deltas, change)
		action := "write"
		if remove {
			action = "delete"
		}
		plan.view.Files = append(plan.view.Files, ScriptRestoreFile{Path: actual, State: state, Action: action, Size: len(target)})
	}
	encoded, _ := json.Marshal(struct {
		Source, Mode, USN, Ext string
		Version                uint32
		Raw, Pending           []byte
		Files                  []scriptDelta
	}{source, mode, entry.GetAttributeValue("uSNChanged"), entry.GetAttributeValue("gPC" + rec.Scope + "ExtensionNames"), version, raw, pending, plan.deltas})
	plan.view.Revision = fmt.Sprintf("%x", sha256.Sum256(encoded))
	return plan, nil
}

// The original journal stays recoverable until an atomic replacement with the
// new recovery plan. A failed recovery can itself be previewed and retried.
func applyScriptRestore(root policyStore, entry *ldap.Entry, plan *scriptRestorePlan, change ScriptMaintenanceChange, commit func(uint32, string) error) (string, error) {
	if plan.view.Revision != change.Revision {
		return "", ErrPolicyConflict
	}
	if len(plan.view.Conflicts) > 0 && !change.AllowConflicts {
		return "", fmt.Errorf("%w: explicitly acknowledge changed or partial files", ErrPolicyConflict)
	}
	currentExt := entry.GetAttributeValue("gPC" + plan.rec.Scope + "ExtensionNames")
	ext, err := scriptExtension(currentExt, plan.rec.Scope)
	if err != nil {
		return "", err
	}
	rec := scriptRecovery{Format: 1, DN: entry.DN, Scope: plan.rec.Scope, USN: entry.GetAttributeValue("uSNChanged"), Extensions: currentExt, Version: plan.view.Version, NextVersion: plan.view.NextVersion, Directories: plan.dirs, Files: plan.deltas, CreatedAt: time.Now().UTC()}
	encoded, _ := json.Marshal(rec)
	backup := ".sambaadm-scripts-backup-" + uuid.NewString() + ".json"
	if plan.pending != nil {
		original := ".sambaadm-scripts-backup-" + uuid.NewString() + ".json"
		if err := createDurablePolicyFile(root, original, plan.pending); err != nil {
			return "", err
		}
		now, err := readScriptRecoveryFile(root, editorJournal)
		if err != nil || !bytes.Equal(now, plan.pending) {
			return "", ErrPolicyConflict
		}
	}
	if err := createDurablePolicyFile(root, backup, encoded); err != nil {
		return "", err
	}
	if plan.pending != nil {
		temp := ".sambaadm-recovery-" + uuid.NewString() + ".tmp"
		if err := createDurablePolicyFile(root, temp, encoded); err != nil {
			return "", err
		}
		if err := root.Rename(temp, editorJournal); err != nil {
			return "", err
		}
	} else if err := createDurablePolicyFile(root, editorJournal, encoded); err != nil {
		return "", err
	}
	pending := func(err error) (string, error) {
		return "", fmt.Errorf("recovery is incomplete; retain %s and %s: %w", editorJournal, backup, err)
	}
	for _, dir := range plan.dirs {
		if err := root.Mkdir(dir, 0755); err != nil {
			return pending(err)
		}
	}
	for _, delta := range plan.deltas {
		if delta.Remove {
			if delta.Existed {
				if err := root.Remove(delta.Path); err != nil {
					return pending(err)
				}
			}
			continue
		}
		if !delta.Existed {
			f, err := root.OpenFile(delta.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
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
		if secure, ok := root.(policySecurityStore); ok && len(delta.AfterACL) > 0 {
			if err := secure.SetACL(delta.Path, delta.AfterACL); err != nil {
				return pending(err)
			}
		}
	}
	for _, delta := range plan.deltas {
		if delta.Remove {
			if _, err := root.Lstat(delta.Path); !errors.Is(err, os.ErrNotExist) {
				return pending(ErrPolicyConflict)
			}
		} else {
			b, err := readPolicyFile(root, delta.Path)
			if err != nil || !bytes.Equal(b, delta.After) {
				return pending(ErrPolicyConflict)
			}
		}
	}
	if err := commit(plan.view.NextVersion, ext); err != nil {
		return pending(err)
	}
	if err := root.Remove(editorJournal); err != nil {
		return pending(err)
	}
	return backup, nil
}

func (s *GPOService) scriptMaintenanceContext(ctx context.Context, gpo string, fn func(policyStore, *ldap.Entry) error) error {
	if s.remote == nil {
		return fmt.Errorf("SYSVOL service credentials are required")
	}
	return s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		root, entry, err := s.scriptRoot(ctx, gpo, sh)
		if err != nil {
			return err
		}
		return fn(root, entry)
	})
}
func (s *GPOService) ScriptMaintenance(ctx context.Context, gpo string) (out *ScriptMaintenance, err error) {
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	err = s.scriptMaintenanceContext(ctx, gpo, func(root policyStore, entry *ldap.Entry) error {
		out, err = scriptMaintenanceState(root, entry, s.gpoCfg)
		return err
	})
	return
}
func (s *GPOService) ScriptRestorePreview(ctx context.Context, gpo, source, mode string) (out *ScriptRestorePreview, err error) {
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	err = s.scriptMaintenanceContext(ctx, gpo, func(root policyStore, entry *ldap.Entry) error {
		plan, e := buildScriptRestorePlan(root, entry, source, mode)
		if e != nil {
			return e
		}
		out = plan.view
		return nil
	})
	return
}
func (s *GPOService) ScriptBackupDownload(ctx context.Context, gpo, name, revision string) (out []byte, err error) {
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	err = s.scriptMaintenanceContext(ctx, gpo, func(root policyStore, entry *ldap.Entry) error {
		state, e := scriptMaintenanceState(root, entry, s.gpoCfg)
		if e != nil {
			return e
		}
		if revision != state.Revision {
			return ErrPolicyConflict
		}
		if name == "pending" {
			name = editorJournal
		}
		out, e = readScriptRecoveryFile(root, name)
		return e
	})
	return
}

func (s *GPOService) MaintainScripts(ctx context.Context, gpo string, in ScriptMaintenanceChange, actor, ip string) (out *ScriptMaintenance, err error) {
	if in.Revision == "" || (in.Operation != "restore" && in.Operation != "delete" && in.Operation != "prune") {
		return nil, fmt.Errorf("%w: maintenance operation and revision required", policy.ErrInvalidValue)
	}
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	defer func() {
		if err != nil {
			s.audit.Failure(actor, "gpo.scripts."+in.Operation, gpo, ip, err)
		} else {
			s.audit.Success(actor, "gpo.scripts."+in.Operation, gpo, ip)
		}
	}()
	err = s.scriptMaintenanceContext(ctx, gpo, func(root policyStore, entry *ldap.Entry) error {
		if in.Operation == "restore" {
			plan, e := buildScriptRestorePlan(root, entry, in.Source, in.Mode)
			if e != nil {
				return e
			}
			if plan.view.Revision != in.Revision {
				return ErrPolicyConflict
			}
			_, e = applyScriptRestore(root, entry, plan, in, func(version uint32, ext string) error {
				assertion, e := ldap.CompileFilter("(&(versionNumber=" + entry.GetAttributeValue("versionNumber") + ")(uSNChanged=" + ldap.EscapeFilter(entry.GetAttributeValue("uSNChanged")) + "))")
				if e != nil {
					return e
				}
				req := ldap.NewModifyRequest(entry.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(assertion.Bytes()))})
				req.Replace("versionNumber", []string{strconv.FormatUint(uint64(version), 10)})
				req.Replace("gPC"+plan.rec.Scope+"ExtensionNames", []string{ext})
				return s.ldap.Modify(ctx, req)
			})
			if e != nil {
				return e
			}
			if _, e := pruneScriptBackups(root, s.gpoCfg); e != nil {
				return e
			}
		} else {
			state, e := scriptMaintenanceState(root, entry, s.gpoCfg)
			if e != nil {
				return e
			}
			if state.Revision != in.Revision || state.Pending {
				return ErrPolicyConflict
			}
			if in.Operation == "prune" {
				if _, e := pruneScriptBackups(root, s.gpoCfg); e != nil {
					return e
				}
			} else {
				found := false
				for _, item := range state.Backups {
					if item.Name == in.Source && !item.Protected {
						found = true
					}
				}
				if !found {
					return fmt.Errorf("%w: backup missing or protected", policy.ErrInvalidValue)
				}
				if e := root.Remove(in.Source); e != nil {
					return e
				}
			}
		}
		fresh, e := s.policyEntry(ctx, gpo)
		if e != nil {
			return e
		}
		out, e = scriptMaintenanceState(root, fresh, s.gpoCfg)
		return e
	})
	return
}
