package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type DriveScope struct {
	Disabled bool       `json:"disabled"`
	Drives   []DriveMap `json:"drives"`
}
type GPODrives struct {
	Controller      string                `json:"controller"`
	Version         uint32                `json:"version"`
	Revision        string                `json:"revision"`
	MachineDisabled bool                  `json:"machineDisabled"`
	UserDisabled    bool                  `json:"userDisabled"`
	Scopes          map[string]DriveScope `json:"scopes"`
	Backup          string                `json:"backup,omitempty"`
}
type driveSnapshot struct {
	transaction *scriptSnapshot
	view        *GPODrives
	docs        map[string]*drivesXML
	paths       map[string]string
	dirs        map[string][]string
}

func loadDriveSnapshot(root policyStore, entry *ldap.Entry, controller string, locked bool) (*driveSnapshot, error) {
	if !locked {
		if _, e := root.Lstat(editorJournal); !errors.Is(e, os.ErrNotExist) {
			if e != nil {
				return nil, e
			}
			return nil, fmt.Errorf("unfinished policy save: inspect %s", editorJournal)
		}
	}
	gpt, e := policyChild(root, ".", "GPT.INI", false)
	if e != nil {
		return nil, e
	}
	ini, e := readPolicyFile(root, gpt)
	if e != nil {
		return nil, e
	}
	version, _, e := gptVersion(ini, nil)
	if e != nil {
		return nil, e
	}
	adVersion, e := strconv.ParseUint(entry.GetAttributeValue("versionNumber"), 10, 32)
	if e != nil || uint32(adVersion) != version {
		return nil, fmt.Errorf("%w: LDAP and GPT.INI versions disagree", ErrPolicyConflict)
	}
	flags, _ := strconv.ParseUint(entry.GetAttributeValue("flags"), 10, 32)
	tx := &scriptSnapshot{root: root, entry: entry, gptPath: gpt, files: map[string][]byte{gpt: ini}, view: &GPOScripts{Controller: controller, Version: version, MachineDisabled: flags&2 != 0, UserDisabled: flags&1 != 0}}
	snap := &driveSnapshot{transaction: tx, view: &GPODrives{Controller: controller, Version: version, MachineDisabled: flags&2 != 0, UserDisabled: flags&1 != 0, Scopes: map[string]DriveScope{}}, docs: map[string]*drivesXML{}, paths: map[string]string{}, dirs: map[string][]string{}}
	for _, scope := range []string{"Machine", "User"} {
		name, dirs, e := scriptPath(root, scope, "Preferences", "Drives", "Drives.xml")
		if e != nil {
			return nil, e
		}
		snap.paths[scope] = name
		snap.dirs[scope] = dirs
		var data []byte
		st, e := root.Lstat(name)
		if e == nil {
			if !st.Mode().IsRegular() || st.Size() > 2<<20 {
				return nil, fmt.Errorf("invalid Drives.xml file")
			}
			data, e = readPolicyFile(root, name)
			if e != nil {
				return nil, e
			}
			tx.files[name] = data
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		doc, e := parseDriveXML(data)
		if e != nil {
			return nil, e
		}
		snap.docs[scope] = doc
		section := DriveScope{Disabled: doc.disabled, Drives: []DriveMap{}}
		for _, x := range doc.items {
			section.Drives = append(section.Drives, x.view)
		}
		snap.view.Scopes[scope] = section
	}
	raw, _ := json.Marshal(struct {
		Files                     map[string][]byte
		USN, Machine, User, Flags string
	}{tx.files, entry.GetAttributeValue("uSNChanged"), entry.GetAttributeValue("gPCMachineExtensionNames"), entry.GetAttributeValue("gPCUserExtensionNames"), entry.GetAttributeValue("flags")})
	snap.view.Revision = fmt.Sprintf("%x", sha256.Sum256(raw))
	tx.view.Revision = snap.view.Revision
	return snap, nil
}
func saveDriveTransaction(snap *driveSnapshot, in DriveChange, recheck func() error, commit func(uint32, string) error) (string, error) {
	if e := validateDriveChange(in); e != nil {
		return "", e
	}
	if snap.view.Revision != in.Revision {
		return "", ErrPolicyConflict
	}
	data, e := patchDriveXML(snap.docs[in.Scope], in)
	if e != nil {
		return "", e
	}
	// Parse our output before writing, catching malformed legacy documents and
	// validating that an attribute edit did not accidentally break targeting XML.
	if _, e = parseDriveXML(data); e != nil {
		return "", e
	}
	name := snap.paths[in.Scope]
	before, exists := snap.transaction.files[name]
	ext, e := policyExtension(snap.transaction.entry.GetAttributeValue("gPC"+in.Scope+"ExtensionNames"), drivesCSE, drivesEditor)
	if e != nil {
		return "", e
	}
	// Preferences also register their editor in the common zero-GUID group.
	ext, e = policyExtension(ext, "{00000000-0000-0000-0000-000000000000}", drivesEditor)
	if e != nil {
		return "", e
	}
	if bytes.Equal(before, data) && ext == snap.transaction.entry.GetAttributeValue("gPC"+in.Scope+"ExtensionNames") {
		return "", nil
	}
	deltas := []scriptDelta{{Path: name, Existed: exists, Before: before, After: data}}
	return savePolicyFilesTransaction(snap.transaction, in.Scope, ext, snap.dirs[in.Scope], deltas, ".sambaadm-preferences-backup-", recheck, commit)
}
func (s *GPOService) Drives(ctx context.Context, gpo string) (*GPODrives, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if e := s.lockEditor(ctx); e != nil {
		return nil, e
	}
	defer s.editorMu.Unlock()
	if s.remote == nil {
		return nil, fmt.Errorf("%w: SYSVOL credentials are required", ErrEditorUnavailable)
	}
	var out *GPODrives
	e := s.sysvol(ctx, s.remote, s.gpoCfg.SMBPort, func(sh *sysvolShare) error {
		root, entry, e := s.scriptRoot(ctx, gpo, sh)
		if e != nil {
			return e
		}
		snap, e := loadDriveSnapshot(root, entry, s.remote.Host, false)
		if e == nil {
			out = snap.view
		}
		return e
	})
	return out, e
}
func (s *GPOService) SetDrive(ctx context.Context, gpo string, in DriveChange, actor, ip string) (out *GPODrives, err error) {
	if err = validateDriveChange(in); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err = s.lockEditor(ctx); err != nil {
		return nil, err
	}
	defer s.editorMu.Unlock()
	defer func() {
		if s.audit != nil {
			if err != nil {
				s.audit.Failure(actor, "gpo.drives.set", gpo+"/"+in.Scope, ip, err)
			} else {
				s.audit.Success(actor, "gpo.drives.set", gpo+"/"+in.Scope+"/"+in.Operation, ip)
			}
		}
	}()
	enabled, e := s.EditorEnabled()
	if e != nil {
		return nil, e
	}
	if !enabled {
		return nil, ErrEditorUnavailable
	}
	if s.remote == nil {
		return nil, fmt.Errorf("%w: SYSVOL credentials are required", ErrEditorUnavailable)
	}
	err = s.sysvol(ctx, s.remote, s.gpoCfg.SMBPort, func(sh *sysvolShare) error {
		root, entry, e := s.scriptRoot(ctx, gpo, sh)
		if e != nil {
			return e
		}
		snap, e := loadDriveSnapshot(root, entry, s.remote.Host, false)
		if e != nil {
			return e
		}
		backup, e := saveDriveTransaction(snap, in, func() error {
			fresh, e := s.policyEntry(ctx, gpo)
			if e != nil {
				return e
			}
			current, e := loadDriveSnapshot(root, fresh, s.remote.Host, true)
			if e != nil {
				return e
			}
			if current.view.Revision != in.Revision {
				return ErrPolicyConflict
			}
			return nil
		}, func(version uint32, ext string) error {
			assertion, e := ldap.CompileFilter("(&(versionNumber=" + strconv.FormatUint(uint64(snap.view.Version), 10) + ")(uSNChanged=" + ldap.EscapeFilter(entry.GetAttributeValue("uSNChanged")) + "))")
			if e != nil {
				return e
			}
			req := ldap.NewModifyRequest(entry.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(assertion.Bytes()))})
			req.Replace("versionNumber", []string{strconv.FormatUint(uint64(version), 10)})
			req.Replace("gPC"+in.Scope+"ExtensionNames", []string{ext})
			return s.ldap.Modify(ctx, req)
		})
		if e != nil {
			return e
		}
		fresh, e := s.policyEntry(ctx, gpo)
		if e != nil {
			return e
		}
		result, e := loadDriveSnapshot(root, fresh, s.remote.Host, false)
		if e != nil {
			return e
		}
		out = result.view
		out.Backup = backup
		return nil
	})
	return out, err
}
