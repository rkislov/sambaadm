package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"sambaadm/internal/config"
)

func TestIntegrationScriptBackupRestoreAndRecovery(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	name := fmt.Sprintf("Recovery-%d", time.Now().UnixNano())
	if _, e := s.GPO.Create(ctx, name, "test", ""); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := s.GPO.Delete(context.Background(), name, "test", ""); e != nil {
			t.Error(e)
		}
	})
	view, e := s.GPO.Scripts(ctx, name)
	if e != nil {
		t.Fatal(e)
	}
	saved, e := s.GPO.SetScripts(ctx, name, ScriptChange{Revision: view.Revision, Scope: "Machine", Event: "startup", Kind: "script", Entries: []ScriptAssignment{{"test.sh", ""}}, Files: []ScriptFileChange{{Name: "test.sh", Data: []byte("#!/bin/sh\nexit 0\n")}}}, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	state, e := s.GPO.ScriptMaintenance(ctx, name)
	if e != nil || len(state.Backups) != 1 || state.Pending {
		t.Fatal(state, e)
	}
	raw, e := s.GPO.ScriptBackupDownload(ctx, name, saved.Backup, state.Revision)
	if e != nil || !json.Valid(raw) {
		t.Fatal("download failed", e)
	}
	plan, e := s.GPO.ScriptRestorePreview(ctx, name, saved.Backup, "before")
	if e != nil {
		t.Fatal(e)
	}
	state, e = s.GPO.MaintainScripts(ctx, name, ScriptMaintenanceChange{Operation: "restore", Revision: plan.Revision, Source: saved.Backup, Mode: "before"}, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	restored, e := s.GPO.Scripts(ctx, name)
	if e != nil || restored.Version != 2 || len(restored.Scripts) != 0 || len(restored.Files) != 0 {
		t.Fatalf("restore did not remove new assignments/files: %+v %v", restored, e)
	}
	if _, e := s.GPO.MaintainScripts(ctx, name, ScriptMaintenanceChange{Operation: "delete", Revision: state.Revision, Source: state.Backups[0].Name}, "test", ""); e == nil {
		t.Fatal("protected backup deleted")
	}
	state, e = s.GPO.MaintainScripts(ctx, name, ScriptMaintenanceChange{Operation: "delete", Revision: state.Revision, Source: saved.Backup}, "test", "")
	if e != nil || len(state.Backups) != 1 {
		t.Fatal(state, e)
	}
	// Simulate a lost LDAP response: SMB after-images exist, LDAP is unchanged.
	e = s.GPO.remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		root, entry, e := s.GPO.scriptRoot(ctx, name, sh)
		if e != nil {
			return e
		}
		snap, e := loadScriptSnapshot(root, entry, s.GPO.remote.Host, false)
		if e != nil {
			return e
		}
		_, e = saveScriptTransaction(snap, ScriptChange{Revision: snap.view.Revision, Scope: "Machine", Event: "startup", Kind: "script", Entries: []ScriptAssignment{{"finish.sh", "--recovery"}}}, func() error { return nil }, func(uint32, string) error { return errors.New("lost LDAP connection") })
		if e == nil {
			return fmt.Errorf("expected recovery journal")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	state, e = s.GPO.ScriptMaintenance(ctx, name)
	if e != nil || !state.Pending {
		t.Fatal(state, e)
	}
	plan, e = s.GPO.ScriptRestorePreview(ctx, name, "pending", "after")
	if e != nil {
		t.Fatal(e)
	}
	state, e = s.GPO.MaintainScripts(ctx, name, ScriptMaintenanceChange{Operation: "restore", Revision: plan.Revision, Source: "pending", Mode: "after"}, "test", "")
	if e != nil || state.Pending {
		t.Fatal(state, e)
	}
	final, e := s.GPO.Scripts(ctx, name)
	if e != nil || final.Version != 3 || len(final.Scripts) != 1 || final.Scripts[0].Command != "finish.sh" {
		t.Fatal(final, e)
	}
}

func TestIntegrationServicePermissionDiagnostics(t *testing.T) {
	s, ldapCfg := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	id := fmt.Sprint(time.Now().UnixNano())
	name := "Diag-" + id
	if _, e := s.GPO.Create(ctx, name, "test", ""); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := s.GPO.Delete(context.Background(), name, "test", ""); e != nil {
			t.Error(e)
		}
	})
	entry, e := s.GPO.policyEntry(ctx, name)
	if e != nil {
		t.Fatal(e)
	}
	guid := entry.GetAttributeValue("name")
	var before []byte
	base, e := s.GPO.policyPath(ctx, entry)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.GPO.remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error { var e error; before, e = sh.ReadFile(base + `\GPT.INI`); return e }); e != nil {
		t.Fatal(e)
	}
	cfg := &config.Config{LDAP: ldapCfg, GPO: s.GPO.gpoCfg}
	report, e := NewDiagnosticService(cfg).RunFor(ctx, guid)
	if e != nil {
		t.Fatal(e)
	}
	checks := map[string]DiagnosticCheck{}
	for _, check := range report.Checks {
		checks[check.ID] = check
	}
	if checks["drs"].Status != "ok" || checks["sysvol_permissions"].Status != "ok" {
		t.Fatalf("admin permissions not observed: %+v", checks)
	}
	after, e := s.GPO.policyEntry(ctx, name)
	if e != nil || after.GetAttributeValue("uSNChanged") != entry.GetAttributeValue("uSNChanged") {
		t.Fatal("diagnostics modified LDAP", e)
	}
	if e := s.GPO.remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		b, e := sh.ReadFile(base + `\GPT.INI`)
		if !bytes.Equal(before, b) {
			return fmt.Errorf("diagnostics modified GPT.INI")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	login := "diag" + id
	password := "Diagnostic-User-Pass1!"
	if _, e := s.Users.Create(ctx, CreateUserInput{Login: login, Password: password, Enabled: true}, "test", ""); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := s.Users.Delete(context.Background(), login, "test", ""); e != nil {
			t.Error(e)
		}
	})
	t.Setenv("DIAG_RESTRICTED_PASSWORD", password)
	cfg.LDAP.Bind.User = login + "@sambaadm.test"
	cfg.LDAP.Bind.PasswordEnv = "DIAG_RESTRICTED_PASSWORD"
	report, e = NewDiagnosticService(cfg).RunFor(ctx, guid)
	if e != nil {
		t.Fatal(e)
	}
	for _, check := range report.Checks {
		if (check.ID == "drs" || check.ID == "sysvol_permissions") && check.Status != "error" {
			t.Fatalf("unprivileged account reported capable: %+v", check)
		}
	}
	data, _ := json.Marshal(report)
	if strings.Contains(string(data), password) {
		t.Fatal("diagnostic secret leaked")
	}
}
