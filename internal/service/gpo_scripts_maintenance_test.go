package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/config"
)

func TestScriptRecoveryRollbackAndCompletion(t *testing.T) {
	for _, mode := range []string{"before", "after"} {
		t.Run(mode, func(t *testing.T) {
			snap, root := scriptTestSnapshot(t, 0)
			in := ScriptChange{Revision: snap.view.Revision, Scope: "Machine", Event: "startup", Kind: "script", Entries: []ScriptAssignment{{"hello.sh", "--test"}}, Files: []ScriptFileChange{{Name: "hello.sh", Data: []byte("hello")}}}
			_, err := saveScriptTransaction(snap, in, func() error { return nil }, func(uint32, string) error { return errors.New("connection lost") })
			if err == nil {
				t.Fatal("expected pending save")
			}
			state, err := scriptMaintenanceState(snap.root, snap.entry, config.GPOConfig{})
			if err != nil || !state.Pending || state.RecoveryError != "" {
				t.Fatalf("pending state: %+v %v", state, err)
			}
			plan, err := buildScriptRestorePlan(snap.root, snap.entry, "pending", mode)
			if err != nil {
				t.Fatal(err)
			}
			backup, err := applyScriptRestore(snap.root, snap.entry, plan, ScriptMaintenanceChange{Revision: plan.view.Revision}, func(v uint32, ext string) error {
				if v != 1 || !strings.Contains(ext, "42B5FAAE") {
					t.Fatal(v, ext)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := root.Stat(backup); err != nil {
				t.Fatal("safety backup missing", err)
			}
			if _, err := root.Stat(editorJournal); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("recovery journal not cleared", err)
			}
			data, err := root.ReadFile("GPT.INI")
			v, _, e := gptVersion(data, nil)
			if err != nil || e != nil || v != 1 {
				t.Fatal("version did not advance", v, err, e)
			}
			file, err := root.ReadFile("Machine/Scripts/Startup/hello.sh")
			if mode == "after" && (err != nil || string(file) != "hello") {
				t.Fatal(file, err)
			}
			if mode == "before" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("created file was not removed", err)
			}
		})
	}
}

func TestScriptBackupPreviewRejectsTamperingAndStaleState(t *testing.T) {
	snap, root := scriptTestSnapshot(t, 0)
	backup, err := saveScriptTransaction(snap, ScriptChange{Revision: snap.view.Revision, Scope: "Machine", Event: "startup", Kind: "script", Entries: []ScriptAssignment{{"test.sh", ""}}}, func() error { return nil }, func(uint32, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	entry := ldap.NewEntry(snap.entry.DN, map[string][]string{"versionNumber": {"1"}, "uSNChanged": {"2"}})
	plan, err := buildScriptRestorePlan(snap.root, entry, backup, "before")
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("Machine/Scripts/scripts.ini", []byte("foreign change"), 0644); err != nil {
		t.Fatal(err)
	}
	fresh, err := buildScriptRestorePlan(snap.root, entry, backup, "before")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.view.Revision == plan.view.Revision || len(fresh.view.Conflicts) == 0 {
		t.Fatal("external edit not detected")
	}
	if _, err := applyScriptRestore(snap.root, entry, fresh, ScriptMaintenanceChange{Revision: plan.view.Revision}, nil); !errors.Is(err, ErrPolicyConflict) {
		t.Fatal("stale preview accepted", err)
	}
	if _, err := applyScriptRestore(snap.root, entry, fresh, ScriptMaintenanceChange{Revision: fresh.view.Revision}, nil); !errors.Is(err, ErrPolicyConflict) {
		t.Fatal("unacknowledged overwrite accepted", err)
	}
	raw, err := root.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"../outside", `Machine/Scripts/../../GPT.INI`, `User/Scripts/scripts.ini`} {
		bad := bytes.Replace(raw, []byte("Machine/Scripts/scripts.ini"), []byte(needle), 1)
		if _, err := validateScriptRecovery(bad, entry.DN); err == nil {
			t.Fatal("unsafe backup accepted", needle)
		}
	}
	if _, err := readScriptRecoveryFile(snap.root, "../GPT.INI"); err == nil {
		t.Fatal("backup download escaped policy")
	}
}

func TestScriptBackupRetentionAndPendingProtection(t *testing.T) {
	snap, root := scriptTestSnapshot(t, 0)
	for i := 1; i <= 4; i++ {
		name := fmt.Sprintf(".sambaadm-scripts-backup-%08x-0000-0000-0000-000000000000.json", i)
		if err := root.WriteFile(name, bytes.Repeat([]byte("x"), 600<<10), 0600); err != nil {
			t.Fatal(err)
		}
		when := time.Unix(int64(i), 0)
		if err := os.Chtimes(filepath.Join(root.Name(), name), when, when); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.GPOConfig{ScriptBackupKeep: 3, ScriptBackupMaxMiB: 1}
	state, err := scriptMaintenanceState(snap.root, snap.entry, cfg)
	if err != nil || len(state.Prunable) != 3 || !state.Backups[0].Protected {
		t.Fatal(state, err)
	}
	if err := root.WriteFile(editorJournal, []byte("broken journal"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := pruneScriptBackups(snap.root, cfg); err == nil {
		t.Fatal("retention ran during recovery")
	}
	if err := root.Remove(editorJournal); err != nil {
		t.Fatal(err)
	}
	removed, err := pruneScriptBackups(snap.root, cfg)
	if err != nil || len(removed) != 3 {
		t.Fatal(removed, err)
	}
	state, err = scriptMaintenanceState(snap.root, snap.entry, cfg)
	if err != nil || len(state.Backups) != 1 || state.TotalBytes > state.MaxBytes {
		t.Fatal(state, err)
	}
}

func TestRecoveryCanReplaceDamagedJournalWithReviewedBackup(t *testing.T) {
	snap, root := scriptTestSnapshot(t, 0)
	backup, err := saveScriptTransaction(snap, ScriptChange{Revision: snap.view.Revision, Scope: "Machine", Event: "startup", Kind: "script", Entries: []ScriptAssignment{{"test.sh", ""}}}, func() error { return nil }, func(uint32, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(editorJournal, []byte("partial JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	entry := ldap.NewEntry(snap.entry.DN, map[string][]string{"versionNumber": {"1"}, "uSNChanged": {"2"}})
	plan, err := buildScriptRestorePlan(snap.root, entry, backup, "before")
	if err != nil || len(plan.view.Conflicts) == 0 {
		t.Fatal(plan, err)
	}
	_, err = applyScriptRestore(snap.root, entry, plan, ScriptMaintenanceChange{Revision: plan.view.Revision, AllowConflicts: true}, func(uint32, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Stat(editorJournal); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestRecoveryFailureCanBeCompletedAgain(t *testing.T) {
	snap, _ := scriptTestSnapshot(t, 0)
	in := ScriptChange{Revision: snap.view.Revision, Scope: "Machine", Event: "startup", Kind: "script", Entries: []ScriptAssignment{{"complete.sh", ""}}}
	_, err := saveScriptTransaction(snap, in, func() error { return nil }, func(uint32, string) error { return errors.New("network lost") })
	if err == nil {
		t.Fatal("expected pending")
	}
	plan, err := buildScriptRestorePlan(snap.root, snap.entry, "pending", "after")
	if err != nil {
		t.Fatal(err)
	}
	_, err = applyScriptRestore(snap.root, snap.entry, plan, ScriptMaintenanceChange{Revision: plan.view.Revision}, func(uint32, string) error { return errors.New("second network loss") })
	if err == nil {
		t.Fatal("failed recovery reported success")
	}
	retry, err := buildScriptRestorePlan(snap.root, snap.entry, "pending", "after")
	if err != nil {
		t.Fatal("recovery journal not reusable", err)
	}
	if _, err := applyScriptRestore(snap.root, snap.entry, retry, ScriptMaintenanceChange{Revision: retry.view.Revision}, func(uint32, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
}
