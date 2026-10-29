package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/policy"
)

func TestScriptINIPatchPreservesGPUISections(t *testing.T) {
	before := "; GPUI policy\r\n[Startup]\r\n0CmdLine=old.sh\r\n0Parameters=old\r\nComment=keep\r\n[Shutdown]\r\n0CmdLine=shutdown.sh\r\n0Parameters=--stop\r\n[ScriptsConfig]\r\nStartExecutePSFirst=true\r\nEndExecutePSFirst=false\r\n"
	for _, wide := range []bool{false, true} {
		data, err := patchScriptINI(encodePolicyText(before, wide), "Machine", "startup", "script", []ScriptAssignment{{"пример.sh", "--ключ=значение=a"}, {"second.sh", ""}})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(data, []byte{0xff, 0xfe}) {
			t.Fatal("scripts must be UTF-16LE for GPUI and gpupdate")
		}
		text, _, err := decodePolicyText(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"; GPUI policy", "Comment=keep", "[Shutdown]\r\n0CmdLine=shutdown.sh\r\n0Parameters=--stop", "[ScriptsConfig]\r\nStartExecutePSFirst=true\r\nEndExecutePSFirst=false", "0CmdLine=пример.sh\r\n0Parameters=--ключ=значение=a", "1CmdLine=second.sh\r\n1Parameters="} {
			if !strings.Contains(text, want) {
				t.Fatalf("lost content %q: %s", want, text)
			}
		}
		rows, err := parseGPOScripts(data, "Machine", "scripts.ini")
		if err != nil || len(rows) != 3 || rows[0].Command != "пример.sh" {
			t.Fatalf("roundtrip: %+v %v", rows, err)
		}
		cleared, err := patchScriptINI(data, "Machine", "startup", "script", []ScriptAssignment{})
		if err != nil {
			t.Fatal(err)
		}
		rows, err = parseGPOScripts(cleared, "Machine", "scripts.ini")
		if err != nil || len(rows) != 1 || rows[0].Event != "shutdown" {
			t.Fatalf("clear erased other event: %+v %v", rows, err)
		}
	}
	for _, text := range []string{"[Startup]\n[Startup]\n", "[Startup]\n0CmdLine=x\n0Parameters=\n0ForeignMetadata=keep\n"} {
		if _, err := patchScriptINI([]byte(text), "Machine", "startup", "script", []ScriptAssignment{}); err == nil {
			t.Fatalf("unsafe rewrite accepted: %s", text)
		}
	}
}

func TestScriptValidationPathsScopesAndInjection(t *testing.T) {
	valid := ScriptChange{Revision: "revision", Scope: "Machine", Event: "startup", Kind: "script", Entries: []ScriptAssignment{{"/usr/local/bin/example.sh", "--flag=value"}}}
	if err := validateScriptChange(valid); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../x.sh", `..\x.sh`, "/x.sh", "x:stream", "CON.sh", "nul", "x\n.sh", "name.", " space.sh"} {
		in := valid
		in.Files = []ScriptFileChange{{Name: name, Data: []byte("x")}}
		if err := validateScriptChange(in); !errors.Is(err, policy.ErrInvalidValue) {
			t.Fatalf("unsafe filename %q: %v", name, err)
		}
	}
	for _, edit := range []func(*ScriptChange){func(in *ScriptChange) { in.Scope = "User" }, func(in *ScriptChange) { in.Kind = "unknown" }, func(in *ScriptChange) { in.Entries = nil }, func(in *ScriptChange) { in.Entries = []ScriptAssignment{{"bad.sh\n[Shutdown]", ""}} }, func(in *ScriptChange) {
		in.Files = []ScriptFileChange{{Name: "a.sh", Data: []byte{}}, {Name: "A.SH", Data: []byte{}}}
	}} {
		in := valid
		edit(&in)
		if err := validateScriptChange(in); !errors.Is(err, policy.ErrInvalidValue) {
			t.Fatalf("invalid change accepted: %+v %v", in, err)
		}
	}
}

func scriptTestSnapshot(t *testing.T, version uint32) (*scriptSnapshot, *os.Root) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "GPT.INI"), []byte(fmt.Sprintf("[General]\r\nDisplayName=GPUI\r\nVersion=%d\r\n", version)), 0640); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	entry := ldap.NewEntry("CN={00000000-0000-0000-0000-000000000001},CN=Policies,DC=example,DC=com", map[string][]string{"versionNumber": {fmt.Sprint(version)}, "uSNChanged": {"1"}, "flags": {"0"}, "gPCMachineExtensionNames": {registryCSE}})
	snap, err := loadScriptSnapshot(localPolicyStore{root}, entry, "dc.example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	return snap, root
}

func TestScriptTransactionBackupVersionAndConflict(t *testing.T) {
	snap, root := scriptTestSnapshot(t, 7)
	in := ScriptChange{Revision: snap.view.Revision, Scope: "User", Event: "logon", Kind: "script", Entries: []ScriptAssignment{{"hello.sh", "--test"}}, Files: []ScriptFileChange{{Name: "hello.sh", Data: []byte("#!/bin/sh\necho hello\n")}}}
	backup, err := saveScriptTransaction(snap, in, func() error { return nil }, func(version uint32, ext string) error {
		if version != 65543 || !strings.Contains(ext, "{40B66650-") {
			t.Fatalf("wrong user metadata: %d %s", version, ext)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Stat(backup); err != nil {
		t.Fatal("backup missing", err)
	}
	if _, err := root.Stat(editorJournal); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("journal not cleaned", err)
	}
	data, err := root.ReadFile("User/Scripts/scripts.ini")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := parseGPOScripts(data, "User", "scripts.ini")
	if err != nil || len(rows) != 1 || rows[0].Command != "hello.sh" {
		t.Fatalf("scripts not saved %+v %v", rows, err)
	}
	data, err = root.ReadFile("GPT.INI")
	version, _, e := gptVersion(data, nil)
	if err != nil || e != nil || version != 65543 || !bytes.Contains(data, []byte("DisplayName=GPUI")) {
		t.Fatalf("GPT metadata %q %v %v", data, err, e)
	}
	if _, err := saveScriptTransaction(snap, ScriptChange{Revision: "stale", Scope: "User", Event: "logon", Kind: "script", Entries: []ScriptAssignment{}}, func() error { t.Fatal("stale request reached mutation"); return nil }, nil); !errors.Is(err, ErrPolicyConflict) {
		t.Fatal(err)
	}
}

func TestScriptTransactionRollbackAndUnknownCommit(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprint(uncertain), func(t *testing.T) {
			snap, root := scriptTestSnapshot(t, 0)
			original, _ := root.ReadFile("GPT.INI")
			in := ScriptChange{Revision: snap.view.Revision, Scope: "Machine", Event: "startup", Kind: "PowerShell", Entries: []ScriptAssignment{{"test.ps1", ""}}}
			_, err := saveScriptTransaction(snap, in, func() error { return nil }, func(uint32, string) error {
				if uncertain {
					return errors.New("connection lost")
				}
				return ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("GPUI changed LDAP"))
			})
			if err == nil {
				t.Fatal("commit failure hidden")
			}
			_, journal := root.Stat(editorJournal)
			if uncertain {
				if journal != nil || !strings.Contains(err.Error(), "requires recovery") {
					t.Fatalf("uncertain result lost journal: %v %v", err, journal)
				}
			} else {
				if !errors.Is(err, ErrPolicyConflict) || !errors.Is(journal, os.ErrNotExist) {
					t.Fatal(err, journal)
				}
				after, _ := root.ReadFile("GPT.INI")
				if !bytes.Equal(original, after) {
					t.Fatal("GPT not restored")
				}
				if _, err := root.Stat("Machine"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("new directories not reverted", err)
				}
			}
		})
	}
}

func TestScriptTransactionDoesNotOverwriteGPUIOnConflict(t *testing.T) {
	snap, root := scriptTestSnapshot(t, 0)
	in := ScriptChange{Revision: snap.view.Revision, Scope: "Machine", Event: "startup", Kind: "script", Entries: []ScriptAssignment{{"test.sh", ""}}}
	_, err := saveScriptTransaction(snap, in, func() error { return nil }, func(uint32, string) error {
		if err := root.WriteFile("Machine/Scripts/scripts.ini", encodePolicyText("[Startup]\r\n0CmdLine=gpui.sh\r\n0Parameters=\r\n", true), 0644); err != nil {
			t.Fatal(err)
		}
		return ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("external editor"))
	})
	data, _ := root.ReadFile("Machine/Scripts/scripts.ini")
	text, _, _ := decodePolicyText(data)
	if err == nil || !strings.Contains(text, "gpui.sh") {
		t.Fatalf("external save lost: %v %s", err, text)
	}
	if _, err := root.Stat(editorJournal); err != nil {
		t.Fatal("conflicting save lost recovery journal", err)
	}
}

func TestGPTINIFromLegacyGPUI(t *testing.T) {
	before := encodePolicyText("[General]\r\nDisplayName=Тест GPUI\r\nVersion=65537\r\n", true)
	next := uint32(65538)
	version, after, err := gptVersion(before, &next)
	if err != nil || version != 65537 {
		t.Fatal(version, err)
	}
	text, wide, err := decodePolicyText(after)
	if err != nil || !wide || !strings.Contains(text, "DisplayName=Тест GPUI") || !strings.Contains(text, "Version=65538") {
		t.Fatal(text, wide, err)
	}
}

type failScriptWriteStore struct{ policyStore }

func (s failScriptWriteStore) OpenFile(name string, flags int, mode os.FileMode) (policyFile, error) {
	if name == "GPT.INI" && flags == os.O_RDWR {
		return nil, errors.New("simulated SMB write failure")
	}
	return s.policyStore.OpenFile(name, flags, mode)
}

func TestScriptWriteFailureRetainsRecoveryAndBlocksEditors(t *testing.T) {
	snap, root := scriptTestSnapshot(t, 0)
	snap.root = failScriptWriteStore{snap.root}
	in := ScriptChange{Revision: snap.view.Revision, Scope: "Machine", Event: "startup", Kind: "script", Entries: []ScriptAssignment{{"test.sh", ""}}}
	committed := false
	_, err := saveScriptTransaction(snap, in, func() error { return nil }, func(uint32, string) error { committed = true; return nil })
	if err == nil || committed || !strings.Contains(err.Error(), "requires recovery") {
		t.Fatalf("failed write treated as committed: %v", err)
	}
	if _, err := root.Stat(editorJournal); err != nil {
		t.Fatal("durable recovery data missing", err)
	}
	if _, err := loadScriptSnapshot(localPolicyStore{root}, snap.entry, "dc", false); err == nil || !strings.Contains(err.Error(), "unfinished policy save") {
		t.Fatalf("interrupted save not blocked: %v", err)
	}
}

func TestScriptPathRejectsInternalSymlink(t *testing.T) {
	snap, root := scriptTestSnapshot(t, 0)
	if err := root.Mkdir("Elsewhere", 0755); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("Elsewhere", "Machine"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, _, err := scriptPath(snap.root, "Machine", "Scripts", "scripts.ini"); err == nil {
		t.Fatal("script directory symlink accepted")
	}
}

func TestScriptExtensionMetadataMerge(t *testing.T) {
	prior := "[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}]"
	ext, err := scriptExtension(registryCSE+prior, "Machine")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ext, registryCSE) || !strings.Contains(ext, "{40B6664F-4972-11D1-A7CA-0000F87571E3}{FFFFFFFF-") {
		t.Fatal("unrelated CSE/ASE metadata lost or unsorted", ext)
	}
	again, err := scriptExtension(ext, "Machine")
	if err != nil || again != ext {
		t.Fatal("extension merge not idempotent", again, err)
	}
	if _, err := scriptExtension("[broken]", "Machine"); err == nil {
		t.Fatal("malformed extensions rewritten")
	}
}

// Optional, called by the upstream compatibility workflow before and after the
// actual GPUI INI plugin reads and writes the generated file.
func TestGPUIINIInterop(t *testing.T) {
	dir := os.Getenv("SAMBAADM_GPUI_FIXTURES")
	if dir == "" {
		t.Skip("set SAMBAADM_GPUI_FIXTURES for upstream GPUI roundtrip")
	}
	input := []byte("[Shutdown]\r\n0CmdLine=stop.sh\r\n0Parameters=--stop\r\n")
	data, err := patchScriptINI(input, "Machine", "startup", "script", []ScriptAssignment{{"пример.sh", "--ключ=значение=a"}, {"second.sh", "--two"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "input.ini"), data, 0644); err != nil {
		t.Fatal(err)
	}
	before, err := parseGPOScripts(data, "Machine", "scripts.ini")
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("SAMBAADM_GPUI_ROUNDTRIP") == "1" {
		after, err := os.ReadFile(filepath.Join(dir, "gpui.ini"))
		if err != nil {
			t.Fatal(err)
		}
		rows, err := parseGPOScripts(after, "Machine", "scripts.ini")
		if err != nil || !reflect.DeepEqual(rows, before) {
			t.Fatalf("GPUI roundtrip changed assignments: %+v %v", rows, err)
		}
	}
}
