package service

import (
	"bytes"
	"github.com/go-ldap/ldap/v3"
	"os"
	"path/filepath"
	"sambaadm/internal/policy"
	"testing"
)

const editorTestADMX = "\ufeff" + `<?xml version="1.0"?><policyDefinitions xmlns="http://schemas.microsoft.com/GroupPolicy/2006/07/PolicyDefinitions"><policies><policy name="chronyd.service" class="Machine" key="Software\BaseALT\Policies\SystemdUnits" valueName="chronyd.service"><enabledValue><decimal value="1"/></enabledValue><disabledValue><decimal value="0"/></disabledValue></policy></policies></policyDefinitions>`

func editorTemplate(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "BaseALTSystemdUnits.admx")
	if e := os.WriteFile(p, []byte(editorTestADMX), 0600); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestGPTVersion(t *testing.T) {
	original := []byte("; comment\r\n[General]\r\nVersion=65537\r\nDisplayName=Keep\r\n[Other]\r\nVersion=9\r\n")
	next := uint32(65538)
	got, updated, e := gptVersion(original, &next)
	if e != nil || got != 65537 || !bytes.Equal(updated, bytes.Replace(original, []byte("65537"), []byte("65538"), 1)) {
		t.Fatalf("GPT.INI %q %v", updated, e)
	}
	for _, bad := range []string{"Version=1", "[General]\nVersion=1\nVersion=2", "[General]\nVersion=-1", "\xff\xfe\x00"} {
		if _, _, e = gptVersion([]byte(bad), nil); e == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
func TestInstalledALTTemplate(t *testing.T) {
	defs, e := policy.SystemdDefinitions(editorTemplate(t))
	if e != nil || len(defs) != 1 || defs[0].Value != "chronyd.service" {
		t.Fatalf("definitions %+v %v", defs, e)
	}
}
func TestPolicyFilesRefuseSymlinks(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("untouched"), 0600)
	if e := os.Symlink(outside, filepath.Join(dir, "GPT.INI")); e != nil {
		t.Skip(e)
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	if _, e = readPolicyFile(localPolicyStore{root}, "GPT.INI"); e == nil {
		t.Fatal("followed symlink")
	}
}

func TestPolicyFilenameCase(t *testing.T) {
	dir := t.TempDir()
	if e := os.Mkdir(filepath.Join(dir, "MACHINE"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "gpt.ini"), []byte("[General]\nVersion=0\n"), 0600); e != nil {
		t.Fatal(e)
	}
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	machine, e := policyChild(localPolicyStore{root}, ".", "Machine", false)
	if e != nil || machine != "MACHINE" {
		t.Fatalf("machine path %q %v", machine, e)
	}
	ini, e := policyChild(localPolicyStore{root}, ".", "GPT.INI", false)
	if e != nil || ini != "gpt.ini" {
		t.Fatalf("ini path %q %v", ini, e)
	}
	missing, e := policyChild(localPolicyStore{root}, machine, "Registry.pol", true)
	if e != nil || missing != filepath.Join("MACHINE", "Registry.pol") {
		t.Fatalf("new registry path %q %v", missing, e)
	}
}

func TestALTPolicyMixedSettingsAndDisabledSection(t *testing.T) {
	definitions := []policy.Definition{
		{ID: "enabled", Key: policy.SystemdKey, Value: "one.service", Scope: "Machine"},
		{ID: "disabled", Key: policy.SystemdKey, Value: "two.service", Scope: "Machine"},
		{ID: "absent", Key: policy.SystemdKey, Value: "three.service", Scope: "Machine"},
		{ID: "foreign", Key: policy.SystemdKey, Value: "four.service", Scope: "Machine"},
	}
	records := []policy.Record{
		{Key: policy.SystemdKey, Name: "ONE.SERVICE", Type: 4, Data: []byte{1, 0, 0, 0}},
		{Key: policy.SystemdKey, Name: "two.service", Type: 4, Data: []byte{0, 0, 0, 0}},
		{Key: policy.SystemdKey, Name: "four.service", Type: 1, Data: []byte{49, 0, 0, 0}},
	}
	for _, flags := range []string{"0", "1", "2", "3"} {
		snap := editorSnapshot{entry: ldap.NewEntry("CN=test", map[string][]string{"flags": {flags}}), definitions: definitions, records: records, version: 65539, revision: "expected-revision"}
		view := snap.view()
		if view.MachineDisabled != (flags == "2" || flags == "3") {
			t.Fatalf("wrong machine section state for flags %s", flags)
		}
		want := []string{"enabled", "disabled", "not-configured", "unsupported"}
		for i, state := range want {
			if view.Settings[i].State != state {
				t.Fatalf("setting %d: got %q want %q", i, view.Settings[i].State, state)
			}
		}
		if view.Version != 65539 || view.Revision != "expected-revision" {
			t.Fatal("client concurrency metadata lost")
		}
	}
	if len(records) != 3 || records[2].Type != 1 || !bytes.Equal(records[2].Data, []byte{49, 0, 0, 0}) {
		t.Fatal("view changed an unsupported record")
	}
}

// Local adapter is test-only: the production editor exclusively uses SMB.
type localPolicyStore struct{ *os.Root }

func (s localPolicyStore) Open(p string) (policyFile, error) { return s.Root.Open(p) }
func (s localPolicyStore) OpenFile(p string, f int, m os.FileMode) (policyFile, error) {
	return s.Root.OpenFile(p, f, m)
}
func (s localPolicyStore) ReadDir(p string) ([]os.FileInfo, error) {
	f, e := s.Root.Open(p)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return f.Readdir(-1)
}

func TestRemoteEditorRejectsPathEscapesBeforeNetwork(t *testing.T) {
	store := &smbPolicyStore{base: "example.test/Policies/{GUID}"}
	for _, name := range []string{"", "..", "../GPT.INI", "/GPT.INI", "Machine/../../GPT.INI", `Machine\Registry.pol`, "GPT.INI:stream", "Machine//Registry.pol"} {
		if _, e := store.checked(name, true); e == nil {
			t.Fatalf("accepted %q", name)
		}
	}
}

func TestPolicyVersionHalves(t *testing.T) {
	for _, tc := range []struct {
		scope     string
		old, next uint32
	}{{"User", 65541, 131077}, {"Machine", 65541, 65542}, {"User", 65535, 131071}} {
		got, e := nextPolicyVersion(tc.old, tc.scope)
		if e != nil || got != tc.next {
			t.Fatalf("%+v got %d %v", tc, got, e)
		}
	}
	if _, e := nextPolicyVersion(65535, "Machine"); e == nil {
		t.Fatal("machine wrap")
	}
	if _, e := nextPolicyVersion(0xffff0000, "User"); e == nil {
		t.Fatal("user wrap")
	}
}
