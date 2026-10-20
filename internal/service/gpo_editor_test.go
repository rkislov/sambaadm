package service

import (
	"bytes"
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
	if _, e = readPolicyFile(root, "GPT.INI"); e == nil {
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
	machine, e := policyChild(root, ".", "Machine", false)
	if e != nil || machine != "MACHINE" {
		t.Fatalf("machine path %q %v", machine, e)
	}
	ini, e := policyChild(root, ".", "GPT.INI", false)
	if e != nil || ini != "gpt.ini" {
		t.Fatalf("ini path %q %v", ini, e)
	}
	missing, e := policyChild(root, machine, "Registry.pol", true)
	if e != nil || missing != filepath.Join("MACHINE", "Registry.pol") {
		t.Fatalf("new registry path %q %v", missing, e)
	}
}
