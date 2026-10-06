package smbconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndSave(t *testing.T) {
	src := `
# header
[global]
   workgroup = EXAMPLE
   security = ADS

[data]
   path = /srv/samba/data
   read only = no
   comment = Shared data
`
	doc, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	names := doc.SectionNames()
	if len(names) != 2 || names[0] != "global" || names[1] != "data" {
		t.Fatalf("sections: %v", names)
	}
	v, ok := doc.GetParam("data", "path")
	if !ok || v != "/srv/samba/data" {
		t.Fatalf("path=%q ok=%v", v, ok)
	}
	doc.SetParam("data", "browseable", "yes")
	doc.EnsureSection("public")
	doc.SetParam("public", "path", "/srv/samba/public")
	doc.SetParam("public", "guest ok", "yes")

	dir := t.TempDir()
	path := filepath.Join(dir, "smb.conf")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	if err := doc.SaveAtomic(path); err != nil {
		t.Fatal(err)
	}
	again, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := again.Get("public"); !ok {
		t.Fatal("public missing")
	}
	if v, _ := again.GetParam("data", "browseable"); v != "yes" {
		t.Fatalf("browseable=%q", v)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("expected bak: %v", err)
	}
}

func TestDeleteSection(t *testing.T) {
	doc, err := Parse(strings.NewReader("[a]\nx=1\n[b]\ny=2\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.DeleteSection("a") {
		t.Fatal("delete failed")
	}
	if _, ok := doc.Get("a"); ok {
		t.Fatal("still present")
	}
	if names := doc.SectionNames(); len(names) != 1 || names[0] != "b" {
		t.Fatalf("names=%v", names)
	}
}
