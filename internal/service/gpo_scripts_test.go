package service

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	smb2 "github.com/cloudsoda/go-smb2"
)

func TestIntegrationGPOScriptsWithoutADMXEditor(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name := fmt.Sprintf("Scripts-%d", time.Now().UnixNano())
	if _, err := s.GPO.Create(ctx, name, "integration", ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.GPO.Delete(context.Background(), name, "integration", ""); err != nil {
			t.Error(err)
		}
	})
	entry, err := s.GPO.policyEntry(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	base, err := s.GPO.policyPath(ctx, entry)
	if err != nil {
		t.Fatal(err)
	}
	err = s.GPO.remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		if err := sh.MkdirAll(base+`\Machine\Scripts`, 0755); err != nil {
			return err
		}
		return sh.WriteFile(base+`\Machine\Scripts\scripts.ini`, []byte("[Startup]\n0CmdLine=recreate-keytab.sh\n0Parameters=--test\n"), 0644)
	})
	if err != nil {
		t.Fatal(err)
	}
	s.GPO.gpoCfg.EditorEnabled = false
	s.GPO.gpoCfg.ADMXPath = "/no-templates-required"
	out, err := s.GPO.Scripts(ctx, name)
	if err != nil || len(out.Scripts) != 1 || out.Scripts[0].Command != "recreate-keytab.sh" {
		t.Fatalf("scripts not visible without editor: %+v %v", out, err)
	}
}

func TestGPOScriptsEncodingsAndOrder(t *testing.T) {
	text := "[Startup]\r\n1Parameters=--name=пример\r\n1CmdLine=second.sh\r\n0CmdLine=recreate-keytab.sh\r\n0Parameters=\r\n[Logon]\r\n0CmdLine=ignored.sh\r\n0Parameters=\r\n"
	wide := []byte{0xff, 0xfe}
	for _, ch := range utf16.Encode([]rune(text)) {
		wide = binary.LittleEndian.AppendUint16(wide, ch)
	}
	for _, data := range [][]byte{[]byte(text), wide, append([]byte{0xef, 0xbb, 0xbf}, []byte(text)...)} {
		rows, err := parseGPOScripts(data, "Machine", "Machine/Scripts/scripts.ini")
		if err != nil || len(rows) != 2 || rows[0].Command != "recreate-keytab.sh" || rows[1].Parameters != "--name=пример" || rows[1].Order != 1 {
			t.Fatalf("incorrect scripts: %+v %v", rows, err)
		}
	}
	rows, err := parseGPOScripts([]byte("[Logon]\n0CmdLine=test.ps1\n0Parameters=-Name value\n"), "User", "User/Scripts/psscripts.ini")
	if err != nil || len(rows) != 1 || rows[0].Kind != "PowerShell" || rows[0].Event != "logon" {
		t.Fatalf("incorrect user PowerShell scripts: %+v %v", rows, err)
	}
	for _, bad := range [][]byte{{0xff, 0xfe, 1}, {0xff, 0xfe, 0, 0xd8}, []byte("[Startup]\n0Parameters=x\n"), []byte("[Startup]\n0CmdLine=x\n0CmdLine=y\n"), []byte("[Startup]\n-1CmdLine=x\n"), []byte("[Startup]\nbroken"), []byte("[Startup]\n0CmdLine=a\x00b")} {
		if _, err := parseGPOScripts(bad, "Machine", "scripts.ini"); err == nil {
			t.Errorf("accepted malformed scripts: %q", bad)
		}
	}
}

func TestReadGPOScriptsCaseInsensitiveAndMissingFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "machine", "sCrIpTs"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "machine", "sCrIpTs", "Scripts.INI"), []byte("[Startup]\n0CmdLine=recreate-keytab.sh\n0Parameters=\n"), 0644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	rows, err := readGPOScripts(localPolicyStore{root})
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].Source, "Scripts.INI") {
		t.Fatalf("incorrect SYSVOL discovery: %+v %v", rows, err)
	}
	// An inaccessible/non-directory path is an error, never an empty policy.
	if err := os.WriteFile(filepath.Join(dir, "User"), []byte("not a directory"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readGPOScripts(localPolicyStore{root}); err == nil {
		t.Fatal("non-directory silently treated as absent scripts")
	}
}
