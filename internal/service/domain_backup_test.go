package service

import (
	"context"
	"os"
	"path/filepath"
	"sambaadm/internal/config"
	"strings"
	"testing"
)

func TestDomainBackupStorageAndReplay(t *testing.T) {
	cfg := &config.Config{}
	cfg.Helper.BackupRoot = t.TempDir()
	cfg.Helper.Node = "dc.example.com"
	if _, e := backupRoot(cfg); e == nil {
		t.Fatal("accepted disabled backups")
	}
	cfg.Helper.DomainBackupEnabled = true
	root, e := backupRoot(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	req := DomainBackupRequest{ID: "00000000-0000-0000-0000-000000000001", Controller: cfg.Helper.Node, DomainGUID: make([]byte, 16), BaseDN: "DC=example,DC=com", PlanRevision: strings.Repeat("a", 64)}
	if e = root.Mkdir(req.ID, 0700); e != nil {
		t.Fatal(e)
	}
	if e = createBackupJSON(root, req.ID+"/request.json", req); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(cfg.Helper.BackupRoot, "domain-backups", req.ID, "domain.tar.gz"), make([]byte, 100), 0600); e != nil {
		t.Fatal(e)
	}
	job := DomainBackupJob{DomainBackupRequest: req, Status: "backed_up", SHA256: strings.Repeat("b", 64), Bytes: 100, Archive: "domain.tar.gz"}
	if e = createBackupJSON(root, req.ID+"/status.json", job); e != nil {
		t.Fatal(e)
	}
	out, e := helperDomainBackup(context.Background(), cfg, "domain.backup.start", HostOperation{Input: hostInput(req)})
	if e != nil {
		t.Fatal(e)
	}
	if out.(*DomainBackupJob).Status != "backed_up" || out.(*DomainBackupJob).RestoreVerified {
		t.Fatal(out)
	}
	req.PlanRevision = strings.Repeat("c", 64)
	if _, e = helperDomainBackup(context.Background(), cfg, "domain.backup.start", HostOperation{Input: hostInput(req)}); e == nil {
		t.Fatal("reused ID for other plan")
	}
	for _, id := range []string{"../outside", "-option", ""} {
		if _, e = localBackupStatus(context.Background(), root, id); e == nil {
			t.Fatal("invalid ID accepted")
		}
	}
	if e = os.Chmod(filepath.Join(cfg.Helper.BackupRoot, "domain-backups", req.ID, "status.json"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = localBackupStatus(context.Background(), root, req.ID); e == nil {
		t.Fatal("public job status accepted")
	}
}
func TestCleanupPeerComparisonIgnoresLocalUSN(t *testing.T) {
	a := testCleanupPlan().Objects[0]
	b := a
	b.Attributes = map[string][][]byte{}
	for k, v := range a.Attributes {
		b.Attributes[k] = v
	}
	a.Attributes["uSNChanged"] = [][]byte{[]byte("1")}
	b.Attributes["uSNChanged"] = [][]byte{[]byte("100")}
	if string(comparableCleanupObject(a)) != string(comparableCleanupObject(b)) {
		t.Fatal("compared DC-local USNs")
	}
	b.Attributes["description"] = [][]byte{[]byte("different")}
	if string(comparableCleanupObject(a)) == string(comparableCleanupObject(b)) {
		t.Fatal("missed metadata conflict")
	}
}

func TestNativeHelpersDoNotDelegateToCommandHandlers(t *testing.T) {
	for name, script := range map[string]string{"domain backup": domainBackupWorker, "RODC preload": localRODCPreloadScript} {
		for _, forbidden := range []string{"samba-tool", "samba.netcmd", "subprocess", "os.system("} {
			if strings.Contains(script, forbidden) {
				t.Fatalf("%s delegates through %s", name, forbidden)
			}
		}
	}
}
