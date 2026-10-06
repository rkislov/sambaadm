package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"sambaadm/internal/audit"
	"sambaadm/internal/config"
)

func TestShareCreateListDelete(t *testing.T) {
	dir := t.TempDir()
	smb := filepath.Join(dir, "smb.conf")
	root := filepath.Join(dir, "shares")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(smb, []byte("[global]\n   workgroup = TEST\n"), 0644); err != nil {
		t.Fatal(err)
	}
	log, err := audit.New("")
	if err != nil {
		t.Fatal(err)
	}
	svc := newShareService(log, config.SambaConfig{
		SMBConf:    smb,
		SharesRoot: root,
		CreateMode: "0755",
		ReloadCmd:  "true", // no-op reload
	})

	createDir := true
	reload := true
	sh, err := svc.Create(context.Background(), CreateShareInput{
		Name:      "docs",
		Comment:   "Documents",
		CreateDir: &createDir,
		Reload:    &reload,
		ValidUsers: "@staff",
	}, "test", "cli")
	if err != nil {
		t.Fatal(err)
	}
	if sh.Path != filepath.Join(root, "docs") {
		t.Fatalf("path=%s", sh.Path)
	}
	if _, err := os.Stat(sh.Path); err != nil {
		t.Fatal(err)
	}

	list, err := svc.ListFileShares(context.Background())
	if err != nil || len(list) != 1 || list[0].Name != "docs" {
		t.Fatalf("list=%v err=%v", list, err)
	}

	aclSvc := newFSACLService(log, svc)
	info, err := aclSvc.Get(context.Background(), sh.Path)
	if err != nil || !info.Exists {
		t.Fatalf("acl get: %+v err=%v", info, err)
	}

	if err := svc.Delete(context.Background(), "docs", true, "test", "cli"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sh.Path); !os.IsNotExist(err) {
		t.Fatalf("dir should be removed: %v", err)
	}
}

func TestSharePathGuard(t *testing.T) {
	dir := t.TempDir()
	smb := filepath.Join(dir, "smb.conf")
	_ = os.WriteFile(smb, []byte("[global]\n"), 0644)
	log, _ := audit.New("")
	svc := newShareService(log, config.SambaConfig{
		SMBConf: smb, SharesRoot: filepath.Join(dir, "shares"), ReloadCmd: "true",
	})
	_, err := svc.Create(context.Background(), CreateShareInput{
		Name: "x", Path: "/tmp/evil",
	}, "t", "")
	if err == nil {
		t.Fatal("expected path guard error")
	}
}
