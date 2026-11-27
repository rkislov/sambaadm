package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	"testing"
)

func treeTestService(t *testing.T) (*ShareService, *FSACLService, string) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "shares")
	docs := filepath.Join(root, "docs")
	if err := os.MkdirAll(filepath.Join(docs, "Отдел & проекты", "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	smb := filepath.Join(dir, "smb.conf")
	if err := os.WriteFile(smb, []byte("[docs]\npath = "+docs+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := audit.New("")
	if err != nil {
		t.Fatal(err)
	}
	s := newShareService(log, config.SambaConfig{SMBConf: smb, SharesRoot: root})
	return s, newFSACLService(log, s), docs
}

func TestShareDirectoryScope(t *testing.T) {
	s, acl, docs := treeTestService(t)
	ctx := context.Background()
	outside := filepath.Join(filepath.Dir(docs), "other-share")
	if err := os.Mkdir(outside, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(docs, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(docs, "file.txt"), []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}
	page, err := s.Directories(ctx, "docs", "", 0)
	if err != nil || len(page.Directories) != 1 || page.Directories[0].Name != "Отдел & проекты" {
		t.Fatalf("%+v %v", page, err)
	}
	for _, rel := range []string{"../other-share", "/etc", "a/../../other-share", "escape", "escape/child", "..\\other-share"} {
		if _, err := s.Directories(ctx, "docs", rel, 0); err == nil {
			t.Errorf("browse accepted %q", rel)
		}
		if _, err := acl.GetSharePath(ctx, "docs", rel); err == nil {
			t.Errorf("ACL read accepted %q", rel)
		}
		if _, err := acl.SetSharePath(ctx, "docs", rel, SetACLInput{Mode: "0700"}, "test", ""); err == nil {
			t.Errorf("ACL write accepted %q", rel)
		}
	}
	info, _ := os.Stat(outside)
	if info.Mode().Perm() != 0755 {
		t.Fatal("outside share changed")
	}
	rel := "Отдел & проекты/nested"
	got, err := acl.SetSharePath(ctx, "docs", rel, SetACLInput{Path: outside, Mode: "0700"}, "test", "")
	if err != nil || got.Path != filepath.Join(docs, filepath.FromSlash(rel)) {
		t.Fatalf("selected directory: %+v %v", got, err)
	}
	info, _ = os.Stat(filepath.Join(docs, filepath.FromSlash(rel)))
	if info.Mode().Perm() != 0700 {
		t.Fatal("selected directory not changed")
	}
	info, _ = os.Stat(docs)
	if info.Mode().Perm() != 0755 {
		t.Fatal("root changed instead of selected directory")
	}
	if _, err := acl.SetSharePath(ctx, "docs", "", SetACLInput{Mode: "0000", Recursive: true}, "test", ""); err == nil {
		t.Fatal("unsafe recursive change accepted")
	}
}

func TestShareDirectoryPagination(t *testing.T) {
	s, _, docs := treeTestService(t)
	for i := 0; i < 430; i++ {
		if err := os.Mkdir(filepath.Join(docs, fmt.Sprintf("dir-%03d", i)), 0755); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	offset := 0
	for {
		page, err := s.Directories(context.Background(), "docs", ".", offset)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Directories) > 200 {
			t.Fatal("unbounded page")
		}
		for _, dir := range page.Directories {
			if seen[dir.Path] {
				t.Fatal("duplicate directory")
			}
			seen[dir.Path] = true
		}
		if page.Next == 0 {
			break
		}
		if page.Next <= offset {
			t.Fatal("cursor did not advance")
		}
		offset = page.Next
	}
	if len(seen) != 431 {
		t.Fatalf("lost directories: %d", len(seen))
	}
}
func TestACLEffectivePermissionsAndIdentityValidation(t *testing.T) {
	entry, ok := parseACLLine("group:123:rwx\t#effective:r-x", false)
	if !ok || entry.Qualifier != "123" || entry.Perms != "rwx" || entry.Effective != "r-x" {
		t.Fatalf("%+v", entry)
	}
	for _, name := range []string{"staff:rwx,o::rwx", "staff\nother", "staff\x00"} {
		if _, err := BuildACLSpec("group", name, "rwx"); err == nil {
			t.Fatal("accepted injected ACL identity")
		}
	}
}
