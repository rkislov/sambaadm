package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDirectoryEditorPreservesSearchAndLeavesFilesNonExecutable(t *testing.T) {
	shares, acl, root := treeTestService(t)
	for _, input := range []SetACLInput{
		{Mode: "0640", Owner: "missing-owner-must-not-be-applied"},
		{ACL: "g:12345:r--"},
		{ACL: "g:12345:rw-"},
		{ACL: "g:12345:r-x,m::r--"},
		{DefaultACL: "g:12345:4"},
		{DefaultACL: "g:12345:r-x,m::---"},
	} {
		if _, err := acl.SetSharePath(context.Background(), "docs", "", input, "test", ""); err == nil || !strings.Contains(err.Error(), "x") {
			t.Fatalf("unsafe directory assignment accepted or checked after mutation: %+v %v", input, err)
		}
		info, err := os.Stat(root)
		if err != nil || info.Mode().Perm() != 0755 {
			t.Fatal("rejected assignment changed directory mode", err)
		}
	}
	if _, err := acl.Set(context.Background(), SetACLInput{Path: root, Mode: "0644"}, "test", ""); err == nil || !strings.Contains(err.Error(), "x") {
		t.Fatal("bare ACL endpoint bypassed directory search", err)
	}
	sharePath := filepath.Join(filepath.Dir(root), "unsafe-created-share")
	if _, err := shares.Create(context.Background(), CreateShareInput{Name: "unsafe-created-share", Path: sharePath, Mode: "0644"}, "test", ""); err == nil {
		t.Fatal("created a directory share without search")
	}
	if _, err := os.Stat(sharePath); !os.IsNotExist(err) {
		t.Fatal("rejected share created its directory", err)
	}
	file := filepath.Join(root, "ordinary.txt")
	if err := os.WriteFile(file, []byte("read me"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := acl.SetSharePath(context.Background(), "docs", "ordinary.txt", SetACLInput{Mode: "0640"}, "test", ""); err != nil {
		t.Fatal("file incorrectly required execute", err)
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm() != 0640 {
		t.Fatal("file received execute bits")
	}
	spec, err := BuildDirectoryACLSpec("group", "12345", "rw")
	if err != nil || spec != "g:12345:rwx" {
		t.Fatal("write builder lost search", spec, err)
	}
	spec, err = BuildDirectoryACLSpec("group", "12345", "r")
	if err != nil || spec != "g:12345:r-x" {
		t.Fatal("read builder lost search", spec, err)
	}
}
func TestDirectorySearchAllowsDropboxesAndExplicitRevocation(t *testing.T) {
	for _, in := range []SetACLInput{{Mode: "0000"}, {ACL: "u::rwx,g::---,m::---,o::---"}, {Mode: "0300"}, {ACL: "g:12345:---"}, {ACL: "g:12345:-wx"}, {ACL: "g:12345:--x"}, {ACL: "g:12345:5,m::5", DefaultACL: "g:12345:r-x,m::r-x"}} {
		if err := validateDirectorySearchInput(in); err != nil {
			t.Fatalf("valid deliberate assignment rejected: %+v %v", in, err)
		}
	}
}
