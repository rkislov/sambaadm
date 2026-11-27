package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIntegrationHostHelperFilesystemConfinement(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("requires host helper")
	}
	s, _ := integrationServices(t, true)
	ctx := context.Background()
	name := fmt.Sprintf("it-helper-files-%d", time.Now().UnixNano())
	dir := filepath.Join("/srv/samba", name)
	yes, no := true, false
	if _, e := s.Shares.Create(ctx, CreateShareInput{Name: name, Path: dir, Mode: "0750", Owner: "root:root", CreateDir: &yes, Reload: &no}, "test", ""); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Shares.Delete(context.Background(), name, true, "test", "") })
	if _, e := s.FSACL.Set(ctx, SetACLInput{Path: dir, Mode: "0700", ACL: "u::rwx,g::---,o::---"}, "test", ""); e != nil {
		t.Fatal(e)
	}
	got, e := s.FSACL.Get(ctx, dir)
	if e != nil || !got.IsDir || got.Mode != "0700" || got.Path != dir {
		t.Fatalf("host ACL: %+v %v", got, e)
	}
	child := filepath.Join(dir, "child")
	if e = os.Mkdir(child, 0750); e != nil {
		t.Fatal(e)
	}
	page, e := s.Shares.Directories(ctx, name, "", 0)
	if e != nil || len(page.Directories) != 1 || page.Directories[0].Path != "child" {
		t.Fatalf("share directory page: %+v %v", page, e)
	}
	if _, e = s.FSACL.SetSharePath(ctx, name, "child", SetACLInput{ACL: "u::rwx,g::r-x,o::---"}, "test", ""); e != nil {
		t.Fatal(e)
	}
	got, e = s.FSACL.GetSharePath(ctx, name, "child")
	if e != nil || got.Path != child || got.Mode != "0750" {
		t.Fatalf("nested host ACL: %+v %v", got, e)
	}
	snapshot, e := s.Shares.PermissionMap(ctx, name, ".")
	if e != nil || !snapshot.Complete {
		t.Fatalf("permission snapshot: %+v %v", snapshot, e)
	}
	input := SharePermissionMapRequest{Root: ".", SnapshotRevision: snapshot.Revision, Overlays: []SharePermissionOverlay{{Path: "child", Recursive: true, Template: SharePermissionTemplate{Name: "Integration template", Inherit: true, Rules: []SharePermissionRule{{Group: "root", GID: "0", Permissions: "rwx"}}}}}}
	plan, e := s.Shares.PlanPermissionMap(ctx, name, input)
	if e != nil || len(plan.Changes) != 1 {
		t.Fatalf("permission plan: %+v %v", plan, e)
	}
	input.Confirm = true
	input.PlanRevision = plan.Revision
	applied, e := s.Shares.ApplyPermissionMap(ctx, name, input, "test", "", "")
	if e != nil || applied.Status != "complete" {
		t.Fatalf("permission apply: %+v %v", applied, e)
	}
	got, e = s.FSACL.GetSharePath(ctx, name, "child")
	if e != nil || got.DefaultACL == "" || got.Mode != "0770" {
		t.Fatalf("template result: %+v %v", got, e)
	}
	outside := t.TempDir()
	secret := filepath.Join(outside, "outside")
	if e = os.WriteFile(secret, []byte("must remain private"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link")
	if e = os.Symlink(outside, link); e != nil {
		t.Fatal(e)
	}
	if _, e = s.FSACL.Set(ctx, SetACLInput{Path: filepath.Join(link, "outside"), Mode: "0777"}, "test", ""); e == nil {
		t.Fatal("ACL escaped share root through symlink")
	}
	st, e := os.Stat(secret)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("outside permissions changed", e)
	}
	if _, e = s.Shares.Create(ctx, CreateShareInput{Name: name + "-escape", Path: filepath.Join(link, "created"), CreateDir: &yes, Reload: &no}, "test", ""); e == nil {
		t.Fatal("directory creation escaped share root")
	}
	if _, e = os.Stat(filepath.Join(outside, "created")); !os.IsNotExist(e) {
		t.Fatal("outside directory was created", e)
	}
}
