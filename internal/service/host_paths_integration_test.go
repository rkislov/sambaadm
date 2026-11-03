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
