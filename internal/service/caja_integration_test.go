package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sambaadm/internal/audit"
	"sambaadm/internal/config"
)

// Run by testdata/caja/run.sh in its disposable ALT GUI container. Caja itself
// runs as UID 1000; this process has the administrative filesystem role.
func TestIntegrationCajaDirectoryTemplate(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_CAJA") != "1" {
		t.Skip("requires disposable ALT/Caja lab")
	}
	const root = "/srv/sambaadm-caja-test"
	marker, err := os.ReadFile(filepath.Join(root, ".disposable-caja-lab"))
	if err != nil || string(marker) != "sambaadm-caja-only\n" {
		t.Fatal("disposable Caja lab marker required")
	}
	logger, err := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	shares := newShareService(logger, config.SambaConfig{SMBConf: "/tmp/caja-smb.conf", SharesRoot: root})
	acl := newFSACLService(logger, shares)
	ctx := context.Background()
	before, err := acl.GetSharePath(ctx, "acl-test", "mode-r-x")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []SetACLInput{{Mode: "0640"}, {ACL: "g:1000:r--"}, {ACL: "m::r--"}, {DefaultACL: "g:1000:r--"}} {
		if _, err := acl.SetSharePath(ctx, "acl-test", "mode-r-x", input, "caja-lab", ""); err == nil || !strings.Contains(err.Error(), "x") {
			t.Fatalf("directory search not protected: %+v %v", input, err)
		}
	}
	unchanged, err := acl.GetSharePath(ctx, "acl-test", "mode-r-x")
	if err != nil || unchanged.ACLText != before.ACLText || unchanged.Mode != before.Mode {
		t.Fatal("rejected operation changed directory", err)
	}
	file, err := acl.SetSharePath(ctx, "acl-test", "file-no-exec.txt", SetACLInput{Mode: "0644"}, "caja-lab", "")
	if err != nil || file.Mode != "0644" {
		t.Fatal("file incorrectly required execute", err)
	}
	t.Log("PASS directory mode/ACL/default ACL/mask without search rejected before mutation; non-executable file accepted")
	snapshot, err := shares.PermissionMap(ctx, "acl-test", ".")
	if err != nil || !snapshot.Complete {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	input := SharePermissionMapRequest{Root: ".", SnapshotRevision: snapshot.Revision, Overlays: []SharePermissionOverlay{{Path: ".", Recursive: true, Template: SharePermissionTemplate{Name: "Read and traverse", Inherit: true, Rules: []SharePermissionRule{{Group: "cajaqa", GID: "1000", Permissions: "r-x"}}}}}}
	plan, err := shares.PlanPermissionMap(ctx, "acl-test", input)
	if err != nil {
		t.Fatal(err)
	}
	input.Confirm = true
	input.PlanRevision = plan.Revision
	result, err := shares.ApplyPermissionMap(ctx, "acl-test", input, "caja-lab", "", t.TempDir())
	if err != nil || result.Status != "complete" {
		t.Fatalf("apply: %+v %v", result, err)
	}
	for _, path := range []string{"mode-r--", "acl-mask-no-x"} {
		current, err := acl.GetSharePath(ctx, "acl-test", path)
		if err != nil {
			t.Fatal(err)
		}
		groupOK, maskOK := false, false
		for _, entry := range current.Entries {
			if entry.Default {
				continue
			}
			if entry.Kind == "group" && entry.Qualifier == "1000" {
				groupOK = strings.Contains(entry.Perms, "x")
			}
			if entry.Kind == "mask" {
				maskOK = strings.Contains(entry.Perms, "x")
			}
		}
		if !groupOK || !maskOK {
			t.Fatal("template lost effective directory search", path, current.ACLText)
		}
	}
	t.Logf("PASS actual read/traverse template applied to %d ALT directories; effective group and mask search restored", len(result.Items))
}
