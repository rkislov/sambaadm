package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
)

// This test uses real LDAP, target-host NSS, HTTPS helper and SMB sessions.
// It runs only in the explicitly opted-in disposable SAMBAADM.TEST domain.
func TestIntegrationSharePermissionTemplatesAndInheritance(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("requires disposable Samba and host helper")
	}
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	suffix := fmt.Sprintf("%x", time.Now().UnixNano())
	suffix = suffix[len(suffix)-10:]
	rwName, roName, oldName := "fsrw"+suffix, "fsro"+suffix, "fsold"+suffix
	rwUser, roUser := "furw"+suffix, "furo"+suffix
	const password = "Lab-File-User-Pass1!"
	for _, name := range []string{rwName, roName, oldName} {
		if _, err := s.Groups.Create(ctx, CreateGroupInput{Name: name}, "integration", ""); err != nil {
			t.Fatal(err)
		}
		name := name
		t.Cleanup(func() {
			if err := s.Groups.Delete(context.Background(), name, "integration", ""); err != nil {
				t.Error("cleanup group", err)
			}
		})
	}
	for _, entry := range []struct{ user, group string }{{rwUser, rwName}, {roUser, roName}} {
		user, err := s.Users.Create(ctx, CreateUserInput{Login: entry.user, Password: password, Enabled: true}, "integration", "")
		if err != nil {
			t.Fatal(err)
		}
		name := entry.user
		t.Cleanup(func() {
			if err := s.Users.Delete(context.Background(), name, "integration", ""); err != nil {
				t.Error("cleanup user", err)
			}
		})
		if err := s.Groups.AddMember(ctx, entry.group, user.DN, "integration", ""); err != nil {
			t.Fatal(err)
		}
	}
	resolve := func(name string) map[string]string {
		t.Helper()
		group, err := s.ResolveFileGroup(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		return group
	}
	rw, ro, old := resolve(rwName), resolve(roName), resolve(oldName)
	t.Logf("Real AD security groups resolved by file-server NSS: RW GID=%s, RO GID=%s, masked GID=%s", rw["gid"], ro["gid"], old["gid"])
	shareName := "it-permissions-" + suffix
	root := filepath.Join("/srv/samba", shareName)
	yes, no := true, false
	if _, err := s.Shares.Create(ctx, CreateShareInput{Name: shareName, Path: root, CreateDir: &yes, Reload: &yes, ReadOnly: &no, GuestOK: &no, Mode: "0700", CreateMask: "0666", DirectoryMask: "0777", InheritACLs: &no, ValidUsers: "@\"" + rw["name"] + "\", @\"" + ro["name"] + "\""}, "integration", ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Shares.Delete(context.Background(), shareName, true, "integration", ""); err != nil {
			t.Error("cleanup share", err)
		}
	})
	// SYSVOL in the lab intentionally uses a separate NT ACL xattr store. This
	// disposable share explicitly exercises Samba's POSIX ACL backend instead.
	for _, param := range [][2]string{{"vfs objects", "dfs_samba4"}, {"acl_xattr:ignore system acls", "no"}} {
		if err := s.Shares.SetParam(ctx, shareName, param[0], param[1], "integration", ""); err != nil {
			t.Fatal(err)
		}
	}
	dirs := []string{".", "Team", "Team/Reports", "Team/Archive", "Other"}
	for _, rel := range dirs {
		if rel != "." {
			if err := os.MkdirAll(filepath.Join(root, rel), 0700); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.FSACL.SetSharePath(ctx, shareName, rel, SetACLInput{ACL: "u::rwx,g::---,g:" + old["gid"] + ":rwx,m::r-x,o::---"}, "integration", ""); err != nil {
			t.Fatal(err)
		}
	}
	existing := filepath.Join(root, "Team", "existing-before.txt")
	if err := os.WriteFile(existing, []byte("existing data must remain unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := s.FSACL.Get(ctx, existing)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.Shares.PermissionMap(ctx, shareName, ".")
	if err != nil || !snapshot.Complete || len(snapshot.Nodes) != len(dirs) {
		t.Fatalf("snapshot: %+v %v", snapshot, err)
	}
	template := func(label, permissions string) SharePermissionTemplate {
		return SharePermissionTemplate{Name: label, Inherit: true, Rules: []SharePermissionRule{{Group: rwName, GID: rw["gid"], Permissions: permissions}, {Group: roName, GID: ro["gid"], Permissions: "r-x"}}}
	}
	input := SharePermissionMapRequest{Root: ".", SnapshotRevision: snapshot.Revision, Overlays: []SharePermissionOverlay{
		{Path: ".", Recursive: true, Template: template("Traverse/read root", "r-x")},
		{Path: "Team", Recursive: true, Template: template("Team read/write", "rwx")},
		{Path: "Team/Archive", Recursive: true, Template: template("Archive read only", "r-x")},
	}}
	plan, err := s.Shares.PlanPermissionMap(ctx, shareName, input)
	if err != nil || len(plan.Changes) != len(dirs) {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	input.Confirm = true
	input.PlanRevision = plan.Revision
	// A changed directory inventory must be rejected before the first write.
	probe := filepath.Join(root, "changed-after-preview")
	if err = os.Mkdir(probe, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Shares.ApplyPermissionMap(ctx, shareName, input, "integration", "", ""); err == nil || !strings.Contains(err.Error(), ErrShareMapConflict.Error()) {
		t.Fatal("changed tree was accepted")
	}
	if err = os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	applied, err := s.Shares.ApplyPermissionMap(ctx, shareName, input, "integration", "", "")
	if err != nil || applied.Status != "complete" || len(applied.Items) != len(dirs) {
		t.Fatalf("apply: %+v %v", applied, err)
	}
	after, err := s.FSACL.Get(ctx, existing)
	if err != nil || after.ACLText != before.ACLText || after.Mode != before.Mode {
		t.Fatalf("existing file permissions changed: before=%+v after=%+v err=%v", before, after, err)
	}
	expect := func(path, gid, perms string, def bool) {
		t.Helper()
		acl, err := s.FSACL.Get(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		mask := 7
		for _, e := range acl.Entries {
			if e.Default == def && e.Kind == "mask" {
				mask = shareACLBits(e.Perms)
			}
		}
		for _, e := range acl.Entries {
			if e.Kind == "group" && e.Qualifier == gid && e.Default == def {
				if got := shareACLPerms(shareACLBits(e.Perms) & mask); got != perms {
					t.Fatalf("%s GID=%s default=%v: got %s want %s; %s %s", path, gid, def, got, perms, acl.ACLText, acl.DefaultACL)
				}
				return
			}
		}
		t.Fatalf("%s missing GID=%s default=%v: %s %s", path, gid, def, acl.ACLText, acl.DefaultACL)
	}
	for _, rel := range dirs {
		perm := "r-x"
		if rel == "Team" || rel == "Team/Reports" {
			perm = "rwx"
		}
		dir := filepath.Join(root, rel)
		expect(dir, rw["gid"], perm, false)
		expect(dir, ro["gid"], "r-x", false)
		expect(dir, old["gid"], "r-x", false)
		expect(dir, rw["gid"], perm, true)
		expect(dir, ro["gid"], "r-x", true)
		newDir := filepath.Join(dir, "new-linux-dir")
		if err := os.Mkdir(newDir, 0777); err != nil {
			t.Fatal(err)
		}
		expect(newDir, rw["gid"], perm, false)
		expect(newDir, rw["gid"], perm, true)
		newFile := filepath.Join(newDir, "new-linux-file.txt")
		if err := os.WriteFile(newFile, []byte("inherited through two levels"), 0666); err != nil {
			t.Fatal(err)
		}
		filePerm := "r--"
		if perm == "rwx" {
			filePerm = "rw-"
		}
		expect(newFile, rw["gid"], filePerm, false)
		expect(newFile, ro["gid"], "r--", false)
	}
	t.Log("PASS all 5 existing directories: root RO, Team subtree RW, Archive override RO, unrelated masked group remains r-x")
	t.Log("PASS default ACL inheritance in all branches: new directories and files, two levels; regular files have no effective execute bit; old file unchanged")
	connect := func(user string) *smb2.Share {
		t.Helper()
		d := smb2.Dialer{Negotiator: smb2.Negotiator{RequireMessageSigning: true}, Initiator: &smb2.NTLMInitiator{User: user, Domain: "SAMBAADM", Password: password}}
		session, err := d.Dial(ctx, "127.0.0.1:445")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { session.Logoff() })
		sh, err := session.WithContext(ctx).Mount(shareName)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sh.Umount() })
		return sh.WithContext(ctx)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		for _, command := range [][]string{{"testparm", "-s", "--section-name=" + shareName}, {"id", "SAMBAADM\\" + rwUser}, {"namei", "-l", filepath.Join(root, "Team")}, {"getfacl", "-p", "-n", root, filepath.Join(root, "Team")}} {
			output, err := exec.Command(command[0], command[1:]...).CombinedOutput()
			t.Logf("diagnostic %s: %s (%v)", command[0], output, err)
		}
	})
	unixProbe := filepath.Join(root, "Team", "unix-user-probe")
	if output, err := exec.CommandContext(ctx, "runuser", "-u", "SAMBAADM\\"+rwUser, "--", "mkdir", unixProbe).CombinedOutput(); err != nil {
		t.Fatalf("real Unix writer: %s %v", output, err)
	}
	if err := os.Remove(unixProbe); err != nil {
		t.Fatal(err)
	}
	writer, reader := connect(rwUser), connect(roUser)
	if err = writer.Mkdir("Team/smb-dir", 0777); err != nil {
		t.Fatal("SMB RW mkdir", err)
	}
	if err = writer.WriteFile("Team/smb-dir/shared.txt", []byte("SMB inheritance"), 0666); err != nil {
		t.Fatal("SMB RW create", err)
	}
	expect(filepath.Join(root, "Team/smb-dir"), rw["gid"], "rwx", true)
	expect(filepath.Join(root, "Team/smb-dir/shared.txt"), ro["gid"], "r--", false)
	if data, err := reader.ReadFile("Team/smb-dir/shared.txt"); err != nil || string(data) != "SMB inheritance" {
		t.Fatal("SMB RO read", string(data), err)
	}
	if err = reader.WriteFile("Team/reader-must-not-create.txt", []byte("forbidden"), 0666); err == nil {
		t.Fatal("SMB RO user created a file")
	}
	if err = reader.WriteFile("Team/smb-dir/shared.txt", []byte("forbidden"), 0666); err == nil {
		t.Fatal("SMB RO user changed a file")
	}
	for _, rel := range []string{"Team/Archive/forbidden.txt", "Other/forbidden.txt"} {
		if err = writer.WriteFile(rel, []byte("forbidden"), 0666); err == nil {
			t.Fatal("SMB writer escaped branch permissions", rel)
		}
	}
	if data, err := writer.ReadFile("Team/Archive/new-linux-dir/new-linux-file.txt"); err != nil || len(data) == 0 {
		t.Fatal("SMB Archive read", err)
	}
	t.Log("PASS real signed SMB sessions: RW creates folder/file; RO reads but cannot create/overwrite; writer cannot write Archive or Other")
	// Samba's inherit-acls switch is separate from POSIX default ACL
	// inheritance. Exercise the enabled mode too, without changing templates.
	if err = s.Shares.SetParam(ctx, shareName, "inherit acls", "yes", "integration", ""); err != nil {
		t.Fatal(err)
	}
	inheritingWriter := connect(rwUser)
	if err = inheritingWriter.WriteFile("Team/smb-inherit-acls-enabled.txt", []byte("Samba inheritance flag"), 0666); err != nil {
		t.Fatal(err)
	}
	inheritedACL, err := s.FSACL.Get(ctx, filepath.Join(root, "Team/smb-inherit-acls-enabled.txt"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("OBSERVED inherit acls=yes SMB file mode=%s ACL=%s", inheritedACL.Mode, strings.ReplaceAll(inheritedACL.ACLText, "\n", "; "))
	expect(filepath.Join(root, "Team/smb-inherit-acls-enabled.txt"), ro["gid"], "r-x", false)
	expect(filepath.Join(root, "Team/smb-inherit-acls-enabled.txt"), rw["gid"], "rwx", false)
	t.Log("PASS both Samba modes: inherit acls=no gives non-executable SMB files through create mask; inherit acls=yes also inherits directory execute permissions onto SMB files")

	data, err := os.ReadFile(applied.Journal)
	if err != nil {
		t.Fatal(err)
	}
	var journal sharePermissionJournal
	if err = json.Unmarshal(data, &journal); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(applied.Journal)
	if err != nil || info.Mode().Perm() != 0600 || journal.Result.Status != "complete" || len(journal.Plan.Changes) != len(dirs) {
		t.Fatal("invalid permission journal", err)
	}
	if !strings.Contains(journal.Plan.Changes[0].Before.Access, "group:"+old["gid"]+":rwx") {
		t.Fatal("journal lost masked original rights")
	}
	t.Log("PASS private journal contains original ACLs, plan and successful per-directory results")
}
