package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const mapTestAccess = "user::rwx\ngroup::rwx\ngroup:1001:rwx\nmask::r-x\nother::---"

type fakeMapACL struct {
	Access  string
	Default string
}

// The fixture exercises the actual subprocess, descriptor pinning and journal
// paths. It emulates only getfacl/setfacl, never real AD or Linux ACL semantics.
func TestShareMapCommandProcess(t *testing.T) {
	if os.Getenv("SAMBAADM_MAP_FAKE") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	args = args[1:]
	method := args[0]
	args = args[1:]
	path := args[len(args)-1]
	info, err := os.Stat(path)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(2)
	}
	key := shareMapDigest(shareMapFileIdentity(info))
	file := filepath.Join(os.Getenv("SAMBAADM_MAP_STATE"), key+".json")
	acl := fakeMapACL{Access: mapTestAccess}
	if data, err := os.ReadFile(file); err == nil {
		json.Unmarshal(data, &acl)
	}
	if method == "getfacl" {
		fmt.Print(acl.Access + "\n" + acl.Default + "\n")
		os.Exit(0)
	}
	if method != "setfacl" {
		os.Exit(2)
	}
	if key == os.Getenv("SAMBAADM_MAP_FAIL_KEY") {
		fmt.Fprint(os.Stderr, "injected write failure")
		os.Exit(3)
	}
	defaultACL := false
	for _, arg := range args {
		if arg == "-d" {
			defaultACL = true
		}
	}
	for _, arg := range args {
		if arg == "-k" {
			acl.Default = ""
		}
		if strings.HasPrefix(arg, "--set=") {
			text := strings.ReplaceAll(strings.TrimPrefix(arg, "--set="), ",", "\n")
			if defaultACL {
				lines := strings.Split(text, "\n")
				for i := range lines {
					lines[i] = "default:" + lines[i]
				}
				acl.Default = strings.Join(lines, "\n")
			} else {
				acl.Access = text
			}
		}
	}
	data, _ := json.Marshal(acl)
	if err := os.WriteFile(file, data, 0600); err != nil {
		os.Exit(4)
	}
	os.Exit(0)
}
func mapCommandFixture(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	state := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	for _, method := range []string{"getfacl", "setfacl"} {
		script := "#!/bin/sh\nexec " + quote(exe) + " -test.run=^TestShareMapCommandProcess$ -- " + method + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(bin, method), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GORACE", os.Getenv("GORACE")+" atexit_sleep_ms=0")
	t.Setenv("SAMBAADM_MAP_FAKE", "1")
	t.Setenv("SAMBAADM_MAP_STATE", state)
}
func mapTestRequest(snapshot *SharePermissionSnapshot) SharePermissionMapRequest {
	return SharePermissionMapRequest{Root: snapshot.Root, SnapshotRevision: snapshot.Revision, Overlays: []SharePermissionOverlay{{Path: snapshot.Root, Recursive: true, Template: SharePermissionTemplate{Name: "Команда", Inherit: true, Rules: []SharePermissionRule{{Group: "Finance", GID: "2001", Permissions: "rwx"}}}}}}
}
func TestSharePermissionMapPreservesEffectiveRightsAndOverrides(t *testing.T) {
	access, defaults, err := canonicalShareACL(mapTestAccess, "")
	if err != nil {
		t.Fatal(err)
	}
	makeNode := func(path string) SharePermissionNode {
		n := SharePermissionNode{Path: path, Access: access, Default: defaults}
		n.Revision = shareMapNodeRevision(n)
		return n
	}
	snapshot := &SharePermissionSnapshot{Root: ".", Revision: "snapshot", Complete: true, Nodes: []SharePermissionNode{makeNode("."), makeNode("a"), makeNode("a/child"), makeNode("ab")}}
	input := mapTestRequest(snapshot)
	input.Overlays = append(input.Overlays, SharePermissionOverlay{Path: "a", Recursive: true, Template: SharePermissionTemplate{Name: "Чтение ветви", Rules: []SharePermissionRule{{Group: "Finance", GID: "2001", Permissions: "r-x"}}}})
	plan, err := planSharePermissionMap(snapshot, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 4 {
		t.Fatalf("%+v", plan)
	}
	for _, change := range plan.Changes {
		if !strings.Contains(change.Access, "group:1001:r-x") {
			t.Fatal("widened unrelated masked permissions", change.Access)
		}
		desired := "rwx"
		if change.Path == "a" || change.Path == "a/child" {
			desired = "r-x"
		}
		if !strings.Contains(change.Access, "group:2001:"+desired) {
			t.Fatal("wrong overlay precedence/boundary", change.Path, change.Access)
		}
		if !strings.Contains(change.Default, "default:group:2001:rwx") {
			t.Fatal("missing directory defaults")
		}
	}
	snapshot.Nodes[0].Owner = "different-display-name"
	snapshot.Nodes[0].Entries = []ACLEntry{{Identity: "NSS display"}}
	again, err := planSharePermissionMap(snapshot, input)
	if err != nil || again.Revision != plan.Revision {
		t.Fatal("display name affected plan revision")
	}
	snapshot.Complete = false
	if _, err = planSharePermissionMap(snapshot, input); err == nil {
		t.Fatal("partial snapshot accepted")
	}
	snapshot.Complete = true
	input.SnapshotRevision = "old"
	if _, err = planSharePermissionMap(snapshot, input); err != ErrShareMapConflict {
		t.Fatal(err)
	}
}
func TestSharePermissionMapApplyAndJournal(t *testing.T) {
	mapCommandFixture(t)
	s, _, docs := treeTestService(t)
	ctx := context.Background()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(docs, "link")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(docs, "existing.txt")
	if err := os.WriteFile(file, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := s.PermissionMap(ctx, "docs", ".")
	if err != nil || !snapshot.Complete || len(snapshot.Nodes) != 3 || snapshot.SkippedLinks != 1 {
		t.Fatalf("%+v %v", snapshot, err)
	}
	input := mapTestRequest(snapshot)
	plan, err := s.PlanPermissionMap(ctx, "docs", input)
	if err != nil {
		t.Fatal(err)
	}
	input.Confirm = true
	input.PlanRevision = plan.Revision
	state := t.TempDir()
	result, err := s.ApplyPermissionMap(ctx, "docs", input, "tester", "", state)
	if err != nil || result.Status != "complete" || len(result.Items) != 3 {
		t.Fatalf("%+v %v", result, err)
	}
	data, err := os.ReadFile(result.Journal)
	if err != nil {
		t.Fatal(err)
	}
	var journal sharePermissionJournal
	if err = json.Unmarshal(data, &journal); err != nil {
		t.Fatal(err)
	}
	if journal.Actor != "tester" || journal.Result.Status != "complete" || !strings.Contains(journal.Plan.Changes[0].Before.Access, "group:1001:rwx") {
		t.Fatal("original ACL missing from journal")
	}
	info, err := os.Stat(result.Journal)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("journal not private")
	}
	for _, node := range snapshot.Nodes {
		now, err := s.PermissionMap(ctx, "docs", node.Path)
		if err != nil || !strings.Contains(now.Nodes[0].Access, "group:2001:rwx") {
			t.Fatalf("missing nested ACL %s: %+v %v", node.Path, now, err)
		}
	}
	info, _ = os.Stat(file)
	if info.Mode().Perm() != 0600 {
		t.Fatal("changed an existing file")
	}
	if _, err = s.ApplyPermissionMap(ctx, "docs", input, "tester", "", state); err != ErrShareMapConflict {
		t.Fatal("stale replay accepted", err)
	}
}
func TestSharePermissionMapRejectsChangedTreeAndReportsPartial(t *testing.T) {
	mapCommandFixture(t)
	s, _, docs := treeTestService(t)
	ctx := context.Background()
	snapshot, err := s.PermissionMap(ctx, "docs", ".")
	if err != nil {
		t.Fatal(err)
	}
	input := mapTestRequest(snapshot)
	plan, err := s.PlanPermissionMap(ctx, "docs", input)
	if err != nil {
		t.Fatal(err)
	}
	input.Confirm = true
	input.PlanRevision = plan.Revision
	if err = os.Mkdir(filepath.Join(docs, "new"), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ApplyPermissionMap(ctx, "docs", input, "test", "", t.TempDir()); err != ErrShareMapConflict {
		t.Fatal("tree change accepted", err)
	}
	snapshot, err = s.PermissionMap(ctx, "docs", ".")
	if err != nil {
		t.Fatal(err)
	}
	input = mapTestRequest(snapshot)
	plan, err = s.PlanPermissionMap(ctx, "docs", input)
	if err != nil {
		t.Fatal(err)
	}
	input.Confirm = true
	input.PlanRevision = plan.Revision
	// The first item succeeds; the second stops the operation and all remaining
	// directories stay pending. The durable journal records exactly that state.
	info, err := os.Stat(filepath.Join(docs, filepath.FromSlash(plan.Changes[1].Path)))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAMBAADM_MAP_FAIL_KEY", shareMapDigest(shareMapFileIdentity(info)))
	result, err := s.ApplyPermissionMap(ctx, "docs", input, "test", "", t.TempDir())
	if err != nil || result.Status != "partial" || result.Items[0].Status != "applied" || result.Items[1].Status != "failed" || result.Items[2].Status != "pending" {
		t.Fatalf("partial report: %+v %v", result, err)
	}
}
func TestSharePermissionTemplateValidation(t *testing.T) {
	access, _, _ := canonicalShareACL(mapTestAccess, "")
	snapshot := &SharePermissionSnapshot{Root: ".", Revision: "r", Complete: true, Nodes: []SharePermissionNode{{Path: ".", Access: access}}}
	for _, gid := range []string{"-1", "bad", "1:rw", "4294967296"} {
		input := mapTestRequest(snapshot)
		input.Overlays[0].Template.Rules[0].GID = gid
		if _, err := planSharePermissionMap(snapshot, input); err == nil {
			t.Fatal("invalid GID", gid)
		}
	}
	for i := 0; i < 3; i++ {
		input := mapTestRequest(snapshot)
		switch i {
		case 0:
			input.Overlays[0].Path = "../outside"
		case 1:
			input.Overlays[0].Template.Rules[0].Permissions = "deny"
		case 2:
			input.Overlays[0].Template.Rules = append(input.Overlays[0].Template.Rules, input.Overlays[0].Template.Rules[0])
		}
		if _, err := planSharePermissionMap(snapshot, input); err == nil {
			t.Fatal("invalid template", strconv.Itoa(i))
		}
	}
}
