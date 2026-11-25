package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"os"
	"path"
	"path/filepath"
	"sambaadm/internal/agent"
	"testing"
	"time"
)

func TestIntegrationSYSVOLSyncKerberosWithoutSourceHelper(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_SECOND_DC") == "" || os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("needs disposable two-DC helper fixture")
	}
	services, cfg := integrationServices(t, true)
	s := services.GPO
	s.gpoCfg.DelegationStateDir = filepath.Join(t.TempDir(), "sync")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	dc1, e := services.Sites.controller(ctx, "DC1")
	if e != nil {
		t.Fatal(e)
	}
	dc2, e := services.Sites.controller(ctx, os.Getenv("SAMBAADM_IT_SECOND_DC"))
	if e != nil {
		t.Fatal(e)
	}
	name := fmt.Sprintf("IT-SYSVOL-Sync-%d", time.Now().UnixNano())
	if _, e = s.Create(ctx, name, "test", ""); e != nil {
		t.Fatal(e)
	}
	list, e := s.List(ctx)
	if e != nil {
		t.Fatal(e)
	}
	id := ""
	for _, p := range list {
		if p.DisplayName == name {
			id = p.GUID
		}
	}
	if id == "" {
		t.Fatal("missing GPO")
	}
	if e = s.helpers.Call(ctx, dc2.DNS, "sysvol.mkdir-all", helperFSRequest{Path: `sambaadm.test\Policies`, Mode: 0755}, nil); e != nil {
		t.Fatal(e)
	}
	originalHelpers := s.helpers
	t.Cleanup(func() { s.helpers = originalHelpers; s.Delete(context.Background(), id, "test", "") })
	edit := func(host, text string) error {
		return s.withRepairDC(ctx, id, host, func(_ *GPOService, _ *ldap.Entry, v repairVolume, base string) error {
			tree := v.Tree(path.Base(base))
			if _, err := tree.Lstat("sync-test.txt"); os.IsNotExist(err) {
				return createDurablePolicyFile(tree, "sync-test.txt", []byte(text))
			}
			return writePolicyFile(tree, "sync-test.txt", []byte(text))
		})
	}
	if e = edit(dc1.DNS, "source v1"); e != nil {
		t.Fatal(e)
	}
	if e = services.Repl.Sync(ctx, dc2.DNS, dc1.DNS, cfg.BaseDN, "test", ""); e != nil {
		t.Fatal(e)
	}
	// Only the recipient retains a helper. A source helper regression must fail.
	copyClient := &agent.Client{Config: s.helpers.Config}
	copyClient.Config.Nodes = nil
	for _, node := range s.helpers.Config.Nodes {
		if node.Name == dc2.DNS {
			copyClient.Config.Nodes = append(copyClient.Config.Nodes, node)
		}
	}
	s.helpers = copyClient
	wait := func(j *SYSVOLSyncJob) *SYSVOLSyncJob {
		t.Helper()
		for n := 0; n < 500; n++ {
			v, e := s.SYSVOLSyncRead(j.ID)
			if e != nil {
				t.Fatal(e)
			}
			if v.State != "planning" && v.State != "running" {
				return v
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("sync timeout")
		return nil
	}
	plan := func() *SYSVOLSyncJob {
		t.Helper()
		j, e := s.SYSVOLSyncPlan(ctx, SYSVOLSyncInput{Source: dc1.DNS, Targets: []string{dc2.DNS}, Policies: []string{id}}, "test", "")
		if e != nil {
			t.Fatal(e)
		}
		return wait(j)
	}
	j := plan()
	if j.Items[0].State != "ready" {
		t.Fatalf("Kerberos source preview: %+v", j.Items)
	}
	if _, e = s.SYSVOLSyncApply(context.Background(), j.ID, j.Revision, "test", "", false); !errors.Is(e, ErrTopologyConflict) {
		t.Fatal("missing confirmation accepted", e)
	}
	applied, e := s.SYSVOLSyncApply(context.Background(), j.ID, j.Revision, "test", "", true)
	if e != nil {
		t.Fatal(e)
	}
	applied = wait(applied)
	if applied.State != "completed" || applied.Items[0].State != "applied" {
		t.Fatalf("apply: %+v", applied.Items)
	}
	if _, e = s.SYSVOLSyncApply(context.Background(), j.ID, j.Revision, "test", "", true); !errors.Is(e, ErrTopologyConflict) {
		t.Fatal("replay accepted", e)
	}
	identical := plan()
	if identical.Items[0].State != "identical" {
		t.Fatalf("not idempotent: %+v", identical.Items)
	}
	// Prepare another source revision, then change the recipient after preview.
	s.helpers = originalHelpers
	if e = edit(dc1.DNS, "source v2"); e != nil {
		t.Fatal(e)
	}
	s.helpers = copyClient
	newer := plan()
	if newer.Items[0].State != "ready" {
		t.Fatalf("new source: %+v", newer.Items)
	}
	s.helpers = originalHelpers
	if e = edit(dc1.DNS, "source v3 after preview"); e != nil {
		t.Fatal(e)
	}
	s.helpers = copyClient
	changed, e := s.SYSVOLSyncApply(context.Background(), newer.ID, newer.Revision, "test", "", true)
	if e != nil {
		t.Fatal(e)
	}
	changed = wait(changed)
	if changed.Items[0].State != "conflict" {
		t.Fatalf("source change not detected: %+v", changed.Items)
	}
	newer = plan()
	if newer.Items[0].State != "ready" {
		t.Fatalf("new source preview: %+v", newer.Items)
	}
	if e = edit(dc2.DNS, "concurrent local edit"); e != nil {
		t.Fatal(e)
	}
	done, e := s.SYSVOLSyncApply(context.Background(), newer.ID, newer.Revision, "test", "", true)
	if e != nil {
		t.Fatal(e)
	}
	done = wait(done)
	if done.State != "partial" || done.Items[0].State != "conflict" {
		t.Fatalf("concurrent change not blocked: %+v", done.Items)
	}
	blocked := plan()
	if blocked.Items[0].State != "conflict" {
		t.Fatalf("local change lost on fresh preview: %+v", blocked.Items)
	}
	e = s.withRepairDC(ctx, id, dc2.DNS, func(_ *GPOService, _ *ldap.Entry, v repairVolume, base string) error {
		raw, e := readPolicyFile(v.Tree(path.Base(base)), "sync-test.txt")
		if e != nil {
			return e
		}
		if string(raw) != "concurrent local edit" {
			return fmt.Errorf("local edits overwritten")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	// Another policy remains deliverable when one policy is blocked.
	s.helpers = originalHelpers
	secondName := name + "-unblocked"
	if _, e = s.Create(ctx, secondName, "test", ""); e != nil {
		t.Fatal(e)
	}
	all, e := s.List(ctx)
	if e != nil {
		t.Fatal(e)
	}
	second := ""
	for _, p := range all {
		if p.DisplayName == secondName {
			second = p.GUID
		}
	}
	if second == "" {
		t.Fatal("missing second policy")
	}
	t.Cleanup(func() { s.helpers = originalHelpers; s.Delete(context.Background(), second, "test", "") })
	if e = services.Repl.Sync(ctx, dc2.DNS, dc1.DNS, cfg.BaseDN, "test", ""); e != nil {
		t.Fatal(e)
	}
	s.helpers = copyClient
	mixed, e := s.SYSVOLSyncPlan(ctx, SYSVOLSyncInput{Source: dc1.DNS, Targets: []string{dc2.DNS}, Policies: []string{id, second}}, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	mixed = wait(mixed)
	if mixed.Items[0].State != "conflict" || mixed.Items[1].State != "ready" {
		t.Fatalf("mixed preview: %+v", mixed.Items)
	}
	mixed, e = s.SYSVOLSyncApply(context.Background(), mixed.ID, mixed.Revision, "test", "", true)
	if e != nil {
		t.Fatal(e)
	}
	mixed = wait(mixed)
	if mixed.State != "partial" || mixed.Items[0].State != "conflict" || mixed.Items[1].State != "applied" {
		t.Fatalf("partial delivery: %+v", mixed.Items)
	}

}
