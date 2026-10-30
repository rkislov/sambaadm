package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"
)

func TestIntegrationRepairAcrossTwoDCs(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_SECOND_DC") == "" {
		t.Skip("requires two DCs")
	}
	s, cfg := integrationServices(t, true)
	s.GPO.gpoCfg.DelegationStateDir = filepath.Join(t.TempDir(), "state")
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	name := fmt.Sprintf("IT-Repair-%d", time.Now().UnixNano())
	if _, e := s.GPO.Create(ctx, name, "test", ""); e != nil {
		t.Fatal(e)
	}
	all, e := s.GPO.List(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var id string
	for _, p := range all {
		if p.DisplayName == name {
			id = p.GUID
		}
	}
	if id == "" {
		t.Fatal("GPO missing")
	}
	t.Cleanup(func() { s.GPO.Delete(context.Background(), id, "test", "") })
	dc2, e := s.Sites.controller(ctx, os.Getenv("SAMBAADM_IT_SECOND_DC"))
	if e != nil {
		t.Fatal(e)
	}
	dc1, e := s.Sites.controller(ctx, "DC1")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Repl.Sync(ctx, dc2.DNS, dc1.DNS, cfg.BaseDN, "test", ""); e != nil {
		t.Fatal(e)
	}

	e = s.GPO.withRepairDC(ctx, id, dc1.DNS, func(_ *GPOService, _ *ldap.Entry, v repairVolume, base string) error {
		tree := v.Tree(path.Base(base))
		if e := tree.Mkdir("Machine/Scripts", 0700); e != nil {
			return e
		}
		return createDurablePolicyFile(tree, "Machine/Scripts/check.sh", []byte("#!/bin/sh\necho test\n"))
	})
	if e != nil {
		t.Fatal(e)
	}
	in := RepairInput{Operation: "repair", Source: dc1.DNS, Target: dc2.DNS}
	apply := func(in RepairInput) *RepairResult {
		t.Helper()
		p, e := s.GPO.RepairPreview(ctx, id, in)
		if e != nil {
			t.Fatal(e)
		}
		in.Preview = p.Preview
		result, e := s.GPO.RepairApply(ctx, id, in, "test", "")
		if e != nil {
			t.Fatal(e)
		}
		return result
	}
	result := apply(in)
	if result.State != "complete" || result.Report == nil || result.Report.Status != "consistent" {
		t.Fatalf("missing target repair: %+v", result)
	}
	result = apply(RepairInput{Operation: "rollback", Record: result.Record})
	if result.State != "rolled-back" || result.Report == nil || result.Report.Status != "incomplete" {
		t.Fatalf("rollback absent target: %+v", result)
	}
	result = apply(in)
	// Change a target file without changing LDAP version, then repair and roll back.
	e = s.GPO.withRepairDC(ctx, id, dc2.DNS, func(_ *GPOService, _ *ldap.Entry, v repairVolume, base string) error {
		tree := v.Tree(path.Base(base))
		sec := tree.(policySecurityStore)
		acl, e := sec.GetACL("GPT.INI")
		if e != nil {
			return e
		}
		ace, e := delegationFileACE([]byte{1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0}, "read", false)
		if e != nil {
			return e
		}
		desired, _, e := delegationDescriptor(acl, [][]byte{ace})
		if e != nil {
			return e
		}
		if e = sec.SetACL("GPT.INI", desired); e != nil {
			return e
		}
		if e = createDurablePolicyFile(tree, "obsolete.txt", []byte("backup this")); e != nil {
			return e
		}
		return writePolicyFile(tree, "GPT.INI", []byte("[General]\nVersion=0\n; target change\n"))
	})
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.GPO.RepairPreview(ctx, id, in)
	if e != nil {
		t.Fatal(e)
	}
	e = s.GPO.withRepairDC(ctx, id, dc2.DNS, func(_ *GPOService, _ *ldap.Entry, v repairVolume, base string) error {
		return writePolicyFile(v.Tree(path.Base(base)), "GPT.INI", []byte("[General]\nVersion=0\n; concurrent change\n"))
	})
	if e != nil {
		t.Fatal(e)
	}
	if len(p.ACLChanges) == 0 {
		t.Fatal("ACL difference missing from preview")
	}
	stale := in
	stale.Preview = p.Preview
	if _, e = s.GPO.RepairApply(ctx, id, stale, "test", ""); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("stale preview: %v", e)
	}
	result = apply(in)
	if result.Report == nil || result.Report.Status != "consistent" {
		t.Fatalf("existing repair: %+v", result)
	}
	result = apply(RepairInput{Operation: "rollback", Record: result.Record})
	if result.State != "rolled-back" || result.Report == nil || result.Report.Status != "different" {
		t.Fatalf("existing rollback: %+v", result)
	}
	e = s.GPO.withRepairDC(ctx, id, dc2.DNS, func(_ *GPOService, _ *ldap.Entry, v repairVolume, base string) error {
		return writePolicyFile(v.Tree(path.Base(base)), "GPT.INI", []byte("corrupt target GPT"))
	})
	if e != nil {
		t.Fatal(e)
	}
	result = apply(in)
	if result.Report == nil || result.Report.Status != "consistent" {
		t.Fatalf("malformed target repair: %+v", result)
	}
	result = apply(RepairInput{Operation: "rollback", Record: result.Record})
	if result.State != "rolled-back" || result.Report == nil || result.Report.Status != "incomplete" {
		t.Fatalf("malformed target restored: %+v", result)
	}

}
