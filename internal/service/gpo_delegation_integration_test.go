package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestIntegrationGPOLdapDelegation(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name := fmt.Sprintf("IT-Delegate-%d", time.Now().UnixNano())
	if _, err := s.GPO.Create(ctx, name, "integration", ""); err != nil {
		t.Fatal(err)
	}
	policies, err := s.GPO.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var gpo GPO
	for _, p := range policies {
		if p.DisplayName == name {
			gpo = p
		}
	}
	if gpo.GUID == "" {
		t.Fatal("missing GPO")
	}
	t.Cleanup(func() { s.GPO.Delete(context.Background(), gpo.GUID, "integration", "") })
	principal, err := s.Users.Create(ctx, CreateUserInput{Login: name}, "integration", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Users.Delete(context.Background(), name, "integration", "") })
	for _, profile := range []string{"read-apply", "edit-ldap"} {
		before, err := s.GPO.SecurityFilter(ctx, gpo.GUID)
		if err != nil {
			t.Fatal(err)
		}
		in := GPDelegationChange{Revision: before.Revision, Principal: principal.DN, Profile: profile}
		plan, err := s.GPO.DelegationPreview(ctx, gpo.GUID, in)
		if err != nil || len(plan.Added) == 0 {
			t.Fatalf("preview %+v %v", plan, err)
		}
		if err = s.GPO.GrantDelegation(ctx, gpo.GUID, in, "integration", ""); err == nil {
			t.Fatal("missing preview accepted")
		}
		in.Preview = "bad"
		if err = s.GPO.GrantDelegation(ctx, gpo.GUID, in, "integration", ""); !errors.Is(err, ErrTopologyConflict) {
			t.Fatal("bad preview", err)
		}
		unchanged, _ := s.GPO.SecurityFilter(ctx, gpo.GUID)
		if unchanged.Revision != before.Revision {
			t.Fatal("preview mutated LDAP")
		}
		in.Preview = plan.Preview
		if err = s.GPO.GrantDelegation(ctx, gpo.GUID, in, "integration", ""); err != nil {
			t.Fatal(err)
		}
		after, err := s.GPO.SecurityFilter(ctx, gpo.GUID)
		if err != nil {
			t.Fatal(err)
		}
		old := map[string]int{}
		for _, a := range before.Entries {
			old[a.ID]++
		}
		for _, a := range after.Entries {
			old[a.ID]--
		}
		for _, n := range old {
			if n > 0 {
				t.Fatal("existing ACE removed")
			}
		}
		if len(after.Entries) != len(before.Entries)+len(plan.Added) {
			t.Fatalf("unexpected ACE count %d", len(after.Entries))
		}
		if err = s.GPO.GrantDelegation(ctx, gpo.GUID, in, "integration", ""); !errors.Is(err, ErrTopologyConflict) {
			t.Fatal("stale revision", err)
		}
		in.Revision = after.Revision
		in.Preview = ""
		plan, err = s.GPO.DelegationPreview(ctx, gpo.GUID, in)
		if err != nil || len(plan.Added) != 0 {
			t.Fatalf("duplicate %+v %v", plan, err)
		}
	}
}
