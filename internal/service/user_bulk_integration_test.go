package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestIntegrationBulkUsers(t *testing.T) {
	svcs, _ := integrationServices(t, true)
	ctx := context.Background()
	s := NewEmployeeService(svcs.Users.ldap, svcs.Audit, filepath.Join(t.TempDir(), "bulk"), "Administrator@sambaadm.test", func(string) error { return nil })
	actor := EmployeeActor{Name: "test"}
	for _, name := range []string{"bulk-one", "bulk-two"} {
		_, e := svcs.Users.Create(ctx, CreateUserInput{Login: name, Password: "Fixture-Password-Long-Enough42!", Enabled: true}, "test", "")
		if e != nil {
			t.Fatal(e)
		}
		defer svcs.Users.Delete(ctx, name, "test", "")
	}
	p, e := s.BulkPreview(ctx, "disable", []string{"bulk-one", "bulk-two", "missing-bulk"}, actor)
	if e != nil {
		t.Fatal(e)
	}
	if p.Items[2].State != "blocked" {
		t.Fatal(p)
	}
	if _, e = s.BulkApply(ctx, p.ID, "wrong", actor); !errors.Is(e, ErrEmployeeConflict) {
		t.Fatal(e)
	}
	p, e = s.BulkApply(ctx, p.ID, p.Revision, actor)
	if e != nil {
		t.Fatal(e)
	}
	if p.State != "partial" || p.Items[0].State != "done" || p.Items[1].State != "done" {
		t.Fatal(p)
	}
	for _, name := range []string{"bulk-one", "bulk-two"} {
		u, e := svcs.Users.Show(ctx, name)
		if e != nil || u.Enabled {
			t.Fatal(name, e)
		}
	}
	p, e = s.BulkPreview(ctx, "enable", []string{"bulk-one", "bulk-two"}, actor)
	if e != nil {
		t.Fatal(e)
	}
	p, e = s.BulkApply(ctx, p.ID, p.Revision, actor)
	if e != nil || p.State != "completed" {
		t.Fatal(p, e)
	}
	p, e = s.BulkPreview(ctx, "unlock", []string{"bulk-one", "bulk-two"}, actor)
	if e != nil {
		t.Fatal(e)
	}
	p, e = s.BulkApply(ctx, p.ID, p.Revision, actor)
	if e != nil || p.State != "completed" {
		t.Fatal(p, e)
	}

}
