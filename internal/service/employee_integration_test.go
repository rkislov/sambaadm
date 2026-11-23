package service

import (
	"context"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"os"
	"strings"
	"testing"
	"time"
)

func TestIntegrationEmployeeLifecycle(t *testing.T) {
	svcs, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	actor := EmployeeActor{Name: "test"}
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	revoked := ""
	newSvc := func() *EmployeeService {
		return NewEmployeeService(svcs.Users.ldap, svcs.Audit, root, "Administrator@sambaadm.test", func(id string) error { revoked = id; return nil })
	}
	s := newSvc()
	g1, e := svcs.Groups.Create(ctx, CreateGroupInput{Name: "employee-old"}, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	defer svcs.Groups.Delete(context.Background(), g1.SAMAccountName, "test", "")
	g2, e := svcs.Groups.Create(ctx, CreateGroupInput{Name: "employee-new"}, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	defer svcs.Groups.Delete(context.Background(), g2.SAMAccountName, "test", "")
	ref := func(dn string) EmployeeRef {
		subject, e := svcs.Domain.subjectByDN(ctx, dn)
		if e != nil {
			t.Fatal(e)
		}
		return EmployeeRef{ID: subject.ID, DN: subject.DN, Name: subject.Name}
	}
	a, b := ref(g1.DN), ref(g2.DN)
	// Group PSO must already apply when the password is set.
	pso, e := svcs.Domain.CreatePSO(ctx, PSOChange{Name: "employee-policy", PSOValues: PSOValues{Precedence: 1, PasswordPolicyValues: PasswordPolicyValues{MinLength: 24, Complexity: true, MaxAgeDays: 42}}, Subjects: []PSOSubject{{ID: a.ID, DN: a.DN, Name: a.Name, Kind: "group"}}}, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		p, e := svcs.Domain.GetPSO(context.Background(), pso.ID)
		if e == nil {
			_ = svcs.Domain.DeletePSO(context.Background(), p.ID, p.Revision, "test", "")
		}
	}()
	dept := "Первый отдел"
	plan, e := s.Preview(ctx, EmployeeInput{Scenario: "join", Login: "employee-fixture", DisplayName: "Тестовый сотрудник", Department: &dept, AddGroups: []EmployeeRef{a}, Activate: true, ForceChange: true}, actor)
	if e != nil {
		t.Fatal(e)
	}
	defer svcs.Users.Delete(context.Background(), "employee-fixture", "test", "")
	apply := func(p *EmployeePlan, pass string) *EmployeePlan {
		t.Helper()
		p, e := s.Apply(ctx, p.ID, p.Revision, pass, actor)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	plan = apply(plan, "Short-Pass42!")
	if plan.State != "partial" || plan.Person == nil || plan.Person.Enabled {
		t.Fatalf("PSO failure must leave disabled account: %+v", plan)
	}
	if !strings.Contains(plan.Error, "0000052D") && !strings.Contains(strings.ToLower(plan.Error), "password") {
		t.Fatalf("not a password error: %s", plan.Error)
	}
	guid := plan.Person.ID
	// Restart, reconcile, set password once; fail before enable and resume without resetting it.
	s = newSvc()
	plan, e = s.Review(ctx, plan.ID, plan.Revision, actor)
	if e != nil {
		t.Fatal(e)
	}
	s.beforeStep = func(kind string) error {
		if kind == "enable" {
			return errors.New("injected enable failure")
		}
		return nil
	}
	plan = apply(plan, "Fixture-Password-Long-Enough42!")
	if plan.State != "partial" || plan.Person.Enabled {
		t.Fatalf("expected disabled partial result: %+v", plan)
	}
	s = newSvc()
	plan, e = s.Review(ctx, plan.ID, plan.Revision, actor)
	if e != nil {
		t.Fatal(e)
	}
	if plan.NeedsPassword {
		t.Fatal("confirmed password must not reset on resume")
	}
	plan = apply(plan, "")
	if plan.State != "completed" || !plan.Person.Enabled {
		t.Fatalf("join not completed: %+v", plan)
	}
	snap, e := s.capture(ctx, "", guid)
	if e != nil {
		t.Fatal(e)
	}
	if snap.Values["pwdLastSet"] != "0" {
		t.Fatal("force password change lost")
	}
	// Move to another actual OU while preserving GUID and membership semantics.
	ou, e := svcs.OU.Create(ctx, CreateOUInput{Name: "employee-destination"}, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	defer svcs.OU.Delete(context.Background(), ou.DN, "test", "")
	parent, e := s.Parent(ctx, ou.DN)
	if e != nil {
		t.Fatal(e)
	}
	dept = "Второй отдел"
	plan, e = s.Preview(ctx, EmployeeInput{Scenario: "transfer", Login: "employee-fixture", UserID: guid, Parent: &parent, Department: &dept, RemoveGroups: []EmployeeRef{a}, AddGroups: []EmployeeRef{b}}, actor)
	if e != nil {
		t.Fatal(e)
	}
	plan = apply(plan, "")
	if plan.State != "completed" || plan.Person.ID != guid || !plan.Person.Enabled || !strings.Contains(plan.Person.DN, ou.DN) {
		t.Fatalf("transfer failed: %+v", plan)
	}
	// Stale revision / directory snapshot fail closed.
	stale, e := s.Preview(ctx, EmployeeInput{Scenario: "offboard", Login: "employee-fixture", UserID: guid, RemoveGroups: []EmployeeRef{b}}, actor)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Apply(ctx, stale.ID, "bad", "", actor); !errors.Is(e, ErrEmployeeConflict) {
		t.Fatal("stale accepted", e)
	}
	if _, e = s.Preview(ctx, EmployeeInput{Scenario: "offboard", Login: "employee-fixture", UserID: guid}, EmployeeActor{ID: guid}); !errors.Is(e, ErrEmployeeInput) {
		t.Fatal("self offboarding accepted", e)
	}
	plan = apply(stale, "")
	if plan.State != "completed" || plan.Person.Enabled || revoked != guid {
		t.Fatalf("offboard failed: %+v", plan)
	}
	if len(plan.Person.Groups) != 1 || !plan.Person.Groups[0].Primary {
		t.Fatalf("wrong remaining groups: %+v", plan.Person.Groups)
	}
}

func TestIntegrationEmployeeInterruptedCreation(t *testing.T) {
	svcs, _ := integrationServices(t, true)
	ctx := context.Background()
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	newSvc := func() *EmployeeService {
		return NewEmployeeService(svcs.Users.ldap, svcs.Audit, root, "Administrator@sambaadm.test", func(string) error { return nil })
	}
	s := newSvc()
	actor := EmployeeActor{Name: "test"}
	plan, e := s.Preview(ctx, EmployeeInput{Scenario: "join", Login: "employee-unknown", DisplayName: "Прерванный приём", Activate: true}, actor)
	if e != nil {
		t.Fatal(e)
	}
	competing, e := s.Preview(ctx, EmployeeInput{Scenario: "join", Login: "employee-unknown", DisplayName: "Другой приём", Activate: true}, actor)
	if e != nil {
		t.Fatal(e)
	}
	r, e := s.load(plan.ID)
	if e != nil {
		t.Fatal(e)
	}
	r.Plan.State = "running"
	r.Plan.Steps[0].State = "running"
	if e = s.save(r); e != nil {
		t.Fatal(e)
	}
	if e = s.executeEmployeeStep(ctx, r, nil, r.Plan.Steps[0], ""); e != nil {
		t.Fatal(e)
	}
	defer svcs.Users.Delete(ctx, "employee-unknown", "test", "")
	s = newSvc()
	plan, e = s.Get(plan.ID)
	if e != nil || plan.State != "interrupted" {
		t.Fatal("interrupted create missing", e)
	}
	plan, e = s.Review(ctx, plan.ID, plan.Revision, actor)
	if e != nil {
		t.Fatal(e)
	}
	if plan.Person == nil || plan.Person.Enabled {
		t.Fatal("created identity not recovered")
	}
	guid := plan.Person.ID
	if _, e = s.Apply(ctx, competing.ID, competing.Revision, "Fixture-Password-Long-Enough42!", actor); !errors.Is(e, ErrEmployeeConflict) {
		t.Fatal("adopted another plan's identity", e)
	}
	plan, e = s.Apply(ctx, plan.ID, plan.Revision, "Fixture-Password-Long-Enough42!", actor)
	if e != nil || plan.State != "completed" || plan.Person.ID != guid {
		t.Fatalf("recovery: %v %+v", e, plan)
	}
	// Changing the directory after preview invalidates the snapshot.
	stale, e := s.Preview(ctx, EmployeeInput{Scenario: "offboard", Login: "employee-unknown"}, actor)
	if e != nil {
		t.Fatal(e)
	}
	snap, e := s.capture(ctx, "", guid)
	if e != nil {
		t.Fatal(e)
	}
	req := ldap.NewModifyRequest(snap.Person.DN, nil)
	req.Replace("title", []string{"Внешнее изменение"})
	if e = s.ldap.Modify(ctx, req); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Apply(ctx, stale.ID, stale.Revision, "", actor); !errors.Is(e, ErrEmployeeConflict) {
		t.Fatal("changed directory accepted", e)
	}
}
