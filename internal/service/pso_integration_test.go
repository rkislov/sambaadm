package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIntegrationPSOAndEffectivePolicy(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	user, err := s.Users.Create(ctx, CreateUserInput{Login: "pso-fixture-user", Password: "FixturePassword42!", Enabled: false}, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Users.Delete(context.Background(), user.SAMAccountName, "test", "")
	inner, err := s.Groups.Create(ctx, CreateGroupInput{Name: "pso-fixture-inner"}, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Groups.Delete(context.Background(), inner.SAMAccountName, "test", "")
	outer, err := s.Groups.Create(ctx, CreateGroupInput{Name: "pso-fixture-outer"}, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Groups.Delete(context.Background(), outer.SAMAccountName, "test", "")
	if err = s.Groups.AddMember(ctx, inner.SAMAccountName, user.DN, "test", ""); err != nil {
		t.Fatal(err)
	}
	if err = s.Groups.AddMember(ctx, outer.SAMAccountName, inner.DN, "test", ""); err != nil {
		t.Fatal(err)
	}
	subUser, err := s.Domain.subjectByDN(ctx, user.DN)
	if err != nil {
		t.Fatal(err)
	}
	subGroup, err := s.Domain.subjectByDN(ctx, outer.DN)
	if err != nil {
		t.Fatal(err)
	}
	effective := func() *EffectivePasswordPolicy {
		t.Helper()
		p, e := s.Domain.EffectivePasswordPolicy(ctx, user.SAMAccountName, "fixture DC")
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	if p := effective(); p.Source != "domain" || p.Domain == nil {
		t.Fatal("new user should start with domain policy")
	}
	makePSO := func(name string, priority int, subjects ...PSOSubject) *PSO {
		t.Helper()
		p, e := s.Domain.CreatePSO(ctx, PSOChange{Name: name, PSOValues: PSOValues{Precedence: priority, PasswordPolicyValues: PasswordPolicyValues{MinLength: 20, HistoryLength: 24, Complexity: true, MaxAgeDays: 42, LockoutThreshold: 5, LockoutDurationMinutes: 30, LockoutWindowMinutes: 30}}, Subjects: subjects}, "test", "")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			current, e := s.Domain.GetPSO(context.Background(), p.ID)
			if e == nil {
				e = s.Domain.DeletePSO(context.Background(), p.ID, current.Revision, "test", "")
			}
			if e != nil && !errors.Is(e, ErrPSONotFound) {
				t.Error(e)
			}
		})
		return p
	}
	group := makePSO("fixture-pso-group", 1, subGroup)
	if p := effective(); p.Policy == nil || p.Policy.ID != group.ID {
		t.Fatalf("nested group PSO not selected by DC: %+v", p)
	}
	direct := makePSO("fixture-pso-direct", 50, subUser)
	if p := effective(); p.Policy == nil || p.Policy.ID != direct.ID {
		t.Fatal("direct assignment must beat group PSO regardless of precedence")
	}
	tied := makePSO("fixture-pso-tied", 50, subUser)
	chosen := effective()
	if chosen.Policy == nil || (chosen.Policy.ID != direct.ID && chosen.Policy.ID != tied.ID) {
		t.Fatal("tie selected outside direct assignments")
	}
	if effective().Policy.ID != chosen.Policy.ID {
		t.Fatal("DC tie selection unstable")
	}
	change := PSOChange{Name: direct.Name, Revision: direct.Revision, PSOValues: direct.PSOValues, Subjects: direct.Subjects}
	change.Precedence = 2
	change.MinLength = 24
	change.MaxAgeDays = 0
	updated, err := s.Domain.UpdatePSO(ctx, direct.ID, change, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if updated.MaxAgeDays != 0 || effective().Policy.ID != direct.ID {
		t.Fatal("precedence or no-expiry change not effective")
	}
	if _, err = s.Domain.UpdatePSO(ctx, direct.ID, change, "test", ""); !errors.Is(err, ErrPSOConflict) {
		t.Fatal("stale revision accepted", err)
	}
	// A compliant domain-level password must still be rejected by the effective PSO.
	if err = s.Users.SetPassword(ctx, user.SAMAccountName, "ShortButStrong42!", "test", ""); err == nil {
		t.Fatal("effective PSO minimum length was not enforced")
	}
	if err = s.Users.SetPassword(ctx, user.SAMAccountName, "FixturePasswordLongEnoughForPSO42!", "test", ""); err != nil {
		t.Fatal("compliant password refused", err)
	}
	change.Revision = updated.Revision
	change.Subjects = []PSOSubject{}
	updated, err = s.Domain.UpdatePSO(ctx, direct.ID, change, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if effective().Policy.ID != tied.ID {
		t.Fatal("removing direct assignment did not reveal other direct PSO")
	}
	if err = s.Domain.DeletePSO(ctx, tied.ID, tied.Revision, "test", ""); err != nil {
		t.Fatal(err)
	}
	if effective().Policy.ID != group.ID {
		t.Fatal("deleting direct PSO did not fall back to group PSO")
	}
	groupChange := PSOChange{Name: group.Name, Revision: group.Revision, PSOValues: group.PSOValues, Subjects: []PSOSubject{}}
	if _, err = s.Domain.UpdatePSO(ctx, group.ID, groupChange, "test", ""); err != nil {
		t.Fatal(err)
	}
	if effective().Source != "domain" {
		t.Fatal("removing all applicable assignments did not fall back to domain policy")
	}
	if _, err = s.Domain.CreatePSO(ctx, PSOChange{Name: "invalid-target", PSOValues: group.PSOValues, Subjects: []PSOSubject{{ID: subUser.ID, DN: "CN=Other,DC=foreign,DC=test"}}}, "test", ""); !errors.Is(err, ErrPSOInput) {
		t.Fatal("foreign target accepted", err)
	}
	t.Log("PSO create/read/update/delete, nested global group, direct assignment precedence, DC tie selection, password enforcement, no expiry, conflict and domain fallback: PASS")
}
