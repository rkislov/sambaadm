package service

import (
	"context"
	"errors"
	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
	"testing"
	"time"
)

func TestIntegrationUserLoginUnlock(t *testing.T) {
	s, cfg := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	login := "unlock-fixture"
	user, err := s.Users.Create(ctx, CreateUserInput{Login: login, Password: "FixturePassword42!", Enabled: true}, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Users.Delete(context.Background(), login, "test", "")
	// Only the disposable SAMBAADM.TEST domain is allowed by integrationServices.
	before, err := s.Domain.PasswordPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	req := ldap.NewModifyRequest(cfg.BaseDN, nil)
	req.Replace("lockoutThreshold", []string{"3"})
	req.Replace("lockoutDuration", []string{"-18000000000"})
	req.Replace("lockOutObservationWindow", []string{"-18000000000"})
	if err = s.Users.ldap.Modify(ctx, req); err != nil {
		t.Fatal(err)
	}
	defer func() {
		current, e := s.Domain.PasswordPolicy(context.Background())
		if e == nil {
			_, e = s.Domain.SetPasswordPolicy(context.Background(), PasswordPolicyChange{Revision: current.Revision, Policy: before.PasswordPolicyValues}, "test", "")
		}
		if e != nil {
			t.Error("restore disposable domain policy:", e)
		}
	}()
	for i := 0; i < 3; i++ {
		client := ldapproto.NewClient(cfg)
		if e := client.BindSimple(ctx, login+"@sambaadm.test", "wrong-fixture-password"); e == nil {
			t.Fatal("wrong password accepted")
		}
		client.Close()
	}
	status, err := s.Users.LoginStatus(ctx, login, "fixture DC")
	if err != nil {
		t.Fatal(err)
	}
	locked := false
	for _, c := range status.Checks {
		if c.Code == "lockout" && c.State == "issue" {
			locked = true
		}
	}
	if !locked || !status.CanUnlock {
		t.Fatalf("real lockout not detected: %+v", status)
	}
	if _, err = s.Users.Unlock(ctx, login, "stale", "fixture DC", "test", ""); !errors.Is(err, ErrLoginConflict) {
		t.Fatal("stale diagnostic accepted", err)
	}
	// An independently changed flag must survive lockout reset.
	if err = s.Users.Disable(ctx, login, "test", ""); err != nil {
		t.Fatal(err)
	}
	status, err = s.Users.LoginStatus(ctx, login, "fixture DC")
	if err != nil {
		t.Fatal(err)
	}
	after, err := s.Users.Unlock(ctx, login, status.Revision, "fixture DC", "test", "")
	if err != nil {
		t.Fatal(err)
	}
	if after.CanUnlock {
		t.Fatal("still locked")
	}
	profile, err := s.Users.Show(ctx, login)
	if err != nil || profile.Enabled || profile.DN != user.DN {
		t.Fatal("unlock changed disabled state or identity")
	}
	if err = s.Users.Enable(ctx, login, "test", ""); err != nil {
		t.Fatal(err)
	}
	client := ldapproto.NewClient(cfg)
	defer client.Close()
	if err = client.BindSimple(ctx, login+"@sambaadm.test", "FixturePassword42!"); err != nil {
		t.Fatal("correct password still cannot sign in after unlock:", err)
	}
	t.Log("Real failed-password lockout, diagnosis, stale revision refusal, unlock verification and successful subsequent login passed")
}
