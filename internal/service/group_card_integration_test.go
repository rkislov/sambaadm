package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
	"testing"
	"time"
)

func TestIntegrationGroupCardAndMemberDelegation(t *testing.T) {
	s, cfg := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	prefix := fmt.Sprintf("gc-%d", time.Now().UnixNano()%1000000000)
	created := []string{}
	defer func() {
		for _, name := range created {
			_ = s.Groups.Delete(context.Background(), name, "test", "")
		}
	}()
	create := func(suffix string) *Group {
		g, e := s.Groups.Create(ctx, CreateGroupInput{Name: prefix + suffix}, "test", "")
		if e != nil {
			t.Fatal(e)
		}
		created = append(created, g.SAMAccountName)
		return g
	}
	parent := create("-p")
	child := create("-c")
	operators := create("-o")
	other := create("-x")
	g, e := s.Groups.Update(ctx, parent.SAMAccountName, UpdateGroupInput{Revision: parent.Revision, Description: "Русское описание", Scope: "universal", Category: "security", Confirm: true}, "test", "")
	if e != nil || g.Scope != "universal" {
		t.Fatal(g, e)
	}
	if _, e = s.Groups.Update(ctx, g.SAMAccountName, UpdateGroupInput{Revision: parent.Revision, Scope: "global", Category: "security", Confirm: true}, "test", ""); !errors.Is(e, ErrGroupConflict) {
		t.Fatal("stale group revision", e)
	}
	if e = s.Groups.AddMember(ctx, parent.SAMAccountName, child.DN, "test", ""); e != nil {
		t.Fatal(e)
	}
	if e = s.Groups.AddMember(ctx, child.SAMAccountName, parent.DN, "test", ""); !errors.Is(e, ErrGroupMemberInput) {
		t.Fatal("cycle accepted", e)
	}
	password := "Card-fixture-Pass42!"
	login := prefix + "-u"
	user, e := s.Users.Create(ctx, CreateUserInput{Login: login, Password: password, Enabled: true}, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Users.Delete(context.Background(), login, "test", "")
	if e = s.Groups.AddMember(ctx, child.SAMAccountName, user.DN, "test", ""); e != nil {
		t.Fatal(e)
	}
	if e = s.Groups.AddMember(ctx, operators.SAMAccountName, user.DN, "test", ""); e != nil {
		t.Fatal(e)
	}
	details, e := s.Groups.Details(ctx, parent.SAMAccountName)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, p := range details.Members {
		if sameGroupDN(p.DN, user.DN) {
			found = !p.Direct && len(p.Via) == 2
		}
	}
	if !found {
		t.Fatal("nested membership path missing", details.Members)
	}
	acl, e := s.Groups.Access(ctx, parent.SAMAccountName)
	if e != nil {
		t.Fatal(e)
	}
	change := GPDelegationChange{Revision: acl.Revision, Principal: operators.DN, Profile: "manage-members"}
	plan, e := s.Groups.AccessPreview(ctx, parent.SAMAccountName, change)
	if e != nil || len(plan.Added) != 2 {
		t.Fatal(plan, e)
	}
	if e = s.Groups.GrantAccess(ctx, parent.SAMAccountName, change, "test", ""); e == nil {
		t.Fatal("grant without preview accepted")
	}
	change.Preview = plan.Preview
	if e = s.Groups.GrantAccess(ctx, parent.SAMAccountName, change, "test", ""); e != nil {
		t.Fatal(e)
	}
	limited := ldapproto.NewClient(cfg)
	defer limited.Close()
	if e = limited.BindSimple(ctx, login+"@sambaadm.test", password); e != nil {
		t.Fatal(e)
	}
	req := ldap.NewModifyRequest(parent.DN, nil)
	req.Add("member", []string{other.DN})
	if e = limited.Modify(ctx, req); e != nil {
		t.Fatal("delegated membership write failed", e)
	}
	req = ldap.NewModifyRequest(parent.DN, nil)
	req.Replace("description", []string{"must be denied"})
	if e = limited.Modify(ctx, req); !ldap.IsErrorWithCode(e, ldap.LDAPResultInsufficientAccessRights) {
		t.Fatal("delegation granted unrelated write", e)
	}
	updated, e := s.Groups.Show(ctx, parent.SAMAccountName)
	if e != nil {
		t.Fatal(e)
	}
	if updated.Description != "Русское описание" {
		t.Fatal(updated)
	}
}
