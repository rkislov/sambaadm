package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestIntegrationGPOScopeAndFilter(t *testing.T) {
	s, cfg := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name := fmt.Sprintf("IT-Scope-%d", time.Now().UnixNano())
	actor, ip := "integration", "127.0.0.1"
	ou, e := s.OU.Create(ctx, CreateOUInput{Name: name, ParentDN: cfg.BaseDN, Description: "scope test"}, actor, ip)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.OU.Delete(context.Background(), ou.DN, actor, ip) })
	if _, e = s.GPO.Create(ctx, name, actor, ip); e != nil {
		t.Fatal(e)
	}
	policies, e := s.GPO.List(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var p GPO
	for _, g := range policies {
		if g.DisplayName == name {
			p = g
		}
	}
	if p.GUID == "" {
		t.Fatal("missing policy")
	}
	t.Cleanup(func() {
		s.GPO.Unlink(context.Background(), ou.DN, p.GUID, actor, ip)
		s.GPO.Delete(context.Background(), p.GUID, actor, ip)
	})
	model, e := s.GPO.Scope(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var rev string
	for _, c := range model.Containers {
		if strings.EqualFold(c.DN, ou.DN) {
			rev = c.Revision
		}
	}
	in := ScopeChange{Container: ou.DN, Revision: rev, Block: true, Links: []ScopeLink{{DN: p.DN, Enabled: true, Enforced: true}}}
	if e = s.GPO.SaveScope(ctx, in, actor, ip); e != nil {
		t.Fatal(e)
	}
	if e = s.GPO.SaveScope(ctx, in, actor, ip); !errors.Is(e, ErrTopologyConflict) {
		t.Fatal("stale scope", e)
	}
	model, e = s.GPO.Scope(ctx)
	if e != nil {
		t.Fatal(e)
	}
	v, e := ScopeInheritance(model, ou.DN)
	if e != nil || len(v) == 0 || v[0].GUID != p.GUID || !v[0].Enforced {
		t.Fatalf("%+v %v", v, e)
	}

	// Explanation is LDAP-only, including when the editor and SMB access are disabled.
	editorEnabled, remote := s.GPO.gpoCfg.EditorEnabled, s.GPO.remote
	s.GPO.gpoCfg.EditorEnabled, s.GPO.remote = false, nil
	report, explainErr := s.GPO.Explain(ctx, GPExplainInput{Computer: ou.DN})
	s.GPO.gpoCfg.EditorEnabled, s.GPO.remote = editorEnabled, remote
	if explainErr != nil || len(report.Sections) != 1 {
		t.Fatalf("explain: %+v %v", report, explainErr)
	}
	found := false
	for _, link := range report.Sections[0].Links {
		if link.GUID == p.GUID {
			found = link.Status == "conditional" && link.Priority == 1
		}
	}
	if !found {
		t.Fatalf("missing conditional policy: %+v", report)
	}
	user, err := s.Users.Create(ctx, CreateUserInput{Login: name, OU: ou.DN}, actor, ip)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Users.Delete(context.Background(), name, actor, ip) })
	report, explainErr = s.GPO.Explain(ctx, GPExplainInput{User: user.DN})
	if explainErr != nil || report.Sections[0].Container != ou.DN {
		t.Fatalf("user explanation: %+v %v", report, explainErr)
	}
	if _, err = s.GPO.Explain(ctx, GPExplainInput{Computer: user.DN}); err == nil {
		t.Fatal("user accepted as computer")
	}
	if _, err = s.GPO.Explain(ctx, GPExplainInput{User: "CN=x,DC=other"}); err == nil {
		t.Fatal("foreign target accepted")
	}
	before, e := s.GPO.SecurityFilter(ctx, p.GUID)
	if e != nil {
		t.Fatal(e)
	}
	var ace GPFilterACE
	for _, a := range before.Entries {
		if a.SID == "S-1-5-11" && a.Editable {
			ace = a
		}
	}
	if ace.ID == "" {
		t.Fatalf("no Authenticated Users Apply ACE: %+v", before)
	}
	if e = s.GPO.SetSecurityFilter(ctx, p.GUID, FilterChange{Revision: before.Revision, Remove: ace.ID}, actor, ip); e != nil {
		t.Fatal(e)
	}
	after, e := s.GPO.SecurityFilter(ctx, p.GUID)
	if e != nil {
		t.Fatal(e)
	}
	if len(after.Entries) != len(before.Entries)-1 {
		t.Fatal("unrelated ACL changed")
	}
	for _, a := range after.Entries {
		found := false
		for _, b := range before.Entries {
			found = found || a.ID == b.ID
		}
		if !found {
			t.Fatal("unrelated ACE changed")
		}
	}
	if e = s.GPO.SetSecurityFilter(ctx, p.GUID, FilterChange{Revision: before.Revision, Principal: "S-1-5-11"}, actor, ip); !errors.Is(e, ErrTopologyConflict) {
		t.Fatal("stale ACL", e)
	}
	if e = s.GPO.SetSecurityFilter(ctx, p.GUID, FilterChange{Revision: after.Revision, Principal: "S-1-5-11"}, actor, ip); e != nil {
		t.Fatal(e)
	}
}

func TestIntegrationShareWizardDomainResolution(t *testing.T) {
	s, cfg := integrationServices(t, false)
	ctx := context.Background()
	groups, e := s.Groups.List(ctx, "")
	if e != nil {
		t.Fatal(e)
	}
	var dn string
	for _, g := range groups {
		if g.SAMAccountName == "Domain Users" {
			dn = g.DN
		}
	}
	if dn == "" {
		t.Fatal("missing domain users")
	}
	in := ShareWizardInput{Name: "IT-Team", Profile: "team", Groups: []string{dn}}
	plan, e := s.planShare(ctx, in, func(context.Context, string) (string, error) { return "12345", nil })
	if e != nil {
		t.Fatal(e)
	}
	if !plan.Ready || plan.Input.ValidUsers != `@"SAMBAADM\Domain Users"` || plan.Input.WriteList != plan.Input.ValidUsers || !strings.Contains(plan.Input.ACL, "g:12345:rwx") || !*plan.Input.ReadOnly || *plan.Input.GuestOK {
		t.Fatalf("%+v", plan)
	}
	in.Groups = []string{"CN=Domain Users,CN=Users,DC=other,DC=test"}
	if _, e = s.planShare(ctx, in, func(context.Context, string) (string, error) { t.Fatal("foreign principal resolved"); return "", nil }); e == nil {
		t.Fatal("foreign domain accepted", cfg)
	}
}
