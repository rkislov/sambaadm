package service

import (
	"context"
	"errors"
	"fmt"
	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
	"os"
	"path/filepath"
	"sambaadm/internal/adremote"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"testing"
	"time"
)

func TestIntegrationFullDelegationGrantRevoke(t *testing.T) {
	s, _ := integrationServices(t, true)
	s.GPO.gpoCfg.DelegationStateDir = filepath.Join(t.TempDir(), "delegation")
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	name := fmt.Sprintf("IT-FullACL-%d", time.Now().UnixNano())
	if _, e := s.GPO.Create(ctx, name, "integration", ""); e != nil {
		t.Fatal(e)
	}
	policies, e := s.GPO.List(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var id string
	for _, p := range policies {
		if p.DisplayName == name {
			id = p.GUID
		}
	}
	if id == "" {
		t.Fatal("missing GPO")
	}
	t.Cleanup(func() { s.GPO.Delete(context.Background(), id, "integration", "") })
	user, e := s.Users.Create(ctx, CreateUserInput{Login: name, Password: "Delegation-Test-Pass1!", Enabled: true}, "integration", "")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Users.Delete(context.Background(), name, "integration", "") })

	principalRemote := &adremote.Client{Host: s.GPO.remote.Host, User: name + "@sambaadm.test", Password: func() string { return "Delegation-Test-Pass1!" }}
	principalLDAP := ldapproto.NewServiceClient(config.LDAPConfig{URI: os.Getenv("SAMBAADM_IT_URI"), CACert: os.Getenv("SAMBAADM_IT_CA"), BaseDN: "DC=sambaadm,DC=test", Bind: config.BindConfig{Type: "simple", User: name + "@sambaadm.test"}}, func() string { return "Delegation-Test-Pass1!" })
	defer principalLDAP.Close()
	entry, e := s.GPO.policyEntry(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	base, e := s.GPO.policyPath(ctx, entry)
	if e != nil {
		t.Fatal(e)
	}
	canWrite := func() error {
		return principalRemote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
			f, e := sh.OpenFile(base+"\\GPT.INI", os.O_RDWR, 0)
			if e != nil {
				return e
			}
			return f.Close()
		})
	}
	if canWrite() == nil {
		t.Fatal("baseline account unexpectedly can write")
	}
	for _, profile := range []string{"read-apply", "edit"} {
		in := DelegationOperation{Operation: "grant", Principal: user.DN, Profile: profile}
		p, e := s.GPO.FullDelegationPreview(ctx, id, in)
		if e != nil {
			t.Fatal(e)
		}
		if len(p.Files) < 4 || len(p.Conflicts) > 0 {
			t.Fatalf("plan: %+v", p)
		}
		in.Preview = p.Preview
		if e = s.GPO.FullDelegationApply(ctx, id, in, "integration", ""); e != nil {
			t.Fatal(e)
		}

		accessErr := canWrite()
		if (profile == "edit") != (accessErr == nil) {
			t.Fatalf("SYSVOL %s access: %v", profile, accessErr)
		}
		req := ldap.NewModifyRequest(entry.DN, nil)
		req.Replace("description", []string{"delegation access test"})
		accessErr = principalLDAP.Modify(ctx, req)
		if (profile == "edit") != (accessErr == nil) {
			t.Fatalf("LDAP %s access: %v", profile, accessErr)
		}
		state, e := s.GPO.FullDelegationState(ctx, id)
		if e != nil || state.Pending != "" {
			t.Fatalf("state %+v %v", state, e)
		}
		in = DelegationOperation{Operation: "revoke", Source: state.Records[0].ID}
		p, e = s.GPO.FullDelegationPreview(ctx, id, in)
		if e != nil {
			t.Fatal(e)
		}
		if len(p.Conflicts) > 0 {
			t.Fatalf("revoke conflicts %+v", p)
		}
		in.Preview = p.Preview
		if e = s.GPO.FullDelegationApply(ctx, id, in, "integration", ""); e != nil {
			t.Fatal(e)
		}
		if canWrite() == nil {
			t.Fatal("write permission remains after revoke")
		}
		state, e = s.GPO.FullDelegationState(ctx, id)
		if e != nil || state.Pending != "" || !state.Records[1].Revoked {
			t.Fatalf("revoked %+v %v", state, e)
		}
	}
	// Simulate a lost response after LDAP committed, then reopen the durable journal
	// using a new service instance (no in-memory transaction state).
	e = s.GPO.withDelegation(ctx, id, func(root policyStore, local *os.Root, entry *ldap.Entry) error {
		sid, e := s.GPO.delegationSID(ctx, user.DN)
		if e != nil {
			return e
		}
		p, e := buildDelegationPlan(root, local, s.GPO.remote.Host, entry, DelegationOperation{Operation: "grant", Principal: user.DN, Profile: "edit"}, sid)
		if e != nil {
			return e
		}
		return applyDelegationPlan(root, local, p, func() ([]byte, string, error) {
			v, e := s.GPO.filterEntry(ctx, id)
			if e != nil {
				return nil, "", e
			}
			acl, e := normalizeDACL(v.GetRawAttributeValue("nTSecurityDescriptor"))
			return acl, v.GetAttributeValue("uSNChanged"), e
		}, func(acl []byte, revision string) error {
			controls, e := assertion(revision)
			if e != nil {
				return e
			}
			controls = append(controls, daclControl)
			req := ldap.NewModifyRequest(entry.DN, controls)
			req.Replace("nTSecurityDescriptor", []string{string(acl)})
			if e = s.GPO.ldap.Modify(ctx, req); e != nil {
				return e
			}
			return errors.New("injected lost LDAP response")
		})
	})
	if e == nil {
		t.Fatal("lost LDAP response not injected")
	}
	reopened := &GPOService{remote: s.GPO.remote, ldap: s.GPO.ldap, audit: s.GPO.audit, gpoCfg: s.GPO.gpoCfg}
	state, e := reopened.FullDelegationState(ctx, id)
	if e != nil || state.Pending == "" {
		t.Fatalf("pending history %+v %v", state, e)
	}
	pendingID := state.Pending
	in := DelegationOperation{Operation: "complete", Source: pendingID}
	p, e := reopened.FullDelegationPreview(ctx, id, in)
	if e != nil || len(p.Conflicts) > 0 {
		t.Fatalf("reopen %+v %v", p, e)
	}
	in.Preview = p.Preview
	if e = reopened.FullDelegationApply(ctx, id, in, "integration", ""); e != nil {
		t.Fatal(e)
	}
	in = DelegationOperation{Operation: "revoke", Source: pendingID}
	p, e = reopened.FullDelegationPreview(ctx, id, in)
	if e != nil {
		t.Fatal(e)
	}
	in.Preview = p.Preview
	if e = reopened.FullDelegationApply(ctx, id, in, "integration", ""); e != nil {
		t.Fatal(e)
	}
	if canWrite() == nil {
		t.Fatal("write access remains after recovered grant was revoked")
	}

}
