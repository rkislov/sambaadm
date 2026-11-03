package service

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
)

func TestIntegrationRODCPolicyPreloadAndAuthentication(t *testing.T) {
	host := os.Getenv("SAMBAADM_IT_RODC")
	if host == "" {
		t.Skip("requires disposable RODC")
	}
	s, cfg := integrationServices(t, true)
	helperCfg := &config.Config{LDAP: cfg, Helper: config.HelperServerConfig{Node: host, AuthLog: "/var/log/samba/auth.json", SYSVOLPrefix: "sambaadm.test/Policies"}}
	s.RODC.helpers = testHelperClient(t, s, helperCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	state, e := s.RODC.State(ctx, host)
	if e != nil {
		t.Fatal(e)
	}
	if !state.Controller.RODC || state.Source != "dc1.sambaadm.test" {
		t.Fatalf("wrong controller: %+v", state)
	}
	name := fmt.Sprintf("it-rodc-%d", time.Now().UnixNano())
	u, e := s.Users.Create(ctx, CreateUserInput{Login: name, Password: "Lab-User-Test-Pass1!", Enabled: true}, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Users.Delete(context.Background(), name, "test", "") })
	apply := func(in RODCInput) *RODCResult {
		t.Helper()
		p, e := s.RODC.Preview(ctx, host, in)
		if e != nil {
			t.Fatal(e)
		}
		in.Preview = p.Preview
		r, e := s.RODC.Apply(ctx, host, in, "test", "")
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	apply(RODCInput{Operation: "allow", Principal: u.DN})
	t.Cleanup(func() {
		p, e := s.RODC.Preview(context.Background(), host, RODCInput{Operation: "remove-allow", Principal: u.DN})
		if e == nil {
			s.RODC.Apply(context.Background(), host, RODCInput{Operation: "remove-allow", Principal: u.DN, Preview: p.Preview}, "test", "")
		}
	})
	apply(RODCInput{Operation: "deny", Principal: u.DN})
	p, e := s.RODC.Preview(ctx, host, RODCInput{Operation: "preload", Accounts: []string{u.DN}})
	if e != nil {
		t.Fatal(e)
	}
	if p.Accounts[0].Decision != "denied" {
		t.Fatalf("deny did not win: %+v", p)
	}
	r := apply(RODCInput{Operation: "preload", Accounts: []string{u.DN}})
	if r.Accounts[0].Status != "blocked" {
		t.Fatalf("denied preload ran: %+v", r)
	}
	apply(RODCInput{Operation: "remove-deny", Principal: u.DN})
	if e = s.Repl.Sync(ctx, host, "dc1.sambaadm.test", cfg.BaseDN, "test", ""); e != nil {
		t.Fatal(e)
	}
	r = apply(RODCInput{Operation: "preload", Accounts: []string{u.DN}})
	if r.Accounts[0].Status != "preloaded" {
		t.Fatalf("preload: %+v", r)
	}
	state, e = s.RODC.State(ctx, host)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, p := range state.Cached {
		if p.DN == u.DN {
			found = true
		}
	}
	if !found {
		t.Fatalf("source did not record revealed secret: %+v", state.Cached)
	}
	// Authenticate directly against this RODC, then read its own JSON audit.
	peerCfg := cfg
	peerCfg.URI = "ldaps://" + host + ":636"
	client := ldapproto.NewClient(peerCfg)
	defer client.Close()
	if e = client.BindSimple(ctx, name+"@sambaadm.test", "Lab-User-Test-Pass1!"); e != nil {
		t.Fatal(e)
	}
	if e = client.BindSimple(ctx, name+"@sambaadm.test", "wrong-password"); e == nil {
		t.Fatal("bad password authenticated")
	}
	auth, e := s.RODC.Authentications(ctx, host, time.Time{}, name)
	if e != nil {
		t.Fatal(e)
	}
	if len(auth.Events) < 2 {
		t.Fatalf("RODC audit lacks success/failure: %+v", auth)
	}
	success, failure := false, false
	for _, event := range auth.Events {
		if event.Status == "NT_STATUS_OK" {
			success = true
		} else {
			failure = true
		}
	}
	if !success || !failure {
		t.Fatalf("audit: %+v", auth.Events)
	}
	// The same RODC agent also receives policy files; never write from sambaadm
	// directly to the remote share.
	if e = s.RODC.helpers.Call(ctx, host, "sysvol.mkdir-all", helperFSRequest{Path: `sambaadm.test\Policies`, Mode: 0755}, nil); e != nil {
		t.Fatal(e)
	}
	file := `sambaadm.test\Policies\.sambaadm-rodc-file-test-` + name
	t.Cleanup(func() {
		s.RODC.helpers.Call(context.Background(), host, "sysvol.remove", helperFSRequest{Path: file}, nil)
	})
	if e = s.RODC.helpers.Call(ctx, host, "sysvol.write-file", helperFSRequest{Path: file, Data: []byte("RODC helper copy"), Mode: 0600}, nil); e != nil {
		t.Fatal(e)
	}
	var data []byte
	if e = s.RODC.helpers.Call(ctx, host, "sysvol.read", helperFSRequest{Path: file}, &data); e != nil || string(data) != "RODC helper copy" {
		t.Fatal(string(data), e)
	}
}
