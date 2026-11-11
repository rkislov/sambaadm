package service

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
)

func TestIntegrationRODCReplicationStatus(t *testing.T) {
	host := os.Getenv("SAMBAADM_IT_RODC")
	if host == "" {
		t.Skip("requires disposable RODC")
	}
	s, cfg := integrationServices(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	check := func(t *testing.T, repl *ReplService, target string) {
		t.Helper()
		status, err := repl.StatusFor(ctx, target)
		if err != nil {
			t.Fatal(err)
		}
		if status.Health != "healthy" || status.Server != host || len(status.PartitionIssues) != 0 {
			t.Fatalf("wrong RODC status: %+v", status)
		}
		partitions := make(map[string]bool)
		for _, neighbor := range status.Neighbors {
			attempt, err := time.Parse(time.RFC3339, neighbor.LastAttempt)
			if neighbor.Direction != "inbound" || neighbor.Partner == "" || neighbor.Result != "0" ||
				err != nil || time.Since(attempt).Abs() >= time.Hour {
				t.Fatalf("expected recent successful inbound replication: %+v", neighbor)
			}
			partitions[dnKey(neighbor.Partition)] = true
		}
		for _, prefix := range []string{"", "CN=Configuration,", "CN=Schema,CN=Configuration,", "DC=ForestDnsZones,", "DC=DomainDnsZones,"} {
			if !partitions[dnKey(prefix+cfg.BaseDN)] {
				t.Errorf("missing inbound neighbors for %s%s", prefix, cfg.BaseDN)
			}
		}
	}
	t.Run("selected RODC", func(t *testing.T) { check(t, s.Repl, host) })
	t.Run("default RODC", func(t *testing.T) {
		peer := s.Repl.ldap.ServicePeer("ldaps://" + host + ":636")
		defer peer.Close()
		remote := *s.Repl.remote
		remote.Host = host
		check(t, &ReplService{ldap: peer, remote: &remote}, "")
	})
}

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

	// The RODC receives a policy with nested files through the signed helper.
	// A regular domain user can authenticate but cannot install the same policy.
	const policy = "31B2F340-016D-11D2-945F-00C04FB984F9"
	snapshot, entry, e := s.GPO.captureNativeBackup(ctx, policy)
	if e != nil {
		t.Fatal(e)
	}
	path, e := s.GPO.policyPath(ctx, entry)
	if e != nil {
		t.Fatal(e)
	}
	localPolicy := filepath.Join("/var/lib/samba/sysvol", filepath.FromSlash(strings.ReplaceAll(path, `\`, "/")))
	// Use a named, inherited POSIX ACL with a restrictive mask, as on
	// provisioned SYSVOL shares that also store Windows ACLs.
	if out, err := exec.CommandContext(ctx, "setfacl", "-m", "d:g:65534:rwx,d:m::r-x,d:o::---", filepath.Dir(localPolicy)).CombinedOutput(); err != nil {
		t.Fatalf("configure SYSVOL POSIX ACL: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if e := s.RODC.helpers.Call(context.Background(), host, "sysvol.remove-tree", helperFSRequest{Path: path}, nil); e != nil {
			t.Error(e)
		}
	})
	var machine string
	for name := range snapshot.Permissions {
		if strings.EqualFold(name, "Machine") {
			machine = name
			break
		}
	}
	if machine == "" {
		t.Fatal("source policy has no Machine ACL")
	}
	preferences := machine + "/Preferences"
	fileRel := preferences + "/sambaadm-integration.txt"
	snapshot.Permissions[preferences] = snapshot.Permissions[machine]
	snapshot.Permissions[fileRel] = snapshot.Permissions["GPT.INI"]
	snapshot.Files[fileRel] = []byte("first revision")
	in := policyInstallRequest{Target: path, ACL: snapshot.ACL, Files: snapshot.Files, Permissions: snapshot.Permissions}
	withCredentials := func(user, password string) context.Context {
		return agent.WithCredentials(ctx, func() (agent.Credentials, error) {
			return agent.Credentials{Username: user, Password: password}, nil
		})
	}
	admin := withCredentials(cfg.Bind.User, os.Getenv(cfg.Bind.PasswordEnv))
	if e = s.RODC.helpers.Call(admin, host, "sysvol.install-policy", in, nil); e != nil {
		t.Fatal(e)
	}
	for _, check := range []struct {
		path string
		mask os.FileMode
	}{
		{localPolicy, 0o050},
		{filepath.Join(localPolicy, preferences), 0o050},
		{filepath.Join(localPolicy, fileRel), 0o040},
	} {
		info, err := os.Stat(check.path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm() & 0o077; got != check.mask {
			t.Errorf("%s: effective group/other mode %03o, want %03o", check.path, got, check.mask)
		}
	}
	ordinary := withCredentials(name+"@sambaadm.test", "Lab-User-Test-Pass1!")
	snapshot.Files[fileRel] = []byte("second revision")
	if e = s.RODC.helpers.Call(ordinary, host, "sysvol.install-policy", in, nil); e == nil || !strings.Contains(e.Error(), "lacks rights") {
		t.Fatalf("ordinary domain user was not rejected by the write-access check: %v", e)
	}
	nested := helperFSRequest{Path: path + `\` + strings.ReplaceAll(fileRel, "/", `\`)}
	if e = s.RODC.helpers.Call(admin, host, "sysvol.read", nested, &data); e != nil || !bytes.Equal(data, []byte("first revision")) {
		t.Fatalf("unauthorized request changed the policy: %q, %v", data, e)
	}
	if e = s.RODC.helpers.Call(admin, host, "sysvol.install-policy", in, nil); e != nil {
		t.Fatal(e)
	}
	if e = s.RODC.helpers.Call(admin, host, "sysvol.read", nested, &data); e != nil || !bytes.Equal(data, []byte("second revision")) {
		t.Fatalf("policy replacement did not install the nested file: %q, %v", data, e)
	}
}
