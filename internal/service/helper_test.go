package service

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"sambaadm/internal/adremote"
	"sambaadm/internal/agent"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
)

func testHelperClient(t *testing.T, backend *Services, cfg *config.Config, intercept ...func(context.Context, string, json.RawMessage) error) *agent.Client {
	t.Helper()
	if cfg.Helper.StateDir == "" {
		cfg.Helper.StateDir = t.TempDir()
	}
	if e := os.Chmod(cfg.Helper.StateDir, 0700); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	private, public := filepath.Join(dir, "key"), filepath.Join(dir, "key.pub")
	if e := agent.GenerateKey(private, public); e != nil {
		t.Fatal(e)
	}
	v, e := agent.NewVerifier(cfg.Helper.Node, []string{public})
	if e != nil {
		t.Fatal(e)
	}
	if e = v.UseStateDir(cfg.Helper.StateDir); e != nil {
		t.Fatal(e)
	}
	srv := httptest.NewUnstartedServer(agent.API(v, func(ctx context.Context, method string, raw json.RawMessage) (any, error) {
		for _, hook := range intercept {
			if err := hook(ctx, method, raw); err != nil {
				return nil, err
			}
		}
		return backend.HelperDispatch(ctx, cfg, method, raw)
	}))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	cert, e := x509.ParseCertificate(srv.TLS.Certificates[0].Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	ca := filepath.Join(dir, "ca.pem")
	if e = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); e != nil {
		t.Fatal(e)
	}
	return &agent.Client{Config: agent.Config{PrivateKey: private, HostNode: cfg.Helper.Node, Nodes: []agent.Node{{Name: cfg.Helper.Node, Transport: "https", Endpoint: srv.URL, CACert: ca}}}}
}

func TestHostServicesUseHelperAndDoNotFallBack(t *testing.T) {
	dir := t.TempDir()
	smb := filepath.Join(dir, "smb.conf")
	if e := os.WriteFile(smb, []byte("[global]\nworkgroup = TEST\n[demo]\npath = "+dir+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	cfg := &config.Config{Samba: config.SambaConfig{SMBConf: smb, SharesRoot: dir}, Helper: config.HelperServerConfig{Node: "files.example", StateDir: t.TempDir()}}
	logger, e := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { logger.Close() })
	backend := NewWithOptions(ldapproto.NewClient(config.LDAPConfig{}), logger, ServiceOptions{Samba: cfg.Samba})
	client := testHelperClient(t, backend, cfg)
	front := NewWithOptions(ldapproto.NewClient(config.LDAPConfig{}), nil, ServiceOptions{Samba: config.SambaConfig{SMBConf: "/must-not-read-local", SharesRoot: "/must-not-read-local"}, Helpers: client})
	shares, e := front.Shares.List(context.Background())
	if e != nil || len(shares) != 1 || shares[0].Name != "demo" {
		t.Fatal(shares, e)
	}
	front.Shares.helpers = &agent.Client{}
	if _, e = front.Shares.List(context.Background()); e == nil {
		t.Fatal("missing helper fell back to local file")
	}
	gpo := &GPOService{helpers: &agent.Client{}}
	called := false
	e = gpo.sysvol(context.Background(), &adremote.Client{Host: "unregistered.example"}, 445, func(*sysvolShare) error { called = true; return nil })
	if e == nil || called {
		t.Fatal("missing DC helper was bypassed")
	}
	if _, e = helperNativeOpenFlags(64); e == nil {
		t.Fatal("unrecognized open mode accepted")
	}
	if flags, e := helperNativeOpenFlags(helperOpenFlags(os.O_WRONLY | os.O_CREATE | os.O_EXCL)); e != nil || flags != os.O_WRONLY|os.O_CREATE|os.O_EXCL {
		t.Fatal(flags, e)
	}
}

func TestForwardedSYSVOLCredentialsDoNotMutateServiceIdentity(t *testing.T) {
	var fallbackUsed atomic.Bool
	client := ldapproto.NewClient(config.LDAPConfig{URI: "ldaps://127.0.0.1:636"})
	backend := NewWithOptions(client, nil, ServiceOptions{Username: "service@example.org", Password: func() string { fallbackUsed.Store(true); return "service-password" }})
	cfg := &config.Config{}
	cfg.Helper.SYSVOLPrefix = "example.org/Policies"
	cfg.GPO.SMBPort = 1
	ctx := agent.WithCredentials(t.Context(), func() (agent.Credentials, error) {
		return agent.Credentials{Username: "admin@example.org", Password: "admin-password"}, nil
	})
	raw, _ := json.Marshal(helperFSRequest{Path: "example.org/Policies"})
	if _, err := backend.helperSYSVOL(ctx, cfg, "stat", raw); err == nil {
		t.Fatal("closed test port accepted")
	}
	if fallbackUsed.Load() {
		t.Fatal("helper used configured password instead of request identity")
	}
	if backend.GPO.remote.User != "service@example.org" {
		t.Fatal("shared service identity mutated")
	}
	if err := backend.GPO.sysvol(ctx, backend.GPO.remote, 1, func(*sysvolShare) error { return nil }); err == nil || !strings.Contains(err.Error(), "registered sambaadm-helper") {
		t.Fatal("missing helper silently fell back", err)
	}
	if fallbackUsed.Load() {
		t.Fatal("missing helper used configured password")
	}
}
