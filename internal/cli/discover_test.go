package cli

import (
	"bytes"
	"context"
	"errors"
	"github.com/spf13/cobra"
	"net"
	"os"
	"path/filepath"
	"sambaadm/internal/config"
	"testing"
)

func TestResolveCandidates(t *testing.T) {
	lookup := func(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
		if service != "ldap" || proto != "tcp" {
			t.Fatal(service, proto)
		}
		switch name {
		case "dc._msdcs.corp.example", "dc._msdcs.lab.example":
			return "", []*net.SRV{{Target: "DC1." + name[len("dc._msdcs."):] + "."}}, nil
		}
		return "", nil, nil
	}
	candidates := resolverDomains("domain previous.example\nsearch unrelated.example CORP.EXAMPLE # search suffixes")
	domain, dc, err := resolveCandidates(context.Background(), candidates, "", "", lookup)
	if err != nil || domain != "corp.example" || dc != "dc1.corp.example" {
		t.Fatal(domain, dc, err)
	}
	if _, _, err := resolveCandidates(context.Background(), append(candidates, "lab.example"), "", "", lookup); err == nil {
		t.Fatal("ambiguous domains accepted")
	}
}

func TestDiscoveredConfigFile(t *testing.T) {
	data, err := discoveredConfig(context.Background(), "CORP.EXAMPLE", "DC1.CORP.EXAMPLE", "svc@corp.example", "CN=Operators,DC=corp,DC=example", "/etc/domain-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := writeDiscoveredConfig(path, data); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v", info.Mode())
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LDAP.URI != "ldaps://dc1.corp.example:636" || cfg.LDAP.BaseDN != "DC=corp,DC=example" || cfg.LDAP.Bind.User != "svc@corp.example" || cfg.LDAP.CACert != "/etc/domain-ca.pem" || cfg.Server.Listen != "127.0.0.1:8080" || cfg.Server.EnrollmentDir == "" || cfg.Auth.Roles.Admins[0] != "CN=Operators,DC=corp,DC=example" {
		t.Fatalf("unexpected configuration: %+v", cfg)
	}
	if err := writeDiscoveredConfig(path, []byte("replacement")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("overwrite: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("existing config changed", err)
	}
}

func TestDiscoveredConfigDoesNotFollowSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	path := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(target, path); err != nil {
		t.Skip(err)
	}
	if err := writeDiscoveredConfig(path, []byte("replacement")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target was created: %v", err)
	}
}

func TestEnsureServerConfigPreservesExisting(t *testing.T) {
	previous := cfgFile
	t.Cleanup(func() { cfgFile = previous })
	cfgFile = filepath.Join(t.TempDir(), "config.yaml")
	original := []byte("# operator config\n")
	if err := os.WriteFile(cfgFile, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureServerConfig(&cobra.Command{}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(cfgFile)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("existing config changed", err)
	}
}
