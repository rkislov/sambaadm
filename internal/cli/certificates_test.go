package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"sambaadm/internal/config"
	"sambaadm/internal/pki"
	"sambaadm/internal/testkerberos"
	"strings"
	"testing"
	"time"
)

func TestHTTPSConfigureAndRenewPreserveConfiguration(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "config.yaml")
	raw := "# Preserve this deployment\nserver:\n  listen: 127.0.0.1:8080\n  certificate_dir: " + filepath.Join(dir, "certificates") + "\nldap:\n  uri: ldaps://dc.example.test:636\n  base_dn: DC=example,DC=test\n  bind:\n    user: svc@example.test\nauth:\n  roles:\n    admins: [CN=Administrators]\ncustom_future_setting: keep-me\n"
	if err := os.WriteFile(source, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	_, keytab := testkerberos.Keytab(t, "HTTP/sambaadm.example.test", "EXAMPLE.TEST")
	previous := rootCfg
	defer func() { rootCfg = previous }()
	run := func(mode, src, target string, flags map[string]string) error {
		var err error
		rootCfg, err = config.Load(src)
		if err != nil {
			return err
		}
		cmd, _, err := rootCmd.Find([]string{"certificates", mode})
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"dns", "listen", "keytab", "sso-realm"} {
			_ = cmd.Flags().Set(name, "")
		}
		_ = cmd.Flags().Set("output", target)
		for name, value := range flags {
			if err = cmd.Flags().Set(name, value); err != nil {
				t.Fatal(err)
			}
		}
		cmd.SetOut(&bytes.Buffer{})
		return cmd.RunE(cmd, nil)
	}
	candidate := filepath.Join(dir, "candidate.yaml")
	if err := run("configure", source, candidate, map[string]string{"keytab": keytab}); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(source)
	if string(original) != raw {
		t.Fatal("source configuration changed")
	}
	data, _ := os.ReadFile(candidate)
	if !strings.Contains(string(data), "# Preserve this deployment") || !strings.Contains(string(data), "custom_future_setting: keep-me") {
		t.Fatal("lost comments or unknown settings")
	}
	cfg, err := config.Load(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.PublicURL != "https://sambaadm.example.test" || cfg.Server.Listen != "0.0.0.0:443" || !cfg.Auth.SSO.Enabled || cfg.Auth.SSO.Keytab != keytab {
		t.Fatal("incorrect HTTPS or SSO config")
	}
	pair, err := pki.LoadServerPair(cfg.Server.TLS.Cert, cfg.Server.TLS.Key, "sambaadm.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(pair.Leaf.NotAfter) < 9*365*24*time.Hour {
		t.Fatal("expected ten year certificate")
	}
	if err = run("configure", source, candidate, nil); err == nil {
		t.Fatal("existing candidate overwritten")
	}
	renewed := filepath.Join(dir, "renewed.yaml")
	if err = run("renew", candidate, renewed, nil); err != nil {
		t.Fatal(err)
	}
	next, err := config.Load(renewed)
	if err != nil {
		t.Fatal(err)
	}
	if next.Auth.SSO != cfg.Auth.SSO || next.LDAP.Bind.User != cfg.LDAP.Bind.User || next.Server.PublicURL != cfg.Server.PublicURL {
		t.Fatal("renewal changed identity or LDAP settings")
	}
	if next.Server.TLS.Cert == cfg.Server.TLS.Cert {
		t.Fatal("renewal reused TLS files")
	}
	if _, err = os.Stat(cfg.Server.TLS.Cert); err != nil {
		t.Fatal("old certificate lost")
	}
}
