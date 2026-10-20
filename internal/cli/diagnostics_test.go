package cli

import (
	"bytes"
	"log/slog"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"strings"
	"testing"
)

func TestDiagnosticURIRedactsCredentials(t *testing.T) {
	for _, raw := range []string{"ldaps://user:secret@dc.test:636/?token=secret#secret", "ldaps://user:%zz@dc.test"} {
		out := diagnosticURI(raw)
		if strings.Contains(out, "secret") || strings.Contains(out, "user:") {
			t.Fatalf("credential leaked: %s", out)
		}
	}
}
func TestStartupMissingConfigurationNoSecretLeak(t *testing.T) {
	t.Setenv("DIAGNOSTIC_TEST_PASSWORD", "private-test-secret")
	cfg := &config.Config{LDAP: config.LDAPConfig{URI: "ldaps://u:private-test-secret@127.0.0.1:1", Bind: config.BindConfig{Type: "simple", PasswordEnv: "DIAGNOSTIC_TEST_PASSWORD"}}}
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(old)
	c := ldapproto.NewServiceClient(cfg.LDAP, cfg.BindPassword)
	defer c.Close()
	if err := startupDiagnostics(cfg, c); err == nil {
		t.Fatal("missing base/account accepted")
	}
	log := buf.String()
	if strings.Contains(log, "private-test-secret") {
		t.Fatal("password leaked")
	}
	for _, want := range []string{"base DN missing", "service account missing", "password_set=true"} {
		if !strings.Contains(log, want) {
			t.Errorf("missing diagnostic %s", want)
		}
	}
}
