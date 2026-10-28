package service

import (
	"context"
	"encoding/json"
	"sambaadm/internal/config"
	"strings"
	"testing"
)

func TestDiagnosticsRedactsSecrets(t *testing.T) {
	t.Setenv("DIAGNOSTIC_TEST_PASSWORD", "secret-value")
	s := NewDiagnosticService(&config.Config{LDAP: config.LDAPConfig{URI: "ldaps://admin:uri-secret@dc.example.com", Bind: config.BindConfig{PasswordEnv: "DIAGNOSTIC_TEST_PASSWORD"}}})
	got := s.clean("failure secret-value ldaps://admin:uri-secret@dc.example.com")
	if strings.Contains(got, "secret-value") || strings.Contains(got, "uri-secret") {
		t.Fatalf("secret leaked: %s", got)
	}
}
func TestDiagnosticsMissingConfigAndBusy(t *testing.T) {
	t.Setenv("SAMBAADM_PASSWORD", "")
	s := NewDiagnosticService(&config.Config{})
	s.gate <- struct{}{}
	if _, err := s.Run(context.Background()); err == nil {
		t.Fatal("overlapping run accepted")
	}
	<-s.gate
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report, err := s.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Checks) < 8 {
		t.Fatal("missing checks")
	}
	for _, check := range report.Checks {
		if check.ID == "ldap" && check.Status != "error" {
			t.Fatal("missing credentials reported healthy")
		}
	}
	b, _ := json.Marshal(report)
	if strings.Contains(string(b), "password_env") {
		t.Fatal("configuration was serialized")
	}
}
