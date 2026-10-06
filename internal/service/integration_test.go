package service

import (
	"context"
	"os"
	"testing"
	"time"

	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
)

// Integration smoke against a live Samba DC. Skipped unless SAMBAADM_IT=1.
func TestIntegrationDomainInfo(t *testing.T) {
	if os.Getenv("SAMBAADM_IT") != "1" {
		t.Skip("set SAMBAADM_IT=1 to run")
	}
	uri := os.Getenv("SAMBAADM_IT_URI")
	user := os.Getenv("SAMBAADM_IT_USER")
	pass := os.Getenv("SAMBAADM_PASSWORD")
	if uri == "" || user == "" || pass == "" {
		t.Fatal("SAMBAADM_IT_URI, SAMBAADM_IT_USER, SAMBAADM_PASSWORD required")
	}
	cfg := config.LDAPConfig{
		URI:    uri,
		BaseDN: os.Getenv("SAMBAADM_IT_BASE"),
		Bind:   config.BindConfig{Type: "simple", User: user, PasswordEnv: "SAMBAADM_PASSWORD"},
	}
	if cfg.BaseDN == "" {
		cfg.BaseDN = "DC=sambaadm,DC=test"
	}
	client := ldapproto.NewClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.BindSimple(ctx, user, pass); err != nil {
		t.Fatal(err)
	}
	log, _ := audit.New("")
	svcs := NewWithOptions(client, log, ServiceOptions{})
	info, err := svcs.Domain.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.BaseDN == "" {
		t.Fatal("empty base DN")
	}
	t.Logf("domain base=%s dns=%s", info.BaseDN, info.DNSRoot)
}
