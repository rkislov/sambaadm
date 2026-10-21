package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnvironmentFieldsWithoutFileKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(p, []byte("logging:\n  level: info\n"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("SAMBAADM_LDAP_BASE_DN", "DC=test,DC=example")
	t.Setenv("SAMBAADM_LDAP_BIND_USER", "svc@test.example")
	t.Setenv("SAMBAADM_LOGGING_LEVEL", "debug")
	t.Setenv("SAMBAADM_LOGGING_FILE", "/tmp/events.log")
	c, e := Load(p)
	if e != nil {
		t.Fatal(e)
	}
	if c.LDAP.BaseDN != "DC=test,DC=example" || c.LDAP.Bind.User != "svc@test.example" || c.Logging.Level != "debug" || c.Logging.File != "/tmp/events.log" || c.Source != p {
		t.Fatalf("environment settings not applied: %+v", c)
	}
}
func TestMalformedDefaultConfigFails(t *testing.T) {
	t.Chdir(t.TempDir())
	if e := os.WriteFile("config.yaml", []byte("ldap: [broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(""); e == nil {
		t.Fatal("silently ignored invalid config")
	}
}
