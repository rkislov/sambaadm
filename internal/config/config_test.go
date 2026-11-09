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

func TestRepairRetentionConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(p, []byte("logging:\n  level: info\n"), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := Load(p)
	if e != nil || c.GPO.RepairBackupKeep != 10 || c.GPO.RepairBackupMaxMiB != 512 {
		t.Fatalf("defaults: %+v %v", c, e)
	}
	t.Setenv("SAMBAADM_GPO_REPAIR_BACKUP_KEEP", "2")
	t.Setenv("SAMBAADM_GPO_REPAIR_BACKUP_MAX_MIB", "128")
	c, e = Load(p)
	if e != nil || c.GPO.RepairBackupKeep != 2 || c.GPO.RepairBackupMaxMiB != 128 {
		t.Fatalf("environment: %+v %v", c, e)
	}
	for _, value := range []string{"0", "101", "-1"} {
		t.Setenv("SAMBAADM_GPO_REPAIR_BACKUP_KEEP", value)
		if _, e := Load(p); e == nil {
			t.Fatal("invalid keep accepted", value)
		}
	}
	t.Setenv("SAMBAADM_GPO_REPAIR_BACKUP_KEEP", "2")
	for _, value := range []string{"0", "10241", "-1"} {
		t.Setenv("SAMBAADM_GPO_REPAIR_BACKUP_MAX_MIB", value)
		if _, e := Load(p); e == nil {
			t.Fatal("invalid budget accepted", value)
		}
	}
}

func TestReplicationTimeoutConfiguration(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("logging:\n  level: info\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil || cfg.GPO.ReplicationTimeout.String() != "5m0s" {
		t.Fatalf("default: %+v %v", cfg, err)
	}
	t.Setenv("SAMBAADM_GPO_REPLICATION_TIMEOUT", "10m")
	cfg, err = Load(p)
	if err != nil || cfg.GPO.ReplicationTimeout.String() != "10m0s" {
		t.Fatalf("override: %+v %v", cfg, err)
	}
	for _, invalid := range []string{"0s", "-1s", "31m", "garbage"} {
		t.Setenv("SAMBAADM_GPO_REPLICATION_TIMEOUT", invalid)
		if _, err := Load(p); err == nil {
			t.Errorf("accepted timeout %s", invalid)
		}
	}
}
