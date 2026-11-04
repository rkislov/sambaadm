package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sambaadm/internal/config"
	"strings"
	"testing"
	"time"
)

func executableCleanupPlan() *CleanupPlan {
	p := testCleanupPlan()
	p.Objects[0].DN = "CN=old," + SitesContainerDN(p.BaseDN)
	p.Objects[0].Attributes["objectClass"] = [][]byte{[]byte("site")}
	p.Objects[0].Findings = []TopologyFinding{{DN: p.Objects[0].DN}}
	p.Revision = cleanupRevision(p)
	return p
}

// The application integration uses a deterministic backup receipt fixture;
// native archive creation/recovery is independently exercised in the offline
// Samba container. This helper is test-only and never used by production code.
func seedVerifiedCleanupBackup(t *testing.T, cfg *config.Config, p *CleanupPlan, guid []byte) *DomainBackupJob {
	t.Helper()
	root, e := backupRoot(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	id := "00000000-0000-0000-0000-000000000011"
	if e = root.Mkdir(id, 0700); e != nil {
		t.Fatal(e)
	}
	req := DomainBackupRequest{ID: id, Controller: cfg.Helper.Node, DomainGUID: guid, BaseDN: p.BaseDN, PlanRevision: p.Revision, Plan: p}
	data := []byte("test fixture: archive recovery is tested separately")
	h := sha256.Sum256(data)
	job := &DomainBackupJob{DomainBackupRequest: req, Status: "backed_up", SHA256: hex.EncodeToString(h[:]), Archive: "domain.tar.gz", Bytes: int64(len(data)), Finished: time.Now().UTC(), RestoreVerified: true}
	for name, v := range map[string]any{"request.json": req, "status.json": job, "restore.json": BackupRestoreReceipt{Kind: backupRestoreKind, ID: id, SHA256: job.SHA256, PlanRevision: p.Revision, Status: "verified", Finished: time.Now().UTC()}} {
		if e = createBackupJSON(root, id+"/"+name, v); e != nil {
			t.Fatal(e)
		}
	}
	if e = root.WriteFile(id+"/domain.tar.gz", data, 0600); e != nil {
		t.Fatal(e)
	}
	return job
}
func TestCleanupApplyBackupGuards(t *testing.T) {
	p := executableCleanupPlan()
	cfg := &config.Config{}
	cfg.Helper.BackupRoot = t.TempDir()
	cfg.Helper.DomainBackupEnabled = true
	cfg.Helper.Node = "dc.example.com"
	job := seedVerifiedCleanupBackup(t, cfg, p, make([]byte, 16))
	if e := validateCleanupBackup(p, job); e != nil {
		t.Fatal(e)
	}
	job.RestoreVerified = false
	if validateCleanupBackup(p, job) == nil {
		t.Fatal("unverified backup accepted")
	}
	job.RestoreVerified = true
	job.Finished = time.Now().Add(-25 * time.Hour)
	if validateCleanupBackup(p, job) == nil {
		t.Fatal("old backup accepted")
	}
	op := HostOperation{Name: job.ID, Revision: p.Revision, Actor: "test"}
	if _, e := helperCleanupApply(context.Background(), cfg, "topology.cleanup.reserve", op); e != nil {
		t.Fatal(e)
	}
	if _, e := helperCleanupApply(context.Background(), cfg, "topology.cleanup.reserve", op); e == nil {
		t.Fatal("replay accepted")
	}
	root, e := backupRoot(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	root.Remove(job.ID + "/apply.json")
	if e = root.WriteFile(job.ID+"/domain.tar.gz", []byte(strings.Repeat("x", int(job.Bytes))), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = helperCleanupApply(context.Background(), cfg, "topology.cleanup.reserve", op); e == nil {
		t.Fatal("same-size archive corruption accepted")
	}
	root.Remove(job.ID + "/restore.json")
	status, e := localBackupStatus(context.Background(), root, job.ID)
	if e != nil {
		t.Fatal(e)
	}
	if status.RestoreVerified {
		t.Fatal("status boolean substituted for receipt")
	}
}
func TestCleanupApplyObjectAllowlist(t *testing.T) {
	p := executableCleanupPlan()
	if _, e := cleanupOrder(p); e != nil {
		t.Fatal(e)
	}
	p.Objects[0].Attributes["objectClass"] = [][]byte{[]byte("nTDSDSA")}
	if _, e := cleanupOrder(p); e == nil {
		t.Fatal("DC metadata accepted")
	}
	p = executableCleanupPlan()
	p.Objects[0].DN = "CN=old,DC=example,DC=com"
	if _, e := cleanupOrder(p); e == nil {
		t.Fatal("outside Sites accepted")
	}
	p = executableCleanupPlan()
	p.Objects = append(p.Objects, p.Objects[0])
	if _, e := cleanupOrder(p); e == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestIntegrationCleanupApply(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("requires disposable two-DC domain")
	}
	integrationCleanupApply(t)
}

func TestCleanupDCRemnantAllowlist(t *testing.T) {
	p := executableCleanupPlan()
	o := &p.Objects[0]
	o.DN = "CN=Retired,CN=Servers,CN=Old," + SitesContainerDN(p.BaseDN)
	o.Attributes["objectClass"] = [][]byte{[]byte("server")}
	o.Findings = []TopologyFinding{{DN: o.DN, Code: "server_without_ntds"}}
	if _, e := cleanupOrder(p); e != nil {
		t.Fatal(e)
	}
	o.Findings[0].Code = "unverified_server"
	if _, e := cleanupOrder(p); e == nil {
		t.Fatal("server without retirement evidence accepted")
	}
	o.DN = "CN=Retired,OU=Domain Controllers," + p.BaseDN
	o.Attributes["objectClass"] = [][]byte{[]byte("computer")}
	o.Attributes["userAccountControl"] = [][]byte{[]byte("8194")}
	o.Findings = []TopologyFinding{{DN: o.DN, Code: "dc_computer_without_server"}}
	if _, e := cleanupOrder(p); e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{"8192", "4098", "2", "invalid"} {
		o.Attributes["userAccountControl"] = [][]byte{[]byte(value)}
		if _, e := cleanupOrder(p); e == nil {
			t.Fatalf("unsafe account flags accepted: %s", value)
		}
	}
}

func TestCleanupHelperRequiresRetirementConfirmation(t *testing.T) {
	p := executableCleanupPlan()
	p.Objects[0].DN = "CN=Retired,CN=Servers,CN=Old," + SitesContainerDN(p.BaseDN)
	p.Objects[0].Attributes["objectClass"] = [][]byte{[]byte("server")}
	p.Objects[0].Findings = []TopologyFinding{{DN: p.Objects[0].DN, Code: "server_without_ntds"}}
	p.Revision = cleanupRevision(p)
	cfg := &config.Config{}
	cfg.Helper.BackupRoot = t.TempDir()
	cfg.Helper.DomainBackupEnabled = true
	cfg.Helper.Node = "dc.example.com"
	job := seedVerifiedCleanupBackup(t, cfg, p, make([]byte, 16))
	op := HostOperation{Name: job.ID, Revision: p.Revision, Actor: "operator"}
	if _, e := helperCleanupApply(context.Background(), cfg, "topology.cleanup.reserve", op); e == nil {
		t.Fatal("helper accepted remnant without retirement confirmation")
	}
	op.Value = "permanently-decommissioned"
	if _, e := helperCleanupApply(context.Background(), cfg, "topology.cleanup.reserve", op); e != nil {
		t.Fatal(e)
	}
	root, e := backupRoot(cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	var record map[string]any
	if e = readBackupJSON(root, job.ID+"/apply.json", &record); e != nil {
		t.Fatal(e)
	}
	if record["decommissionConfirmed"] != true || record["actor"] != "operator" {
		t.Fatal("retirement evidence missing", record)
	}
}

func TestCleanupRejectsLegacyRestoreReceipt(t *testing.T) {
	cfg := &config.Config{}
	cfg.Helper.BackupRoot = t.TempDir()
	cfg.Helper.DomainBackupEnabled = true
	cfg.Helper.Node = "dc.example.com"
	job := seedVerifiedCleanupBackup(t, cfg, executableCleanupPlan(), make([]byte, 16))
	root, err := backupRoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	receipt := BackupRestoreReceipt{ID: job.ID, SHA256: job.SHA256, PlanRevision: job.PlanRevision, Status: "verified", Finished: time.Now().UTC()}
	if err = root.Remove(job.ID + "/restore.json"); err != nil {
		t.Fatal(err)
	}
	if err = createBackupJSON(root, job.ID+"/restore.json", receipt); err != nil {
		t.Fatal(err)
	}
	got, err := localBackupStatus(context.Background(), root, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RestoreVerified {
		t.Fatal("legacy rehearsal receipt accepted")
	}
}
