package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
)

func fullBackupFixture() DomainBackupRequest {
	r := DomainBackupRequest{Purpose: "full", PreparedAt: time.Now().UTC(), ID: uuid.NewString(), Controller: "dc.example.com", DomainGUID: make([]byte, 16), BaseDN: "DC=example,DC=com"}
	r.PlanRevision = fullBackupRevision(r)
	return r
}
func TestFullBackupPurposeAndExpiration(t *testing.T) {
	good := fullBackupFixture()
	if err := validateBackupPurpose(good, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"expired", "future", "plan", "hash", "purpose"} {
		t.Run(scenario, func(t *testing.T) {
			r := good
			switch scenario {
			case "expired":
				r.PreparedAt = time.Now().Add(-25 * time.Hour)
				r.PlanRevision = fullBackupRevision(r)
			case "future":
				r.PreparedAt = time.Now().Add(time.Hour)
				r.PlanRevision = fullBackupRevision(r)
			case "plan":
				r.Plan = &CleanupPlan{}
				r.PlanRevision = fullBackupRevision(r)
			case "hash":
				r.Controller = "other.example.com"
			case "purpose":
				r.Purpose = "unknown"
			}
			if err := validateBackupPurpose(r, time.Now()); err == nil {
				t.Fatal("invalid preparation accepted")
			}
		})
	}
	if expectedBackupRestoreKind(good) == backupRestoreKind {
		t.Fatal("full backup can masquerade as cleanup rehearsal")
	}
}
func TestFullBackupStartAndStatusWorkWithoutLDAP(t *testing.T) {
	cfg := &config.Config{Helper: config.HelperServerConfig{Node: "dc.example.com", BackupRoot: t.TempDir(), DomainBackupEnabled: true}}
	logger, err := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	backend := &Services{Audit: logger}
	helper := testHelperClient(t, backend, cfg)
	svc := &FullBackupService{Sites: &SiteService{helpers: helper}, Store: &ObjectBackupService{root: filepath.Join(t.TempDir(), "store")}}
	r := fullBackupFixture()
	root, err := svc.Store.store(true)
	if err != nil {
		t.Fatal(err)
	}
	if err = createBackupJSON(root, fullPlanName(r.ID), r); err != nil {
		t.Fatal(err)
	}
	root.Close()
	jobs, err := backupRoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	if err = jobs.Mkdir(r.ID, 0700); err != nil {
		t.Fatal(err)
	}
	if err = createBackupJSON(jobs, r.ID+"/request.json", r); err != nil {
		t.Fatal(err)
	}
	if err = jobs.WriteFile(r.ID+"/domain.tar.gz", make([]byte, 100), 0600); err != nil {
		t.Fatal(err)
	}
	job := DomainBackupJob{DomainBackupRequest: r, Status: "backed_up", SHA256: strings.Repeat("a", 64), Bytes: 100, Archive: "domain.tar.gz", Finished: time.Now()}
	if err = createBackupJSON(jobs, r.ID+"/status.json", job); err != nil {
		t.Fatal(err)
	}
	live := &BackupLiveVerification{DCStarted: true, UserLogin: true, InvalidPasswordRejected: true, SYSVOLRead: true, KerberosTGT: true, KerberosLDAP: true, KerberosSYSVOL: true, Authentication: "temporary-user-ntlm-and-kerberos", SYSVOLPath: "example.com/Policies/default/GPT.INI"}
	receipt := BackupRestoreReceipt{ID: r.ID, SHA256: job.SHA256, PlanRevision: r.PlanRevision, Kind: fullBackupRestoreKind, Status: "verified", Finished: time.Now(), Live: live}
	if err = createBackupJSON(jobs, r.ID+"/restore.json", receipt); err != nil {
		t.Fatal(err)
	}
	// A retry must read the same durable job, not launch another worker. LDAP
	// is deliberately nil, modelling the selected DC being stopped.
	out, err := svc.Start(context.Background(), r.ID, r.PlanRevision, "test", "")
	if err != nil || !out.RestoreVerified {
		t.Fatalf("start replay: %+v %v", out, err)
	}
	out, err = svc.Status(context.Background(), r.ID)
	if err != nil || !out.RestoreVerified {
		t.Fatalf("offline status: %+v %v", out, err)
	}
	if err = validateCleanupBackup(&CleanupPlan{Revision: r.PlanRevision}, out); err == nil {
		t.Fatal("full backup accepted as cleanup authorization")
	}
	if _, err = svc.Start(context.Background(), r.ID, "stale", "test", ""); err == nil {
		t.Fatal("stale revision accepted")
	}
	list, err := svc.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("history: %+v %v", list, err)
	}
	// Cleanup receipts are not evidence for standalone jobs either.
	if err = jobs.Remove(r.ID + "/restore.json"); err != nil {
		t.Fatal(err)
	}
	receipt.Kind = backupRestoreKind
	if err = createBackupJSON(jobs, r.ID+"/restore.json", receipt); err != nil {
		t.Fatal(err)
	}
	out, err = svc.Status(context.Background(), r.ID)
	if err != nil || out.RestoreVerified {
		t.Fatalf("wrong receipt kind accepted: %+v %v", out, err)
	}
	if _, err = svc.Load("../outside"); err == nil {
		t.Fatal("path traversal accepted")
	}
	if err = os.Chmod(filepath.Join(svc.Store.root, fullPlanName(r.ID)), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Load(r.ID); err == nil {
		t.Fatal("public preparation accepted")
	}
}
