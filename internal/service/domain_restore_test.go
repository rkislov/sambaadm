package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"sambaadm/internal/config"
	"strings"
	"testing"
	"time"
)

func TestDomainRestoreInputAndRootGuards(t *testing.T) {
	valid := DomainRestoreInput{BackupID: uuid.NewString(), NewName: "RECOVER", Address: "192.0.2.10"}
	if err := validateRestoreInput(valid); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "../dc", "dc;rm", "-dc", "dc-", "localhost", "1234567890123456"} {
		bad := valid
		bad.NewName = name
		if err := validateRestoreInput(bad); err == nil {
			t.Fatalf("bad name accepted: %s", name)
		}
	}
	for _, address := range []string{"", "127.0.0.1", "0.0.0.0", "::1", "224.0.0.1", "169.254.1.2"} {
		bad := valid
		bad.Address = address
		if err := validateRestoreInput(bad); err == nil {
			t.Fatalf("bad address accepted: %s", address)
		}
	}
	cfg := &config.Config{}
	if _, err := restoreRoot(cfg); err == nil {
		t.Fatal("disabled recovery accepted")
	}
	cfg.Helper.DomainRestoreEnabled = true
	cfg.Helper.DomainBackupEnabled = true
	cfg.Helper.BackupRoot = t.TempDir()
	cfg.Helper.DomainRestoreRoot = cfg.Helper.BackupRoot
	if _, err := restoreRoot(cfg); err == nil {
		t.Fatal("overlapping roots accepted")
	}
	cfg.Helper.DomainRestoreRoot = filepath.Join(t.TempDir(), "recovery")
	root, err := restoreRoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	if err = os.Chmod(cfg.Helper.DomainRestoreRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err = restoreRoot(cfg); err == nil {
		t.Fatal("public recovery root accepted")
	}
}
func restoreFixture(t *testing.T) (*config.Config, *DomainBackupJob) {
	t.Helper()
	cfg := &config.Config{Helper: config.HelperServerConfig{DomainBackupEnabled: true, DomainRestoreEnabled: true, BackupRoot: t.TempDir(), DomainRestoreRoot: filepath.Join(t.TempDir(), "recovery")}}
	root, err := backupRoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	request := fullBackupFixture()
	if err = root.Mkdir(request.ID, 0700); err != nil {
		t.Fatal(err)
	}
	if err = createBackupJSON(root, request.ID+"/request.json", request); err != nil {
		t.Fatal(err)
	}
	file, err := root.OpenFile(request.ID+"/domain.tar.gz", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	manifest := []byte(`{"format":"sambaadm-cold-dc-v1","sambaVersion":"4.17.12"}`)
	if err = tw.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(manifest)), Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	if _, err = tw.Write(manifest); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	file.Close()
	data, err := root.ReadFile(request.ID + "/domain.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	job := &DomainBackupJob{DomainBackupRequest: request, Status: "backed_up", Archive: "domain.tar.gz", Bytes: int64(len(data)), SHA256: hex.EncodeToString(digest[:]), Finished: time.Now()}
	if err = createBackupJSON(root, request.ID+"/status.json", job); err != nil {
		t.Fatal(err)
	}
	live := &BackupLiveVerification{DCStarted: true, UserLogin: true, InvalidPasswordRejected: true, SYSVOLRead: true, KerberosTGT: true, KerberosLDAP: true, KerberosSYSVOL: true, Authentication: "temporary-user-ntlm-and-kerberos", SYSVOLPath: "example.com/Policies/default/GPT.INI"}
	receipt := BackupRestoreReceipt{ID: request.ID, SHA256: job.SHA256, PlanRevision: request.PlanRevision, Kind: fullBackupRestoreKind, Status: "verified", Finished: time.Now(), Live: live}
	if err = createBackupJSON(root, request.ID+"/restore.json", receipt); err != nil {
		t.Fatal(err)
	}
	return cfg, job
}
func TestDomainRestorePlanAndFailureGuardsWithoutLDAP(t *testing.T) {
	ctx := context.Background()
	cfg, backup := restoreFixture(t)
	input := DomainRestoreInput{BackupID: backup.ID, NewName: "RECOVER", Address: "192.0.2.10"}
	out, err := helperDomainRestore(ctx, cfg, "domain.restore.plan", HostOperation{Input: hostInput(input)})
	if err != nil {
		t.Fatal(err)
	}
	plan := out.(*DomainRestorePlan)
	if plan.SambaVersion != "4.17.12" || plan.Controller != "recover.example.com" || !strings.HasPrefix(plan.Target, cfg.Helper.DomainRestoreRoot) {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if _, err = os.Stat(plan.Target); !os.IsNotExist(err) {
		t.Fatal("plan wrote recovery data")
	}
	start := DomainRestoreInput{ID: plan.ID, Revision: plan.Revision}
	if _, err = helperDomainRestore(ctx, cfg, "domain.restore.start", HostOperation{Input: hostInput(start)}); err == nil {
		t.Fatal("missing confirmations accepted")
	}
	start.ConfirmDomainLost = true
	start.ConfirmIsolated = true
	start.Revision = "stale"
	if _, err = helperDomainRestore(ctx, cfg, "domain.restore.start", HostOperation{Input: hostInput(start)}); err == nil {
		t.Fatal("stale preview accepted")
	}
	start.Revision = plan.Revision
	root, err := restoreRoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	status, err := localRestoreStatus(ctx, root, plan.ID)
	if err != nil || status.Status != "planned" {
		t.Fatalf("planned status: %+v %v", status, err)
	}
	if err = os.WriteFile(plan.Archive, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = helperDomainRestore(ctx, cfg, "domain.restore.start", HostOperation{Input: hostInput(start)}); err == nil {
		t.Fatal("modified archive accepted")
	}
	if _, err = root.Lstat(plan.ID + "/launch.json"); !os.IsNotExist(err) {
		t.Fatal("corrupt source launched")
	}
	if _, err = localRestoreStatus(ctx, root, "../outside"); err == nil {
		t.Fatal("invalid recovery UUID accepted")
	}
}
func TestDomainRestoreCompletedIdentityAndOneUse(t *testing.T) {
	cfg, backup := restoreFixture(t)
	ctx := context.Background()
	out, err := helperDomainRestore(ctx, cfg, "domain.restore.plan", HostOperation{Input: hostInput(DomainRestoreInput{BackupID: backup.ID, NewName: "RECOVER", Address: "192.0.2.10"})})
	if err != nil {
		t.Fatal(err)
	}
	p := out.(*DomainRestorePlan)
	root, err := restoreRoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	job := DomainRestoreJob{DomainRestorePlan: *p, Status: "ready", Activation: "manual", InvocationID: uuid.NewString(), LiveVerification: &BackupLiveVerification{DCStarted: true, UserLogin: true, InvalidPasswordRejected: true, SYSVOLRead: true, KerberosTGT: true, KerberosLDAP: true, KerberosSYSVOL: true, Authentication: "temporary-user-ntlm-and-kerberos", SYSVOLPath: "example.com/Policies/default/GPT.INI"}}
	if err = createBackupJSON(root, p.ID+"/status.json", job); err != nil {
		t.Fatal(err)
	}
	if err = createBackupJSON(root, p.ID+"/launch.json", map[string]string{"revision": p.Revision}); err != nil {
		t.Fatal(err)
	}
	start := DomainRestoreInput{ID: p.ID, Revision: p.Revision, ConfirmDomainLost: true, ConfirmIsolated: true}
	replay, err := helperDomainRestore(ctx, cfg, "domain.restore.start", HostOperation{Input: hostInput(start)})
	if err != nil || replay.(*DomainRestoreJob).Status != "ready" {
		t.Fatalf("one-use replay: %+v %v", replay, err)
	}
	if err = root.Remove(p.ID + "/status.json"); err != nil {
		t.Fatal(err)
	}
	job.DomainRestorePlan.Target = "/unexpected"
	if err = createBackupJSON(root, p.ID+"/status.json", job); err != nil {
		t.Fatal(err)
	}
	if _, err = localRestoreStatus(ctx, root, p.ID); err == nil {
		t.Fatal("worker changed target identity")
	}
}
