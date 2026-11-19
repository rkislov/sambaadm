package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"sambaadm/internal/config"
)

//go:embed helper_domain_restore.py
var domainRestoreWorker string

type DomainRestoreInput struct {
	BackupID          string `json:"backupID"`
	NewName           string `json:"newName"`
	Address           string `json:"address"`
	ID                string `json:"id,omitempty"`
	Revision          string `json:"revision,omitempty"`
	ConfirmDomainLost bool   `json:"confirmDomainLost,omitempty"`
	ConfirmIsolated   bool   `json:"confirmIsolated,omitempty"`
}
type DomainRestorePlan struct {
	BackupCreated    time.Time `json:"backupCreated"`
	SourceBytes      int64     `json:"sourceBytes"`
	ID               string    `json:"id"`
	BackupID         string    `json:"backupID"`
	SHA256           string    `json:"sha256"`
	Archive          string    `json:"archive"`
	NewName          string    `json:"newName"`
	Controller       string    `json:"controller"`
	Address          string    `json:"address"`
	SourceController string    `json:"sourceController"`
	BaseDN           string    `json:"baseDN"`
	DomainGUID       []byte    `json:"domainGUID"`
	SambaVersion     string    `json:"sambaVersion,omitempty"`
	Target           string    `json:"target"`
	Config           string    `json:"config"`
	Created          time.Time `json:"created"`
	Revision         string    `json:"revision"`
}
type DomainRestoreJob struct {
	DomainRestorePlan
	Status           string                  `json:"status"`
	Started          time.Time               `json:"started,omitempty"`
	Finished         time.Time               `json:"finished,omitempty"`
	Activation       string                  `json:"activation"`
	Error            string                  `json:"error,omitempty"`
	DomainSID        string                  `json:"domainSID,omitempty"`
	InvocationID     string                  `json:"invocationID,omitempty"`
	LiveVerification *BackupLiveVerification `json:"liveVerification,omitempty"`
}

func restoreRevision(p DomainRestorePlan) string {
	p.Revision = ""
	sum := sha256.Sum256(hostInput(p))
	return hex.EncodeToString(sum[:])
}
func validateRestoreInput(in DomainRestoreInput) error {
	if !validBackupID(in.BackupID) || len(in.NewName) < 1 || len(in.NewName) > 15 || strings.EqualFold(in.NewName, "localhost") {
		return topologyBad("backup UUID and new NetBIOS DC name (1-15 characters) required")
	}
	for i, c := range in.NewName {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' && i > 0 && i < len(in.NewName)-1) {
			return topologyBad("invalid new DC name")
		}
	}
	ip, e := netip.ParseAddr(in.Address)
	if e != nil || !ip.Is4() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return topologyBad("explicit unicast IPv4 address for recovered DC required")
	}
	return nil
}
func restoreRoot(cfg *config.Config) (*os.Root, error) {
	if !cfg.Helper.DomainRestoreEnabled || !cfg.Helper.DomainBackupEnabled {
		return nil, topologyBad("helper.domain_restore_enabled and domain_backup_enabled are required")
	}
	dir := filepath.Clean(cfg.Helper.DomainRestoreRoot)
	if !filepath.IsAbs(dir) || dir == "/" {
		return nil, topologyBad("private absolute helper.domain_restore_root required")
	}
	backup := filepath.Clean(cfg.Helper.BackupRoot)
	if dir == backup || strings.HasPrefix(dir, backup+string(filepath.Separator)) || strings.HasPrefix(backup, dir+string(filepath.Separator)) {
		return nil, topologyBad("recovery and archive roots must not overlap")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode().Perm()&0066 != 0 {
		return nil, topologyBad("non-symlink recovery root without group/other read or write access required")
	}
	return os.OpenRoot(dir)
}
func restoreSource(ctx context.Context, cfg *config.Config, id string) (*DomainBackupJob, *os.Root, error) {
	root, err := backupRoot(cfg)
	if err != nil {
		return nil, nil, err
	}
	job, err := localBackupStatus(ctx, root, id)
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	if job.Bytes > 10<<30 || job.Purpose != "full" || job.Status != "backed_up" || !job.RestoreVerified {
		root.Close()
		return nil, nil, topologyBad("completed standalone full backup with verified recovery receipt required")
	}
	f, err := root.Open(id + "/domain.tar.gz")
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	defer f.Close()
	h := sha256.New()
	_, err = io.Copy(h, f)
	if err != nil {
		root.Close()
		return nil, nil, err
	}
	if hex.EncodeToString(h.Sum(nil)) != job.SHA256 {
		root.Close()
		return nil, nil, topologyBad("source archive checksum mismatch")
	}
	return job, root, nil
}
func restoreManifest(root *os.Root, id string) (string, error) {
	f, err := root.Open(id + "/domain.tar.gz")
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, (10<<30)+(64<<20)))
	for {
		hdr, err := tr.Next()
		if err != nil {
			return "", fmt.Errorf("cannot read recovery manifest: %w", err)
		}
		if hdr.Name != "manifest.json" {
			continue
		}
		if hdr.Size > 64<<20 {
			return "", topologyBad("manifest too large")
		}
		var m struct {
			Format       string `json:"format"`
			SambaVersion string `json:"sambaVersion"`
		}
		if err = json.NewDecoder(tr).Decode(&m); err != nil {
			return "", err
		}
		if m.Format != "sambaadm-cold-dc-v1" {
			return "", topologyBad("unsupported cold archive")
		}
		return m.SambaVersion, nil
	}
}
func helperDomainRestore(ctx context.Context, cfg *config.Config, method string, in HostOperation) (any, error) {
	root, err := restoreRoot(cfg)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if method == "domain.restore.status" {
		return localRestoreStatus(ctx, root, in.Name)
	}
	var input DomainRestoreInput
	if err = decodeHost(in.Input, &input); err != nil {
		return nil, err
	}
	if method == "domain.restore.plan" {
		if err = validateRestoreInput(input); err != nil {
			return nil, err
		}
		job, source, err := restoreSource(ctx, cfg, input.BackupID)
		if err != nil {
			return nil, err
		}
		defer source.Close()
		version, err := restoreManifest(source, input.BackupID)
		if err != nil {
			return nil, err
		}
		domain := dnsFromBaseDN(job.BaseDN)
		controller := strings.ToLower(input.NewName) + "." + domain
		if _, err = backupHostFile(controller); err != nil {
			return nil, err
		}
		if strings.EqualFold(job.Controller, controller) {
			return nil, topologyBad("new DC name must differ from the source")
		}
		id := uuid.NewString()
		target := filepath.Join(cfg.Helper.DomainRestoreRoot, id, "dc")
		p := DomainRestorePlan{BackupCreated: job.Finished, SourceBytes: job.Bytes, ID: id, BackupID: input.BackupID, SHA256: job.SHA256, Archive: filepath.Join(cfg.Helper.BackupRoot, "domain-backups", input.BackupID, "domain.tar.gz"), NewName: strings.ToUpper(input.NewName), Controller: controller, Address: input.Address, SourceController: job.Controller, BaseDN: job.BaseDN, DomainGUID: job.DomainGUID, SambaVersion: version, Target: target, Config: filepath.Join(target, "etc", "smb.conf"), Created: time.Now().UTC()}
		p.Revision = restoreRevision(p)
		if err = root.Mkdir(id, 0700); err != nil {
			return nil, err
		}
		if err = createBackupJSON(root, id+"/request.json", p); err != nil {
			return nil, err
		}
		return &p, nil
	}
	if !validBackupID(input.ID) {
		return nil, topologyBad("valid recovery plan ID required")
	}
	var p DomainRestorePlan
	if err = readBackupJSON(root, input.ID+"/request.json", &p); err != nil {
		return nil, err
	}
	if p.ID != input.ID || p.Revision != input.Revision || p.Revision != restoreRevision(p) {
		return nil, ErrTopologyConflict
	}
	if !input.ConfirmDomainLost || !input.ConfirmIsolated {
		return nil, topologyBad("confirmDomainLost and confirmIsolated required; all former DCs must be shut down")
	}
	// A previous launch is one-use, including failures: never overwrite a target.
	if _, err = root.Lstat(p.ID + "/launch.json"); err == nil {
		return localRestoreStatus(ctx, root, p.ID)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if time.Since(p.Created) > time.Hour || p.Created.After(time.Now().Add(time.Minute)) {
		return nil, topologyBad("recovery preview expired; prepare again")
	}
	job, source, err := restoreSource(ctx, cfg, p.BackupID)
	if err != nil {
		return nil, err
	}
	source.Close()
	if job.SHA256 != p.SHA256 {
		return nil, ErrTopologyConflict
	}
	if _, err = root.Lstat(p.ID + "/dc"); !os.IsNotExist(err) {
		return nil, topologyBad("recovery target already exists")
	}
	// One active recovery at a time; status must be resolved after interruption.
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, err := dir.ReadDir(1001)
	dir.Close()
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(entries) > 1000 {
		return nil, topologyBad("recovery history limit reached")
	}
	for _, entry := range entries {
		if !validBackupID(entry.Name()) || entry.Name() == p.ID {
			continue
		}
		status, err := localRestoreStatus(ctx, root, entry.Name())
		if err != nil {
			return nil, err
		}
		if status.Status == "queued" || status.Status == "running" || status.Status == "unknown" {
			return nil, topologyBad("another recovery is unfinished")
		}
	}
	runner, err := exec.LookPath("systemd-run")
	if err != nil {
		return nil, topologyBad("systemd-run required")
	}
	hosts, err := backupHostFile(p.Controller)
	if err != nil {
		return nil, err
	}
	for name, data := range map[string][]byte{"backup_worker.py": []byte(domainBackupWorker), "restore_worker.py": []byte(domainRestoreWorker), "hosts": hosts} {
		if err = root.WriteFile(p.ID+"/"+name, data, 0600); err != nil {
			return nil, err
		}
	}
	if err = createBackupJSON(root, p.ID+"/launch.json", map[string]any{"revision": p.Revision, "time": time.Now().UTC()}); err != nil {
		return nil, err
	}
	jobDir := filepath.Join(cfg.Helper.DomainRestoreRoot, p.ID)
	args := []string{"--quiet", "--unit=" + restoreUnit(p.ID), "--property=Type=exec", "--property=UMask=0077", "--property=PrivateNetwork=yes", "--property=PrivateTmp=yes", "--property=TemporaryFileSystem=/run", "--property=BindReadOnlyPaths=" + fmt.Sprintf("%q", filepath.Join(jobDir, "hosts")+":/etc/hosts"), "--property=RuntimeMaxSec=1800", "--property=KillMode=control-group", "--property=StandardOutput=null", "--property=StandardError=null", "--", "/usr/bin/python3", filepath.Join(jobDir, "restore_worker.py"), jobDir}
	if err = exec.CommandContext(ctx, runner, args...).Run(); err != nil {
		return nil, fmt.Errorf("recovery launch unconfirmed; inspect status before retrying")
	}
	return &DomainRestoreJob{DomainRestorePlan: p, Status: "queued", Activation: "manual"}, nil
}
func restoreUnit(id string) string { return "sambaadm-domain-restore-" + id + ".service" }
func localRestoreStatus(ctx context.Context, root *os.Root, id string) (*DomainRestoreJob, error) {
	if !validBackupID(id) {
		return nil, topologyBad("valid recovery UUID required")
	}
	var p DomainRestorePlan
	if err := readBackupJSON(root, id+"/request.json", &p); err != nil {
		return nil, err
	}
	if p.ID != id || p.Revision != restoreRevision(p) {
		return nil, ErrTopologyConflict
	}
	out := &DomainRestoreJob{DomainRestorePlan: p, Status: "planned", Activation: "manual"}
	err := readBackupJSON(root, id+"/status.json", out)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	// Worker may add result fields but must retain the exact persisted plan.
	if string(hostInput(out.DomainRestorePlan)) != string(hostInput(p)) {
		return nil, fmt.Errorf("recovery job identity mismatch")
	}
	if os.IsNotExist(err) {
		if _, e := root.Lstat(id + "/launch.json"); e == nil {
			out.Status = "queued"
		} else if !os.IsNotExist(e) {
			return nil, e
		}
	}
	if out.Status == "queued" || out.Status == "running" {
		active, e := unitActive(ctx, restoreUnit(id))
		if e != nil {
			out.Status = "unknown"
			out.Error = e.Error()
		} else if !active {
			out.Status = "interrupted"
			out.Error = "Worker is inactive; do not activate a partial target"
		}
	}
	if out.Status == "ready" && (!out.LiveVerification.verified() || out.InvocationID == "" || out.Activation != "manual") {
		return nil, topologyBad("incomplete recovery verification")
	}
	return out, nil
}
