package service

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"strconv"
	"strings"
	"time"
)

//go:embed helper_domain_backup.py
var domainBackupWorker string

type DomainBackupRequest struct {
	ID           string       `json:"id"`
	Controller   string       `json:"controller"`
	DomainGUID   []byte       `json:"domainGUID"`
	BaseDN       string       `json:"baseDN"`
	PlanRevision string       `json:"planRevision"`
	Plan         *CleanupPlan `json:"plan,omitempty"`
}
type DomainBackupJob struct {
	Format string `json:"format,omitempty"`
	DomainBackupRequest
	Status           string                  `json:"status"`
	Started          time.Time               `json:"started,omitempty"`
	Finished         time.Time               `json:"finished,omitempty"`
	SHA256           string                  `json:"sha256,omitempty"`
	Bytes            int64                   `json:"bytes,omitempty"`
	Archive          string                  `json:"archive,omitempty"`
	Error            string                  `json:"error,omitempty"`
	LiveVerification *BackupLiveVerification `json:"liveVerification,omitempty"`
	RestoreVerified  bool                    `json:"restoreVerified"`
	ApplyEvents      []CleanupApplyEvent     `json:"applyEvents,omitempty"`
	ApplyReserved    bool                    `json:"applyReserved"`
}
type CleanupBackupRequest struct {
	CleanupRequest
	ID         string `json:"id"`
	Controller string `json:"controller"`
}

func validBackupID(id string) bool { v, e := uuid.Parse(id); return e == nil && v.String() == id }
func (s *SiteService) StartDomainBackup(ctx context.Context, in CleanupBackupRequest) (*DomainBackupJob, error) {
	if !validBackupID(in.ID) {
		return nil, topologyBad("valid job UUID required")
	}
	p, e := s.PreviewCleanup(ctx, in.DNs)
	if e != nil {
		return nil, e
	}
	if p.Revision != in.Revision {
		return nil, ErrTopologyConflict
	}
	if _, e = cleanupOrder(p); e != nil {
		return nil, e
	}
	dc, e := s.controller(ctx, in.Controller)
	if e != nil {
		return nil, e
	}
	if cleanupRetiredController(p, *dc) {
		return nil, topologyBad("backup must be on a surviving DC")
	}
	if dc.RODC {
		return nil, topologyBad("writable DC required")
	}
	entry, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: s.ldap.BaseDN(), Scope: ldapproto.ScopeBase(), Filter: "(objectClass=domainDNS)", Attributes: []string{"objectGUID"}, MaxEntries: 1})
	if e != nil {
		return nil, e
	}
	guid := entry.GetRawAttributeValue("objectGUID")
	if len(guid) != 16 {
		return nil, topologyBad("domain identity unavailable")
	}
	if s.helpers == nil {
		return nil, topologyBad("helper is required")
	}
	var out DomainBackupJob
	e = s.helpers.Call(ctx, dc.DNS, "domain.backup.start", HostOperation{Input: hostInput(DomainBackupRequest{ID: in.ID, Controller: dc.DNS, DomainGUID: guid, BaseDN: s.ldap.BaseDN(), PlanRevision: p.Revision, Plan: p})}, &out)
	return &out, e
}
func (s *SiteService) DomainBackupStatus(ctx context.Context, controller, id string) (*DomainBackupJob, error) {
	if !validBackupID(id) {
		return nil, topologyBad("valid job UUID required")
	}
	dc, e := s.controller(ctx, controller)
	if e != nil {
		return nil, e
	}
	if s.helpers == nil {
		return nil, topologyBad("helper is required")
	}
	var out DomainBackupJob
	e = s.helpers.Call(ctx, dc.DNS, "domain.backup.status", HostOperation{Name: id}, &out)
	return &out, e
}
func backupRoot(cfg *config.Config) (*os.Root, error) {
	if !cfg.Helper.DomainBackupEnabled {
		return nil, fmt.Errorf("helper.domain_backup_enabled is required")
	}
	if !filepath.IsAbs(cfg.Helper.BackupRoot) {
		return nil, fmt.Errorf("absolute backup root required")
	}
	root, e := os.OpenRoot(cfg.Helper.BackupRoot)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	if e = root.Mkdir("domain-backups", 0700); e != nil && !os.IsExist(e) {
		return nil, e
	}
	st, e := root.Lstat("domain-backups")
	if e != nil {
		return nil, e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("private backup directory required")
	}
	return root.OpenRoot("domain-backups")
}
func readBackupJSON(root *os.Root, name string, out any) error {
	st, e := root.Lstat(name)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > cleanupSnapshotLimit {
		return fmt.Errorf("invalid private job record")
	}
	data, e := root.ReadFile(name)
	if e != nil {
		return e
	}
	return json.Unmarshal(data, out)
}
func createBackupJSON(root *os.Root, name string, value any) error {
	data, e := json.Marshal(value)
	if e != nil {
		return e
	}
	f, e := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(data)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	d, e := root.Open(".")
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}

// Only a DNS hostname can be placed in the isolated hosts file or used as a
// Kerberos service target. In particular, reject addresses and config syntax.
func backupHostFile(controller string) ([]byte, error) {
	labels := strings.Split(controller, ".")
	if len(controller) > 253 || len(labels) < 2 {
		return nil, topologyBad("controller FQDN required")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return nil, topologyBad("invalid controller FQDN")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return nil, topologyBad("invalid controller FQDN")
			}
		}
	}
	if net.ParseIP(controller) != nil {
		return nil, topologyBad("controller FQDN required")
	}
	return []byte("127.0.0.1 localhost\n127.0.0.1 " + strings.ToLower(controller) + " " + strings.ToLower(labels[0]) + "\n::1 localhost\n"), nil
}

func backupUnit(id string) string { return "sambaadm-domain-backup-" + id + ".service" }
func backupActive(ctx context.Context, id string) (bool, error) {
	cmd := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", backupUnit(id), "--property=LoadState", "--property=ActiveState")
	data, e := cmd.Output()
	if e != nil {
		return false, fmt.Errorf("cannot determine backup unit status")
	}
	text := string(data)
	if strings.Contains(text, "LoadState=not-found") {
		return false, nil
	}
	return strings.Contains(text, "ActiveState=active") || strings.Contains(text, "ActiveState=activating") || strings.Contains(text, "ActiveState=deactivating"), nil
}
func helperDomainBackup(ctx context.Context, cfg *config.Config, method string, in HostOperation) (any, error) {
	root, e := backupRoot(cfg)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	if method == "domain.backup.status" {
		return localBackupStatus(ctx, root, in.Name)
	}
	var request DomainBackupRequest
	if e = decodeHost(in.Input, &request); e != nil {
		return nil, e
	}
	hash, he := hex.DecodeString(request.PlanRevision)
	if !validBackupID(request.ID) || !strings.EqualFold(request.Controller, cfg.Helper.Node) || len(request.DomainGUID) != 16 || he != nil || len(hash) != 32 || request.BaseDN == "" {
		return nil, topologyBad("invalid backup request")
	}
	if _, e = root.Lstat(request.ID); e == nil {
		var previous DomainBackupRequest
		if e = readBackupJSON(root, request.ID+"/request.json", &previous); e != nil {
			return nil, e
		}
		if string(hostInput(previous)) != string(hostInput(request)) {
			return nil, ErrTopologyConflict
		}
		return localBackupStatus(ctx, root, request.ID)
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if request.Plan == nil || request.Plan.Revision != request.PlanRevision {
		return nil, topologyBad("cleanup plan required for verified backup")
	}
	// Global helper dispatch lock serializes creation. No second unfinished worker.
	dir, e := root.Open(".")
	if e != nil {
		return nil, e
	}
	entries, e := dir.ReadDir(1001)
	dir.Close()
	if e != nil && e != io.EOF {
		return nil, e
	}
	if len(entries) > 1000 {
		return nil, fmt.Errorf("backup history limit reached")
	}
	for _, entry := range entries {
		if validBackupID(entry.Name()) {
			job, e := localBackupStatus(ctx, root, entry.Name())
			if e != nil {
				return nil, e
			}
			if job.Status == "running" || job.Status == "queued" || job.Status == "unknown" {
				return nil, fmt.Errorf("another backup is unfinished")
			}
		}
	}
	executable, e := exec.LookPath("systemd-run")
	if e != nil {
		return nil, fmt.Errorf("systemd-run is required")
	}
	conf := cfg.Samba.SMBConf
	if conf == "" {
		conf = "/etc/samba/smb.conf"
	}
	if !filepath.IsAbs(conf) {
		return nil, fmt.Errorf("absolute samba.smb_conf required")
	}
	hosts, e := backupHostFile(request.Controller)
	if e != nil {
		return nil, e
	}
	if e = root.Mkdir(request.ID, 0700); e != nil {
		return nil, e
	}
	if e = createBackupJSON(root, request.ID+"/request.json", request); e != nil {
		return nil, e
	}
	if e = root.WriteFile(request.ID+"/hosts", hosts, 0644); e != nil {
		return nil, e
	}
	jobDir := filepath.Join(cfg.Helper.BackupRoot, "domain-backups", request.ID)
	args := []string{"--quiet", "--unit=" + backupUnit(request.ID), "--property=Type=exec", "--property=UMask=0077", "--property=PrivateNetwork=yes", "--property=PrivateTmp=yes", "--property=TemporaryFileSystem=/run", "--property=BindReadOnlyPaths=" + strconv.Quote(filepath.Join(jobDir, "hosts")+":/etc/hosts"), "--property=RuntimeMaxSec=900", "--property=KillMode=control-group", "--property=InaccessiblePaths=-/usr/bin/samba-tool", "--property=StandardOutput=null", "--property=StandardError=null", "--", "/usr/bin/python3", "-c", domainBackupWorker, jobDir, conf}
	if e = exec.CommandContext(ctx, executable, args...).Run(); e != nil {
		return nil, fmt.Errorf("backup launch unconfirmed; check job status before retrying")
	}
	return &DomainBackupJob{DomainBackupRequest: request, Status: "queued"}, nil
}
func localBackupStatus(ctx context.Context, root *os.Root, id string) (*DomainBackupJob, error) {
	if !validBackupID(id) {
		return nil, topologyBad("valid job UUID required")
	}
	var request DomainBackupRequest
	if e := readBackupJSON(root, id+"/request.json", &request); e != nil {
		return nil, e
	}
	job := &DomainBackupJob{DomainBackupRequest: request, Status: "queued"}
	e := readBackupJSON(root, id+"/status.json", job)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}

	if request.ID != id || string(hostInput(job.DomainBackupRequest)) != string(hostInput(request)) {
		return nil, fmt.Errorf("backup job identity mismatch")
	}
	// Restore evidence is a separate private worker receipt bound to exact archive
	// bytes and plan; never trust the status boolean supplied by the worker alone.
	job.RestoreVerified = false
	job.LiveVerification = nil
	var receipt BackupRestoreReceipt
	if err := readBackupJSON(root, id+"/restore.json", &receipt); err == nil {
		job.RestoreVerified = receipt.ID == id && receipt.SHA256 == job.SHA256 && receipt.PlanRevision == request.PlanRevision && receipt.Status == "verified" && receipt.Kind == backupRestoreKind && !receipt.Finished.IsZero() && receipt.Live.verified()
		if job.RestoreVerified {
			job.LiveVerification = receipt.Live
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if job.Status == "backed_up" {
		digest, err := hex.DecodeString(job.SHA256)
		if err != nil || len(digest) != 32 || job.Archive != "domain.tar.gz" || job.Bytes <= 0 {
			return nil, fmt.Errorf("invalid completed backup metadata")
		}
		st, err := root.Lstat(id + "/" + job.Archive)
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() != job.Bytes {
			return nil, fmt.Errorf("completed backup archive missing or changed")
		}
	}
	if job.Status == "queued" || job.Status == "running" {
		active, e := backupActive(ctx, id)
		if e != nil {
			job.Status = "unknown"
			job.Error = e.Error()
		} else if !active {
			job.Status = "interrupted"
			job.Error = "Worker is not active; backup is not confirmed"
		}
	}
	if _, err := root.Lstat(id + "/apply.json"); err == nil {
		job.ApplyReserved = true
		for i := 0; i <= 302; i++ {
			var event CleanupApplyEvent
			err = readBackupJSON(root, id+"/apply-event-"+strconv.Itoa(i)+".json", &event)
			if os.IsNotExist(err) {
				break
			}
			if err != nil {
				return nil, err
			}
			job.ApplyEvents = append(job.ApplyEvents, event)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return job, nil
}
