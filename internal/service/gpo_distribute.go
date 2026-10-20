package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
	"os"
	"path/filepath"
	"sambaadm/internal/adremote"
	"strings"
	"sync"
	"time"

	ldapproto "sambaadm/internal/ldap"
)

// Step statuses for GPO distribution.
const (
	StepPending = "pending"
	StepRunning = "running"
	StepOK      = "ok"
	StepFailed  = "failed"
	StepSkipped = "skipped"

	JobPending = "pending"
	JobRunning = "running"
	JobOK      = "ok"
	JobFailed  = "failed"
)

// DomainController is a discovered DC.
type DomainController struct {
	Name string `json:"name"`
	DNS  string `json:"dns,omitempty"`
	DN   string `json:"dn,omitempty"`
}

// DistributeStep is one visible step in a distribute job.
type DistributeStep struct {
	ID      string    `json:"id"`
	Title   string    `json:"title"`
	Detail  string    `json:"detail,omitempty"`
	DC      string    `json:"dc,omitempty"`
	Status  string    `json:"status"`
	Message string    `json:"message,omitempty"`
	Started time.Time `json:"started,omitempty"`
	Ended   time.Time `json:"ended,omitempty"`
}

// DistributeJob tracks GPO push to all DCs.
type DistributeJob struct {
	ID        string           `json:"id"`
	GPO       string           `json:"gpo"`
	GUID      string           `json:"guid,omitempty"`
	Actor     string           `json:"actor,omitempty"`
	Status    string           `json:"status"`
	Progress  int              `json:"progress"` // 0-100
	Steps     []DistributeStep `json:"steps"`
	CreatedAt time.Time        `json:"createdAt"`
	UpdatedAt time.Time        `json:"updatedAt"`
	Error     string           `json:"error,omitempty"`
}

// jobStore keeps in-memory distribute jobs for UI polling.
type jobStore struct {
	mu   sync.RWMutex
	jobs map[string]*DistributeJob
}

func newJobStore() *jobStore {
	return &jobStore{jobs: make(map[string]*DistributeJob)}
}

func (s *jobStore) put(j *DistributeJob) {
	s.mu.Lock()
	s.jobs[j.ID] = j
	s.mu.Unlock()
}

func (s *jobStore) get(id string) (*DistributeJob, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, false
	}
	// return a shallow copy of the job with copied steps for safe JSON/UI
	cp := *j
	cp.Steps = append([]DistributeStep(nil), j.Steps...)
	return &cp, true
}

func (s *jobStore) update(id string, fn func(*DistributeJob)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return
	}
	fn(j)
	j.UpdatedAt = time.Now().UTC()
	done, total := 0, len(j.Steps)
	for _, st := range j.Steps {
		if st.Status == StepOK || st.Status == StepFailed || st.Status == StepSkipped {
			done++
		}
	}
	if total > 0 {
		j.Progress = done * 100 / total
	}
}

// ListDomainControllers finds DCs in the configuration partition / computer accounts.
func (s *GPOService) ListDomainControllers(ctx context.Context) ([]DomainController, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		BaseDN:     SitesContainerDN(s.ldap.BaseDN()),
		Filter:     "(objectClass=server)",
		Attributes: []string{"cn", "dNSHostName", "name"},
	})
	if err != nil || len(entries) == 0 {
		// Fallback: server trust computer accounts
		entries, err = s.ldap.Search(ctx, ldapproto.SearchOptions{
			Filter:     "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
			Attributes: []string{"cn", "dNSHostName", "name"},
		})
		if err != nil {
			return nil, err
		}
	}
	out := make([]DomainController, 0, len(entries))
	seen := map[string]bool{}
	for _, e := range entries {
		dns := e.GetAttributeValue("dNSHostName")
		name := e.GetAttributeValue("cn")
		if name == "" {
			name = e.GetAttributeValue("name")
		}
		key := strings.ToLower(dns)
		if key == "" {
			key = strings.ToLower(name)
		}
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, DomainController{Name: name, DNS: dns, DN: e.DN})
	}
	return out, nil
}

// StartDistribute begins an async GPO distribution job and returns its ID.
func (s *GPOService) StartDistribute(ctx context.Context, gpo, actor, ip string) (*DistributeJob, error) {
	if s.jobs == nil {
		s.jobs = newJobStore()
	}
	guid, err := s.resolveGUID(ctx, gpo)
	if err != nil {
		return nil, err
	}
	dcs, err := s.ListDomainControllers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list DCs: %w", err)
	}
	if len(dcs) == 0 {
		return nil, fmt.Errorf("no domain controllers found")
	}

	conn, err := s.ldap.Conn(ctx)
	if err != nil {
		return nil, err
	}
	root, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"dNSHostName"}, nil))
	if err != nil {
		return nil, err
	}
	if len(root.Entries) != 1 {
		return nil, fmt.Errorf("missing RootDSE")
	}
	local := root.Entries[0].GetEqualFoldAttributeValue("dNSHostName")
	if local == "" {
		return nil, fmt.Errorf("missing source DC name")
	}
	syncMode := strings.ToLower(s.gpoCfg.SyncMode)
	if syncMode == "" {
		syncMode = "both"
	}
	if syncMode != "both" && syncMode != "drs" && syncMode != "smb" && syncMode != "rsync" {
		return nil, fmt.Errorf("unsupported GPO sync mode")
	}

	id := randomJobID()
	job := &DistributeJob{
		ID:        id,
		GPO:       gpo,
		GUID:      guid,
		Actor:     actor,
		Status:    JobPending,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	job.Steps = append(job.Steps, DistributeStep{ID: "resolve", Title: "Чтение GPO и SYSVOL по SMB", Status: StepPending})

	for _, dc := range dcs {
		host := dc.DNS
		if host == "" {
			host = dc.Name
		}
		if sameHost(host, local) {
			continue
		}
		if syncMode == "drs" || syncMode == "both" {
			job.Steps = append(job.Steps, DistributeStep{
				ID:     "drs-" + host,
				Title:  "Репликация AD (DRS) → " + host,
				Detail: "MS-DRSR RPC",
				DC:     host,
				Status: StepPending,
			})
		}
		if syncMode == "rsync" || syncMode == "smb" || syncMode == "both" {
			job.Steps = append(job.Steps, DistributeStep{
				ID:     "rsync-" + host,
				Title:  "Копирование SYSVOL (SMB) → " + host,
				Detail: "Policies/" + braceGUID(guid),
				DC:     host,
				Status: StepPending,
			})
		}
	}

	job.Steps = append(job.Steps, DistributeStep{
		ID: "done", Title: "Итог распространения", Status: StepPending,
	})

	s.jobs.put(job)
	s.audit.Success(actor, "gpo.distribute.start", gpo, ip)

	go s.runDistribute(id, local)

	out, _ := s.jobs.get(id)
	return out, nil
}

// GetDistributeJob returns job status for polling.
func (s *GPOService) GetDistributeJob(id string) (*DistributeJob, bool) {
	if s.jobs == nil {
		return nil, false
	}
	return s.jobs.get(id)
}

func (s *GPOService) runDistribute(jobID, local string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	s.jobs.update(jobID, func(j *DistributeJob) { j.Status = JobRunning })

	fail := func(msg string) {
		s.jobs.update(jobID, func(j *DistributeJob) {
			j.Status = JobFailed
			j.Error = msg
			j.Progress = 100
		})
	}

	job, _ := s.jobs.get(jobID)
	if job == nil {
		return
	}
	var snapshot policyBackup
	var remotePath string
	if err := s.runStep(jobID, "resolve", func() error {
		tmp, e := os.MkdirTemp("", "sambaadm-distribute-")
		if e != nil {
			return e
		}
		defer os.RemoveAll(tmp)
		if e = s.backupNative(ctx, job.GUID, tmp, job.Actor, ""); e != nil {
			return e
		}
		data, e := os.ReadFile(filepath.Join(tmp, "policy", braceGUID(job.GUID), "sambaadm-backup.json"))
		if e != nil {
			return e
		}
		if e = json.Unmarshal(data, &snapshot); e != nil {
			return e
		}
		entry, e := s.policyEntry(ctx, job.GUID)
		if e != nil {
			return e
		}
		remotePath, e = s.policyPath(ctx, entry)
		return e
	}); err != nil {
		fail(err.Error())
		s.markRemainingSkipped(jobID)
		return
	}
	repl := &ReplService{ldap: s.ldap, audit: s.audit, remote: s.remote}
	job, _ = s.jobs.get(jobID)
	for _, step := range job.Steps {
		if step.Status != StepPending || step.ID == "done" {
			continue
		}
		err := s.runStep(jobID, step.ID, func() error {
			if strings.HasPrefix(step.ID, "drs-") {
				return repl.Sync(ctx, step.DC, local, s.ldap.BaseDN(), job.Actor, "")
			}
			remote := *s.remote
			remote.Host = step.DC
			return remote.SYSVOL(ctx, 445, func(share *smb2.Share) error { return installPolicySnapshot(share, remotePath, snapshot) })
		})
		if err != nil {
			fail(err.Error())
			s.markRemainingSkipped(jobID)
			return
		}
	}

	// Final summary
	_ = s.runStep(jobID, "done", func() error {
		job, _ := s.jobs.get(jobID)
		failed := 0
		for _, st := range job.Steps {
			if st.ID == "done" {
				continue
			}
			if st.Status == StepFailed {
				failed++
			}
		}
		if failed > 0 {
			return fmt.Errorf("завершено с ошибками: %d шаг(ов)", failed)
		}
		return nil
	})

	s.jobs.update(jobID, func(j *DistributeJob) {
		if j.Status != JobFailed {
			// if done step failed, status already failed inside runStep
			allOK := true
			for _, st := range j.Steps {
				if st.Status == StepFailed {
					allOK = false
					break
				}
			}
			if allOK {
				j.Status = JobOK
			} else {
				j.Status = JobFailed
			}
		}
		j.Progress = 100
	})
}

func (s *GPOService) runStep(jobID, stepID string, fn func() error) error {
	s.jobs.update(jobID, func(j *DistributeJob) {
		for i := range j.Steps {
			if j.Steps[i].ID == stepID {
				j.Steps[i].Status = StepRunning
				j.Steps[i].Started = time.Now().UTC()
				j.Steps[i].Message = ""
			}
		}
	})
	err := fn()
	s.jobs.update(jobID, func(j *DistributeJob) {
		for i := range j.Steps {
			if j.Steps[i].ID != stepID {
				continue
			}
			j.Steps[i].Ended = time.Now().UTC()
			if err != nil {
				j.Steps[i].Status = StepFailed
				j.Steps[i].Message = err.Error()
				j.Status = JobFailed
				j.Error = err.Error()
			} else {
				j.Steps[i].Status = StepOK
				j.Steps[i].Message = "OK"
			}
		}
	})
	return err
}

func (s *GPOService) markRemainingSkipped(jobID string) {
	s.jobs.update(jobID, func(j *DistributeJob) {
		for i := range j.Steps {
			if j.Steps[i].Status == StepPending {
				j.Steps[i].Status = StepSkipped
				j.Steps[i].Message = "пропущено из-за предыдущей ошибки"
			}
		}
		j.Progress = 100
	})
}

func (s *GPOService) sysvol() string {
	if s.gpoCfg.SysvolPath != "" {
		return s.gpoCfg.SysvolPath
	}
	return "/var/lib/samba/sysvol"
}

func (s *GPOService) localDCName() string {
	if host := hostnameFromURI(s.ldap.URI()); host != "" {
		return host
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "localhost"
}

func normalizeGPOGUID(gpo string) string {
	g := strings.TrimSpace(gpo)
	g = strings.TrimPrefix(g, "{")
	g = strings.TrimSuffix(g, "}")
	return g
}

func looksLikeGUID(g string) bool {
	g = normalizeGPOGUID(g)
	// 8-4-4-4-12 hex
	if len(g) != 36 {
		return false
	}
	for i, c := range g {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}
	return true
}

func (s *GPOService) resolveGUID(ctx context.Context, gpo string) (string, error) {
	if looksLikeGUID(gpo) {
		return normalizeGPOGUID(gpo), nil
	}
	list, err := s.List(ctx)
	if err != nil {
		return "", err
	}
	want := strings.ToLower(strings.TrimSpace(gpo))
	for _, g := range list {
		if strings.ToLower(g.DisplayName) == want || strings.EqualFold(normalizeGPOGUID(g.GUID), normalizeGPOGUID(gpo)) {
			return normalizeGPOGUID(g.GUID), nil
		}
	}
	return "", fmt.Errorf("GPO not found: %s", gpo)
}

func braceGUID(gpo string) string {
	g := normalizeGPOGUID(gpo)
	if g == "" {
		return g
	}
	return "{" + g + "}"
}

func sameHost(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == b {
		return true
	}
	aShort, _, _ := strings.Cut(a, ".")
	bShort, _, _ := strings.Cut(b, ".")
	return aShort != "" && aShort == bShort
}

func randomJobID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Stage a complete policy before replacing the target; retain old files if swap fails.
func installPolicySnapshot(share *smb2.Share, target string, snapshot policyBackup) error {
	if i := strings.LastIndex(target, "\\"); i > 0 {
		if err := share.MkdirAll(target[:i], 0755); err != nil {
			return err
		}
	}
	stage := target + ".sambaadm-" + randomJobID()
	old := stage + ".old"
	if err := share.Mkdir(stage, 0755); err != nil {
		return err
	}
	defer share.RemoveAll(stage)
	if err := share.SetSecurityInfoRaw(stage, smb2.OwnerSecurityInformation|smb2.GroupSecurityInformation|smb2.DACLSecurityInformation|0x80000000, adremote.SecurityBytes(snapshot.ACL)); err != nil {
		return err
	}
	for _, part := range []string{"Machine", "User"} {
		if err := share.Mkdir(stage+"\\"+part, 0755); err != nil {
			return err
		}
	}
	for name, data := range snapshot.Files {
		path := stage + "\\" + strings.ReplaceAll(name, "/", "\\")
		i := strings.LastIndex(path, "\\")
		if err := share.MkdirAll(path[:i], 0755); err != nil {
			return err
		}
		if err := share.WriteFile(path, data, 0644); err != nil {
			return err
		}
	}
	if err := applySnapshotPermissions(share, stage, snapshot); err != nil {
		return err
	}
	exists := false
	if _, err := share.Stat(target); err == nil {
		exists = true
		if err = share.Rename(target, old); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := share.Rename(stage, target); err != nil {
		if exists {
			if rollback := share.Rename(old, target); rollback != nil {
				return fmt.Errorf("swap failed: %v; recover original from %s: %w", err, old, rollback)
			}
		}
		return err
	}
	if exists {
		return share.RemoveAll(old)
	}
	return nil
}
