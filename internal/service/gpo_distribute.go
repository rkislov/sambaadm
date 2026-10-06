package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	ID      string `json:"id"`
	Title   string `json:"title"`
	Detail  string `json:"detail,omitempty"`
	DC      string `json:"dc,omitempty"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
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

	local := s.localDCName()
	dnsRoot := dnsFromBaseDN(s.ldap.BaseDN())
	sysvol := s.gpoCfg.SysvolPath
	if sysvol == "" {
		sysvol = "/var/lib/samba/sysvol"
	}
	syncMode := strings.ToLower(s.gpoCfg.SyncMode)
	if syncMode == "" {
		syncMode = "both"
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

	job.Steps = append(job.Steps, DistributeStep{
		ID: "resolve", Title: "Проверка GPO и пути SYSVOL", Detail: filepath.Join(sysvol, dnsRoot, "Policies", braceGUID(guid)),
		Status: StepPending,
	})
	job.Steps = append(job.Steps, DistributeStep{
		ID: "acl-local", Title: "Применение ACL SYSVOL (локально)", Detail: "samba-tool ntacl sysvolreset",
		DC: local, Status: StepPending,
	})

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
				Detail: "samba-tool drs replicate",
				DC:     host,
				Status: StepPending,
			})
		}
		if syncMode == "rsync" || syncMode == "both" {
			job.Steps = append(job.Steps, DistributeStep{
				ID:     "rsync-" + host,
				Title:  "Копирование SYSVOL (rsync) → " + host,
				Detail: "Policies/" + braceGUID(guid),
				DC:     host,
				Status: StepPending,
			})
		}
		if s.gpoCfg.RemoteSysvolReset && (syncMode == "rsync" || syncMode == "both") {
			job.Steps = append(job.Steps, DistributeStep{
				ID:     "acl-" + host,
				Title:  "Сброс ACL SYSVOL на " + host,
				Detail: "ssh … samba-tool ntacl sysvolreset",
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

	go s.runDistribute(id, local, dnsRoot, sysvol, syncMode)

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

func (s *GPOService) runDistribute(jobID, local, dnsRoot, sysvol, syncMode string) {
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
	guid := braceGUID(job.GUID)
	policyPath := filepath.Join(sysvol, dnsRoot, "Policies", guid)

	// Step resolve
	if err := s.runStep(jobID, "resolve", func() error {
		if s.tool == nil || !s.tool.Available() {
			return fmt.Errorf("samba-tool is not available")
		}
		if _, err := os.Stat(policyPath); err != nil {
			return fmt.Errorf("local policy path not found: %s (%v)", policyPath, err)
		}
		return nil
	}); err != nil {
		fail(err.Error())
		s.markRemainingSkipped(jobID)
		return
	}

	// Local ACL
	if err := s.runStep(jobID, "acl-local", func() error {
		_, err := s.tool.Run(ctx, "ntacl", "sysvolreset")
		return err
	}); err != nil {
		// non-fatal warning: continue but record failure on step
		// actually runStep already marks failed; decide: continue distribution
	}

	// Per-DC steps from current job snapshot
	job, _ = s.jobs.get(jobID)
	for _, st := range job.Steps {
		if st.Status != StepPending {
			continue
		}
		if st.ID == "done" {
			continue
		}
		stepID := st.ID
		host := st.DC
		switch {
		case strings.HasPrefix(stepID, "drs-"):
			_ = s.runStep(jobID, stepID, func() error {
				src := local
				if src == "" || src == "localhost" {
					if h, _ := os.Hostname(); h != "" {
						src = h
					}
				}
				_, err := s.tool.Run(ctx, "drs", "replicate", host, src, s.ldap.BaseDN())
				return err
			})
		case strings.HasPrefix(stepID, "rsync-"):
			_ = s.runStep(jobID, stepID, func() error {
				return s.rsyncPolicy(ctx, policyPath, host, dnsRoot, guid)
			})
		case strings.HasPrefix(stepID, "acl-") && stepID != "acl-local":
			_ = s.runStep(jobID, stepID, func() error {
				return s.remoteSysvolReset(ctx, host)
			})
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

func (s *GPOService) rsyncPolicy(ctx context.Context, localPolicy, host, dnsRoot, guid string) error {
	rsync := s.gpoCfg.RsyncBinary
	if rsync == "" {
		rsync = "rsync"
	}
	remotePath := fmt.Sprintf("%s:%s/%s/Policies/%s/", host, strings.TrimRight(s.sysvol(), "/"), dnsRoot, guid)
	src := strings.TrimRight(localPolicy, "/") + "/"
	cmd := exec.CommandContext(ctx, rsync, "-XAavz", "--delete-after", src, remotePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s *GPOService) remoteSysvolReset(ctx context.Context, host string) error {
	ssh := s.gpoCfg.SSHBinary
	if ssh == "" {
		ssh = "ssh"
	}
	cmd := exec.CommandContext(ctx, ssh, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
		host, "samba-tool", "ntacl", "sysvolreset")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
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

