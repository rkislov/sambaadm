package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	"sambaadm/internal/service"
)

type certificateRolloutNode struct {
	Node        string                          `json:"node"`
	Phase       string                          `json:"phase"`
	Error       string                          `json:"error,omitempty"`
	State       *service.CertificateDeployState `json:"state,omitempty"`
	Certificate []byte                          `json:"certificate,omitempty"`
	Expires     time.Time                       `json:"expires,omitempty"`
}
type certificateRollout struct {
	ID      string                   `json:"id"`
	Years   int                      `json:"years"`
	Status  string                   `json:"status"`
	Created time.Time                `json:"created"`
	Updated time.Time                `json:"updated"`
	Actor   string                   `json:"actor"`
	Error   string                   `json:"error,omitempty"`
	CA      []byte                   `json:"ca"`
	Nodes   []certificateRolloutNode `json:"nodes"`
}

func certificateRolloutID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}
func validCertificateRolloutID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 16 && hex.EncodeToString(b) == id
}
func (s *Server) certificateRolloutPath(id string) (string, error) {
	if !validCertificateRolloutID(id) {
		return "", fmt.Errorf("invalid rollout ID")
	}
	if err := certificateDir(s.cfg.Server.CertificateDir); err != nil {
		return "", err
	}
	dir := filepath.Join(s.cfg.Server.CertificateDir, "rollouts")
	if err := certificateDir(dir); err != nil {
		return "", err
	}
	return filepath.Join(dir, id+".json"), nil
}
func (s *Server) saveCertificateRollout(job *certificateRollout) error {
	path, err := s.certificateRolloutPath(job.ID)
	if err != nil {
		return err
	}
	job.Updated = time.Now()
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return saveCertificateFile(path, data)
}
func (s *Server) loadCertificateRollout(id string) (*certificateRollout, error) {
	path, err := s.certificateRolloutPath(id)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var job certificateRollout
	err = json.Unmarshal(raw, &job)
	return &job, err
}
func (s *Server) certificateHelpers() (*agent.Client, error) {
	if s.cfg.Server.EnrollmentDir != "" {
		cfg, err := config.ManagedHelpers(s.cfg.Server.EnrollmentDir)
		if err != nil {
			return nil, err
		}
		return &agent.Client{Config: cfg}, nil
	}
	if s.svcs == nil || s.svcs.Helpers == nil {
		return nil, fmt.Errorf("зарегистрируйте helper на каждом контроллере")
	}
	return s.svcs.Helpers, nil
}
func (s *Server) handleCertificateRollouts(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.certRolloutMu.Lock()
	defer s.certRolloutMu.Unlock()
	if r.Method == "GET" {
		var jobs []*certificateRollout
		dir := filepath.Join(s.cfg.Server.CertificateDir, "rollouts")
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			apiResult(w, nil, err)
			return
		}
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			id := strings.TrimSuffix(entry.Name(), ".json")
			job, e := s.loadCertificateRollout(id)
			if e != nil {
				continue
			}
			if job.Status == "running" && !s.certRolloutActive[id] {
				job.Status = "interrupted"
				job.Error = "Процесс приложения был прерван. Продолжение сначала сверит состояние каждого helper."
				s.saveCertificateRollout(job)
			}
			jobs = append(jobs, job)
		}
		sort.Slice(jobs, func(i, j int) bool { return jobs[i].Created.After(jobs[j].Created) })
		writeJSON(w, 200, jobs)
		return
	}
	var in struct {
		Action  string `json:"action"`
		ID      string `json:"id"`
		Node    string `json:"node"`
		Years   string `json:"years"`
		Confirm bool   `json:"confirm"`
		RenewCA bool   `json:"renewCA"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return
	}
	if in.Action != "plan" && in.Action != "apply" && in.Action != "rollback" {
		writeJSON(w, 400, map[string]string{"error": "invalid rollout action"})
		return
	}
	client, err := s.certificateHelpers()
	if err != nil {
		apiResult(w, nil, err)
		return
	}
	for id, running := range s.certRolloutActive {
		if running {
			writeJSON(w, 409, map[string]string{"error": "Дождитесь завершения развёртывания " + id})
			return
		}
	}
	switch in.Action {
	case "plan":
		years, e := certificateYears(in.Years)
		if e != nil {
			apiResult(w, nil, e)
			return
		}
		dcs, e := s.svcs.Sites.Controllers(r.Context())
		if e != nil {
			apiResult(w, nil, e)
			return
		}
		if len(dcs) == 0 || len(dcs) > 64 {
			writeJSON(w, 400, map[string]string{"error": "Нужно от 1 до 64 контроллеров в каталоге"})
			return
		}
		job := &certificateRollout{ID: certificateRolloutID(), Years: years, Created: time.Now(), Actor: sessionFrom(r).Username, Status: "planned"}
		seen := map[string]bool{}
		// Missing helpers block the whole plan before keys are generated on any DC.
		for _, dc := range dcs {
			node := strings.ToLower(dc.DNS)
			if !enrollmentDNS(node) || seen[node] {
				writeJSON(w, 400, map[string]string{"error": "Неверное или повторяющееся DNS-имя DC"})
				return
			}
			seen[node] = true
			if !client.Has(node) {
				writeJSON(w, 409, map[string]string{"error": "На " + node + " не зарегистрирован helper. Развёртывание требует helper на всех DC, включая RODC."})
				return
			}
			job.Nodes = append(job.Nodes, certificateRolloutNode{Node: node, Phase: "pending"})
		}
		sort.Slice(job.Nodes, func(i, j int) bool { return job.Nodes[i].Node < job.Nodes[j].Node })
		s.certMu.Lock()
		ca, key, caPEM, _, e := s.certificateAuthorityForYears(years, in.RenewCA)
		s.certMu.Unlock()
		if e != nil {
			apiResult(w, nil, e)
			return
		}
		job.CA = caPEM
		for i := range job.Nodes {
			node := &job.Nodes[i]
			ctx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
			var state service.CertificateDeployState
			e = client.Call(ctx, node.Node, "certificate.prepare", service.CertificateDeployInput{ID: job.ID, Node: node.Node}, &state)
			cancel()
			if e != nil {
				node.Phase = "error"
				node.Error = e.Error()
				job.Status = "blocked"
				continue
			}
			node.State = &state
			block, _ := pem.Decode(state.CSR)
			if block == nil {
				node.Error = "helper не вернул CSR"
			} else {
				csr, parseErr := x509.ParseCertificateRequest(block.Bytes)
				if parseErr != nil {
					node.Error = parseErr.Error()
				} else if parseErr = csr.CheckSignature(); parseErr != nil {
					node.Error = parseErr.Error()
				} else {
					node.Certificate, parseErr = signLDAPCertificate(ca, key, node.Node, csr.PublicKey, years)
					if parseErr != nil {
						node.Error = parseErr.Error()
					} else {
						leafBlock, _ := pem.Decode(node.Certificate)
						leaf, _ := x509.ParseCertificate(leafBlock.Bytes)
						node.Expires = leaf.NotAfter
					}
				}
			}
			if node.Error != "" {
				node.Phase = "error"
				job.Status = "blocked"
			} else {
				node.Phase = "prepared"
			}
		}
		if err = s.saveCertificateRollout(job); err != nil {
			apiResult(w, nil, err)
			return
		}
		if s.audit != nil {
			s.audit.Success(job.Actor, "certificate.rollout.plan", job.ID, r.RemoteAddr)
		}
		writeJSON(w, 200, job)
	case "apply":
		if !in.Confirm {
			writeJSON(w, 400, map[string]string{"error": "Подтвердите последовательные перезапуски Samba на всех DC"})
			return
		}
		job, e := s.loadCertificateRollout(in.ID)
		if e != nil {
			apiResult(w, nil, e)
			return
		}
		if job.Status != "planned" && job.Status != "interrupted" && job.Status != "failed" {
			writeJSON(w, 409, map[string]string{"error": "Этот план нельзя применить"})
			return
		}
		if time.Since(job.Created) > time.Hour && job.Status == "planned" {
			writeJSON(w, 409, map[string]string{"error": "План устарел; создайте новый"})
			return
		}
		// Re-read the inventory before any change; a newly added/missing DC invalidates the plan.
		dcs, e := s.svcs.Sites.Controllers(r.Context())
		if e != nil {
			apiResult(w, nil, e)
			return
		}
		names := map[string]bool{}
		for _, dc := range dcs {
			names[strings.ToLower(dc.DNS)] = true
		}
		if len(names) != len(job.Nodes) {
			writeJSON(w, 409, map[string]string{"error": "Список DC изменился; подготовьте новый план"})
			return
		}
		for _, n := range job.Nodes {
			if !names[n.Node] {
				writeJSON(w, 409, map[string]string{"error": "Список DC изменился"})
				return
			}
		}
		job.Status = "running"
		job.Error = ""
		if e = s.saveCertificateRollout(job); e != nil {
			apiResult(w, nil, e)
			return
		}
		if s.certRolloutActive == nil {
			s.certRolloutActive = map[string]bool{}
		}
		s.certRolloutActive[job.ID] = true
		if s.audit != nil {
			s.audit.Success(sessionFrom(r).Username, "certificate.rollout.start", job.ID, r.RemoteAddr)
		}
		writeJSON(w, 202, job)
		go s.runCertificateRollout(job, client)
	case "rollback":
		if !in.Confirm {
			writeJSON(w, 400, map[string]string{"error": "confirm required"})
			return
		}
		job, e := s.loadCertificateRollout(in.ID)
		if e != nil {
			apiResult(w, nil, e)
			return
		}
		for i := range job.Nodes {
			node := &job.Nodes[i]
			if node.Node != in.Node {
				continue
			}
			var result service.CertificateDeployState
			ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
			e = client.Call(ctx, node.Node, "certificate.rollback", service.CertificateDeployInput{ID: job.ID, Node: node.Node}, &result)
			cancel()
			if e != nil {
				apiResult(w, nil, e)
				return
			}
			node.State = &result
			node.Phase = "rolled-back"
			job.Status = "rolled-back"
			s.saveCertificateRollout(job)
			if s.audit != nil {
				s.audit.Success(sessionFrom(r).Username, "certificate.rollout.rollback", node.Node, r.RemoteAddr)
			}
			writeJSON(w, 200, job)
			return
		}
		writeJSON(w, 404, map[string]string{"error": "DC not in plan"})
	default:
		writeJSON(w, 400, map[string]string{"error": "invalid rollout action"})
	}
}
func (s *Server) runCertificateRollout(job *certificateRollout, client *agent.Client) {
	s.runCertificateRolloutWith(job, client, verifyRolloutLDAPS)
}
func (s *Server) runCertificateRolloutWith(job *certificateRollout, client *agent.Client, verify func(context.Context, string, []byte, []byte) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	update := func() bool {
		s.certRolloutMu.Lock()
		defer s.certRolloutMu.Unlock()
		if err := s.saveCertificateRollout(job); err != nil {
			job.Status = "failed"
			job.Error = "Не удалось сохранить журнал: " + err.Error()
			return false
		}
		return true
	}
	defer func() {
		s.certRolloutMu.Lock()
		delete(s.certRolloutActive, job.ID)
		s.saveCertificateRollout(job)
		s.certRolloutMu.Unlock()
	}()
	fail := func(node *certificateRolloutNode, err error) {
		var observed service.CertificateDeployState
		inspectCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		inspectErr := client.Call(inspectCtx, node.Node, "certificate.status", service.CertificateDeployInput{ID: job.ID, Node: node.Node}, &observed)
		stop()
		if inspectErr == nil {
			node.State = &observed
			node.Phase = observed.Phase
		} else {
			node.Phase = "unverified"
		}
		node.Error = err.Error()
		job.Error = node.Node + ": " + err.Error()
		job.Status = "failed"
		if s.audit != nil {
			s.audit.Failure(job.Actor, "certificate.rollout", job.ID, "", err)
		}
		update()
	}
	// Read every helper journal before resuming. Never blindly resend an uncertain operation.
	for i := range job.Nodes {
		node := &job.Nodes[i]
		var state service.CertificateDeployState
		stepCtx, stop := context.WithTimeout(ctx, 40*time.Second)
		err := client.Call(stepCtx, node.Node, "certificate.status", service.CertificateDeployInput{ID: job.ID, Node: node.Node}, &state)
		stop()
		if err != nil {
			fail(node, err)
			return
		}
		if state.Phase != "prepared" && state.Phase != "trusted" && state.Phase != "installed" {
			fail(node, fmt.Errorf("helper phase %s: inspect or roll back this node", state.Phase))
			return
		}
		node.State = &state
		node.Phase = state.Phase
		node.Error = ""
		if !update() {
			return
		}
	}
	// Add new trust on the management host while preserving all currently configured CAs.
	s.certMu.Lock()
	err := s.mergeCertificateTrust(job.CA)
	s.certMu.Unlock()
	if err != nil {
		fail(&job.Nodes[0], err)
		return
	}
	for _, phase := range []string{"trust", "install"} {
		for i := range job.Nodes {
			node := &job.Nodes[i]
			if node.Phase == "installed" || (phase == "trust" && node.Phase == "trusted") {
				continue
			}
			node.Phase = "running-" + phase
			if !update() {
				return
			}
			stepCtx, stop := context.WithTimeout(ctx, 100*time.Second)
			var state service.CertificateDeployState
			err = client.Call(stepCtx, node.Node, "certificate."+phase, service.CertificateDeployInput{ID: job.ID, Node: node.Node, CA: job.CA, Certificate: node.Certificate}, &state)
			stop()
			if err != nil {
				fail(node, err)
				return
			}
			node.State = &state
			node.Phase = state.Phase
			if !update() {
				return
			}
			if phase == "install" {
				if err = verify(ctx, node.Node, node.Certificate, job.CA); err != nil {
					fail(node, err)
					return
				}
			}
		}
	}
	// Check already-installed nodes again, including those skipped on resume.
	for i := range job.Nodes {
		node := &job.Nodes[i]
		if err = verify(ctx, node.Node, node.Certificate, job.CA); err != nil {
			fail(node, err)
			return
		}
	}
	job.Status = "complete"
	job.Error = ""
	if !update() {
		return
	}
	if s.audit != nil {
		s.audit.Success(job.Actor, "certificate.rollout.complete", job.ID, "")
	}
}
func (s *Server) mergeCertificateTrust(ca []byte) error {
	if err := validCABundle(ca); err != nil {
		return err
	}
	path := filepath.Join(s.cfg.Server.CertificateDir, "ldap-ca.pem")
	existing := s.cfg.LDAP.LDAPCAFile()
	var data []byte
	if existing != "" {
		var err error
		data, err = os.ReadFile(existing)
		if err != nil {
			return err
		}
		if err = validCABundle(data); err != nil {
			return fmt.Errorf("existing CA bundle: %w", err)
		}
	}
	if !bytes.Contains(data, ca) {
		data = append(append(data, '\n'), ca...)
	}
	if err := saveCertificateFile(path, data); err != nil {
		return err
	}
	if s.ldap != nil {
		s.ldap.Close()
	}
	return nil
}
func verifyRolloutLDAPS(ctx context.Context, node string, leafPEM, caPEM []byte) error {
	return verifyRolloutLDAPSAt(ctx, node, net.JoinHostPort(node, "636"), leafPEM, caPEM)
}
func verifyRolloutLDAPSAt(ctx context.Context, node, address string, leafPEM, caPEM []byte) error {
	block, _ := pem.Decode(leafPEM)
	if block == nil {
		return fmt.Errorf("missing issued certificate")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("invalid rollout CA")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: node, RootCAs: roots, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, block.Bytes) {
			return fmt.Errorf("DC serves a different certificate")
		}
		return nil
	}}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: cfg}
	conn, err := d.DialContext(ctx, "tcp", address)
	if err == nil {
		conn.Close()
	}
	return err
}
