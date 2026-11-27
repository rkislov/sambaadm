package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"sambaadm/internal/auth"
	"sambaadm/internal/filecluster"
	"sambaadm/internal/service"
)

type clusterRef struct {
	Name     string   `json:"name"`
	Revision string   `json:"revision"`
	Realm    string   `json:"realm,omitempty"`
	VIP      string   `json:"vip,omitempty"`
	Nodes    []string `json:"nodes"`
}

type clusterNodeStatus struct {
	ClusterError  string                      `json:"clusterError,omitempty"`
	SnapshotError string                      `json:"snapshotError,omitempty"`
	Node          string                      `json:"node"`
	Error         string                      `json:"error,omitempty"`
	Owner         string                      `json:"owner,omitempty"`
	SMBReady      *bool                       `json:"smbReady,omitempty"`
	LocalNode     string                      `json:"localNode,omitempty"`
	OnlineNodes   []string                    `json:"onlineNodes,omitempty"`
	Quorum        bool                        `json:"quorum"`
	Platform      string                      `json:"platform,omitempty"`
	StorageError  string                      `json:"storageError,omitempty"`
	Multipath     json.RawMessage             `json:"multipath,omitempty"`
	Snapshots     json.RawMessage             `json:"snapshots,omitempty"`
	Schedule      *filecluster.SnapshotPolicy `json:"schedule,omitempty"`
}

type fileClusterDraft struct {
	ID         string            `json:"id"`
	Plan       filecluster.Input `json:"plan"`
	Platform   string            `json:"platform,omitempty"`
	Targets    []string          `json:"targets,omitempty"`
	LUNs       []clusterLUN      `json:"luns,omitempty"`
	Phase      string            `json:"phase"`
	Action     string            `json:"action,omitempty"`
	Error      string            `json:"error,omitempty"`
	Log        []string          `json:"log,omitempty"`
	Revision   string            `json:"revision,omitempty"`
	Workgroup  string            `json:"workgroup,omitempty"`
	Controller string            `json:"controller,omitempty"`
	GroupSID   string            `json:"groupSID,omitempty"`
}

type clusterLUN struct {
	WWID string `json:"wwid"`
	Size int64  `json:"size"`
}

// AuthKey and helper credential references never need to reach the browser.
type fileClusterState struct {
	Draft  fileClusterDraft    `json:"draft"`
	Key    string              `json:"key"`
	Fences []filecluster.Fence `json:"fences,omitempty"`
}

type clusterSetupAction struct {
	Plan         filecluster.Input             `json:"plan"`
	Portals      []string                      `json:"portals"`
	Target       string                        `json:"target"`
	WWID         string                        `json:"wwid"`
	Fences       []filecluster.CredentialInput `json:"fences"`
	Workgroup    string                        `json:"workgroup"`
	Controller   string                        `json:"controller"`
	GroupSID     string                        `json:"groupSID"`
	Username     string                        `json:"username"`
	Password     string                        `json:"password"`
	DedicatedZFS bool                          `json:"dedicatedZFS"`
	Confirm      bool                          `json:"confirm"`
}

type clusterRPC struct {
	server *Server
	actor  string
}

var clusterDraftID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func clusterID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) fileClusterPage(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanRead) {
		return
	}
	page := s.page(r, "nav.shares", dnsFromBaseDN(s.cfg.LDAP.BaseDN))
	page.Title = "Файловые кластеры"
	s.render(w, "shares/file-cluster.html", page)
}

func (c clusterRPC) call(ctx context.Context, node, method string, in, out any) error {
	if c.server.svcs == nil || c.server.svcs.Helpers == nil || !c.server.svcs.Helpers.Has(node) {
		return fmt.Errorf("helper %s не зарегистрирован", node)
	}
	data, err := json.Marshal(in)
	if err != nil {
		return err
	}
	defer clear(data)
	return c.server.svcs.Helpers.Call(ctx, node, method, service.HostOperation{Input: data, Actor: c.actor}, out)
}

func (c clusterRPC) status(ctx context.Context, ref clusterRef) ([]clusterNodeStatus, error) {
	return c.clusterStatus(ctx, ref, "filecluster.status")
}

func (c clusterRPC) clusterStatus(ctx context.Context, ref clusterRef, method string) ([]clusterNodeStatus, error) {
	read := filecluster.ClusterReadInput{Name: ref.Name, Revision: ref.Revision}
	if err := read.Validate(); err != nil {
		return nil, err
	}
	if len(ref.Nodes) != 2 || ref.Nodes[0] == ref.Nodes[1] {
		return nil, errors.New("выберите два разных helper")
	}
	statuses := make([]clusterNodeStatus, 2)
	var wg sync.WaitGroup
	for i, node := range ref.Nodes {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			statuses[i].Node = node
			err := c.call(ctx, node, method, read, &statuses[i])
			if method == "filecluster.monitor" && helperMethodUnsupported(err) {
				err = c.call(ctx, node, "filecluster.status", read, &statuses[i])
			}
			if err != nil {
				statuses[i].Error = err.Error()
			}
		})
	}
	wg.Wait()
	return statuses, nil
}

func snapshotOwner(statuses []clusterNodeStatus) (string, error) {
	owner := ""
	for _, status := range statuses {
		if status.Error != "" || !status.Quorum || status.Owner == "" {
			continue
		}
		if owner != "" && owner != status.Owner {
			return "", errors.New("helper сообщают разных владельцев")
		}
		owner = status.Owner
	}
	for _, status := range statuses {
		if owner != "" && status.Node == owner && status.LocalNode == owner && status.Owner == owner && status.Quorum && status.Error == "" {
			return owner, nil
		}
	}
	return "", errors.New("активный узел с кворумом не подтверждён")
}

func (s *Server) handleFileClusterAPI(w http.ResponseWriter, r *http.Request) {
	route := chi.RouteContext(r.Context()).RoutePattern()
	canManage := sessionFrom(r) != nil && auth.CanAdmin(sessionFrom(r).Role)
	read := r.Method == http.MethodGet && (route == "/api/v1/file-clusters" || route == "/api/v1/file-clusters/status")
	if read {
		if !requireRole(w, r, auth.CanRead) {
			return
		}
	} else if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	rpc := clusterRPC{s, sessionFrom(r).Username}
	ctx := r.Context()
	answer := func(out any, err error) {
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, out)
	}
	switch route {
	case "/api/v1/file-clusters":
		answer(s.clusterCatalog(ctx, rpc, canManage), nil)
	case "/api/v1/file-clusters/status":
		q := r.URL.Query()
		out, err := rpc.status(ctx, clusterRef{Name: q.Get("name"), Revision: q.Get("revision"), Nodes: q["node"]})
		if !canManage {
			for i := range out {
				for _, detail := range []*string{&out[i].Error, &out[i].ClusterError, &out[i].StorageError, &out[i].SnapshotError} {
					if *detail != "" {
						*detail = "Данные недоступны"
					}
				}
			}
		}
		answer(out, err)
	case "/api/v1/file-clusters/snapshot":
		var in struct {
			Cluster   clusterRef `json:"cluster"`
			Label     string     `json:"label"`
			RequestID string     `json:"requestID"`
		}
		if !topologyJSON(w, r, &in) {
			return
		}
		request := filecluster.ActivationInput{RequestID: in.RequestID, Name: in.Cluster.Name, Revision: in.Cluster.Revision, Label: in.Label}
		if err := request.Validate("snapshot"); err != nil {
			answer(nil, err)
			return
		}
		statuses, err := rpc.status(ctx, in.Cluster)
		if err != nil {
			answer(nil, err)
			return
		}
		node, err := snapshotOwner(statuses)
		if err != nil {
			answer(nil, err)
			return
		}
		var job filecluster.JobStatus
		err = rpc.call(ctx, node, "filecluster.snapshot", request, &job)
		answer(map[string]any{"node": node, "id": job.ID}, err)
	case "/api/v1/file-clusters/restore/{operation}":
		var in struct {
			Cluster      clusterRef `json:"cluster"`
			RequestID    string     `json:"requestID"`
			Snapshot     string     `json:"snapshot"`
			Path         string     `json:"path"`
			Offset       int        `json:"offset,omitempty"`
			Overwrite    bool       `json:"overwrite,omitempty"`
			PlanRevision string     `json:"planRevision,omitempty"`
			Confirm      bool       `json:"confirm,omitempty"`
		}
		if !topologyJSON(w, r, &in) {
			return
		}
		op := chi.URLParam(r, "operation")
		if op != "browse" && op != "preview" && op != "apply" {
			http.NotFound(w, r)
			return
		}
		request := filecluster.RestoreInput{
			ClusterReadInput: filecluster.ClusterReadInput{Name: in.Cluster.Name, Revision: in.Cluster.Revision},
			RequestID:        in.RequestID, Snapshot: in.Snapshot, Path: in.Path, Offset: in.Offset,
			Overwrite: in.Overwrite, PlanRevision: in.PlanRevision, Confirm: in.Confirm,
		}
		if err := request.Validate(op); err != nil {
			answer(nil, err)
			return
		}
		statuses, err := rpc.status(ctx, in.Cluster)
		if err != nil {
			answer(nil, err)
			return
		}
		node, err := snapshotOwner(statuses)
		if err != nil {
			answer(nil, err)
			return
		}
		var job filecluster.JobStatus
		err = rpc.call(ctx, node, "filecluster.restore."+op, request, &job)
		if err == nil && op == "apply" && s.audit != nil {
			s.audit.Success(rpc.actor, "filecluster.restore.start", in.Cluster.Name+"/"+in.Path, r.RemoteAddr)
		}
		answer(map[string]any{"node": node, "id": job.ID}, err)
	case "/api/v1/file-clusters/snapshot-schedule":
		var in struct {
			Cluster   clusterRef                 `json:"cluster"`
			RequestID string                     `json:"requestID"`
			Policy    filecluster.SnapshotPolicy `json:"policy"`
		}
		if !topologyJSON(w, r, &in) {
			return
		}
		request := filecluster.SnapshotScheduleInput{
			ActivationInput: filecluster.ActivationInput{Name: in.Cluster.Name, Revision: in.Cluster.Revision, RequestID: in.RequestID},
			Policy:          in.Policy,
		}
		out, err := rpc.updateSchedule(ctx, in.Cluster, request)
		answer(out, err)
	case "/api/v1/file-clusters/jobs/{id}":
		var job filecluster.JobStatus
		node, id := r.URL.Query().Get("node"), chi.URLParam(r, "id")
		if !clusterDraftID.MatchString(id) {
			answer(nil, errors.New("неверный идентификатор задания"))
			return
		}
		answer(&job, rpc.readJob(ctx, node, id, &job))
	case "/api/v1/file-clusters/setup":
		var in clusterSetupAction
		if !topologyJSON(w, r, &in) {
			return
		}
		out, err := s.createClusterDraft(rpc, in.Plan)
		answer(out, err)
	case "/api/v1/file-clusters/setup/{id}":
		s.clusterMu.Lock()
		state, err := s.readClusterDraft(chi.URLParam(r, "id"))
		s.clusterMu.Unlock()
		answer(state.Draft, err)
	case "/api/v1/file-clusters/setup/{id}/{action}":
		var in clusterSetupAction
		if !topologyJSON(w, r, &in) {
			return
		}
		out, err := s.startClusterAction(rpc, chi.URLParam(r, "id"), chi.URLParam(r, "action"), in)
		answer(out, err)
	default:
		http.NotFound(w, r)
	}
}

type fileClusterCatalog struct {
	Nodes       []service.FileClusterNode `json:"nodes,omitempty"`
	Clusters    []clusterRef              `json:"clusters"`
	Drafts      []fileClusterDraft        `json:"drafts,omitempty"`
	unreachable int
}

type clusterCatalogObservation struct {
	checked  time.Time
	clusters []clusterRef
}

func (s *Server) clusterCatalog(ctx context.Context, rpc clusterRPC, includeAdmin bool) fileClusterCatalog {
	var nodes []service.FileClusterNode
	if s.svcs != nil && s.svcs.Shares != nil {
		nodes, _ = s.svcs.Shares.FileClusterNodes()
	}
	found := map[string]clusterRef{}
	var wg sync.WaitGroup
	unreachable := 0
	var mu sync.Mutex
	gate := make(chan struct{}, 8)
	for _, node := range nodes {
		wg.Go(func() {
			var out struct{ Clusters []clusterRef }
			checked := time.Now()
			var err error
			select {
			case gate <- struct{}{}:
				probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
				err = rpc.call(probeCtx, node.Name, "filecluster.catalog", struct{}{}, &out)
				cancel()
				<-gate
			case <-ctx.Done():
				err = ctx.Err()
			}
			s.clusterCatalogMu.Lock()
			if s.clusterSeen == nil {
				s.clusterSeen = make(map[string]clusterCatalogObservation)
			}
			last := s.clusterSeen[node.Name]
			if err == nil && checked.After(last.checked) {
				last = clusterCatalogObservation{checked: checked, clusters: out.Clusters}
				s.clusterSeen[node.Name] = last
			}
			s.clusterCatalogMu.Unlock()
			mu.Lock()
			if err != nil {
				unreachable++
			}
			for _, cluster := range last.clusters {
				found[cluster.Name+"@"+cluster.Revision] = cluster
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()
	var drafts []fileClusterDraft
	entries, _ := os.ReadDir(s.clusterStateDir())
	for _, entry := range entries {
		id, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		state, err := s.readClusterDraft(id)
		if err != nil {
			continue
		}
		if state.Draft.Phase == "done" {
			d := state.Draft
			found[d.Plan.Name+"@"+d.Revision] = clusterRef{d.Plan.Name, d.Revision, d.Plan.Realm, d.Plan.VirtualIP, []string{d.Plan.Nodes[0].Name, d.Plan.Nodes[1].Name}}
		} else if includeAdmin {
			drafts = append(drafts, state.Draft)
		}
	}
	clusters := make([]clusterRef, 0, len(found))
	for _, cluster := range found {
		clusters = append(clusters, cluster)
	}
	if !includeAdmin {
		nodes = nil
	}
	return fileClusterCatalog{Nodes: nodes, Clusters: clusters, Drafts: drafts, unreachable: unreachable}
}

func (c clusterRPC) readJob(ctx context.Context, node, id string, out *filecluster.JobStatus) error {
	if c.server.svcs == nil || c.server.svcs.Helpers == nil || !c.server.svcs.Helpers.Has(node) {
		return errors.New("helper не зарегистрирован")
	}
	return c.server.svcs.Helpers.Call(ctx, node, "filecluster.job.status", service.HostOperation{Name: id, Actor: c.actor}, out)
}

func (c clusterRPC) job(ctx context.Context, node, method string, input, out any, log func(string)) error {
	var job filecluster.JobStatus
	if err := c.call(ctx, node, method, input, &job); err != nil {
		return err
	}
	log(node + " · задание " + job.ID)
	read := 0
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		for read < len(job.Log) {
			log(job.Log[read])
			read++
		}
		switch job.State {
		case "completed":
			return json.Unmarshal(job.Result, out)
		case "failed", "interrupted":
			return fmt.Errorf("%s: %s", node, job.Error)
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := c.readJob(ctx, node, job.ID, &job); err != nil {
			return err
		}
	}
}

func (s *Server) clusterStateDir() string {
	return filepath.Join(s.cfg.Server.SettingsDir, "file-clusters")
}

func (s *Server) readClusterDraft(id string) (fileClusterState, error) {
	var state fileClusterState
	if !clusterDraftID.MatchString(id) {
		return state, errors.New("неверный идентификатор настройки")
	}
	raw, err := os.ReadFile(filepath.Join(s.clusterStateDir(), id+".json"))
	if err != nil {
		return state, errors.New("настройка не найдена")
	}
	if err = json.Unmarshal(raw, &state); err != nil {
		return state, err
	}
	if state.Draft.Action != "" && !s.clusterRunning[id] {
		state.Draft.Action = ""
		state.Draft.Error = "Операция прервана перезапуском панели. Проверьте журнал helper и повторите шаг."
	}
	return state, nil
}

func (s *Server) writeClusterDraft(state fileClusterState) error {
	dir := s.clusterStateDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".cluster-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	err = json.NewEncoder(tmp).Encode(state)
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), filepath.Join(dir, state.Draft.ID+".json")); err != nil {
		return err
	}
	folder, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer folder.Close()
	return folder.Sync()
}

func (s *Server) createClusterDraft(rpc clusterRPC, plan filecluster.Input) (fileClusterDraft, error) {
	if !filepath.IsAbs(s.cfg.Server.SettingsDir) {
		return fileClusterDraft{}, errors.New("настройте каталог состояния панели")
	}
	if len(plan.Nodes) != 2 {
		return fileClusterDraft{}, errors.New("выберите два helper")
	}
	// Reuse the full plan validation with temporary storage/fencing values.
	check := filecluster.Input{Name: plan.Name, Realm: plan.Realm, Nodes: append([]filecluster.Node(nil), plan.Nodes...), VirtualIP: plan.VirtualIP, Prefix: plan.Prefix,
		Storage: "iscsi", Filesystem: "zfs", Portals: []string{"192.0.2.1:3260", "192.0.2.2:3260"}, TargetIQN: "iqn.2026-11.invalid:placeholder",
		Fences: []filecluster.Fence{{Agent: "redfish", Address: "192.0.2.1", CredentialRef: "placeholder"}, {Agent: "redfish", Address: "192.0.2.2", CredentialRef: "placeholder"}}}
	for i := range check.Nodes {
		node := &check.Nodes[i]
		node.DiskWWID = "placeholder"
		if node.Name == plan.Name+"."+plan.Realm {
			return fileClusterDraft{}, errors.New("имя SMB должно отличаться от имён узлов")
		}
		if rpc.server.svcs == nil || rpc.server.svcs.Helpers == nil || !rpc.server.svcs.Helpers.Has(node.Name) {
			return fileClusterDraft{}, errors.New("выберите зарегистрированные helper")
		}
	}
	if err := check.Validate(); err != nil {
		return fileClusterDraft{}, err
	}
	check.Portals = nil
	check.TargetIQN = ""
	check.Fences = nil
	for i := range check.Nodes {
		check.Nodes[i].DiskWWID = ""
	}
	id := clusterID()
	key := make([]byte, 128)
	_, _ = rand.Read(key)
	state := fileClusterState{Draft: fileClusterDraft{ID: id, Plan: check, Phase: "nodes"}, Key: base64.StdEncoding.EncodeToString(key)}
	clear(key)
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()
	return state.Draft, s.writeClusterDraft(state)
}
