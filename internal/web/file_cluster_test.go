package web

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	"sambaadm/internal/filecluster"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
)

func TestFileClusterAccess(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, tc := range []struct {
		role     auth.Role
		token    bool
		expected int
	}{
		{"", false, 401}, {auth.RoleReadonly, true, 403}, {auth.RoleAdmin, false, 403}, {auth.RoleAdmin, true, 400},
	} {
		req := httptest.NewRequest("POST", "/api/v1/file-clusters/snapshot", strings.NewReader(`{"label":"sample"}`))
		req.Header.Set("Content-Type", "application/json")
		if tc.role != "" {
			sess, _ := s.sessions.Create("cluster-test", "CN=cluster-test", tc.role)
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			if tc.token {
				req.Header.Set(csrfHeader, sess.CSRFToken)
			}
		}
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		if rec.Code != tc.expected {
			t.Errorf("%q csrf=%v: %d, want %d", tc.role, tc.token, rec.Code, tc.expected)
		}
	}
}

func TestSnapshotOwnerAfterFailover(t *testing.T) {
	active := clusterNodeStatus{Node: "fs2", LocalNode: "fs2", Owner: "fs2", Quorum: true}
	pending := clusterNodeStatus{Node: "fs1", LocalNode: "fs1", Owner: "fs1", Quorum: true}
	if _, err := snapshotOwner([]clusterNodeStatus{active, pending}); err == nil {
		t.Fatal("snapshot allowed with conflicting owners")
	}
	pending.Error = "offline"
	if owner, err := snapshotOwner([]clusterNodeStatus{active, pending}); err != nil || owner != "fs2" {
		t.Fatalf("surviving owner: %q, %v", owner, err)
	}
	active.Quorum = false
	if _, err := snapshotOwner([]clusterNodeStatus{active, pending}); err == nil {
		t.Fatal("snapshot allowed without quorum")
	}
}

// The browser uses the actual router and either signed fixture helpers or the
// pre-authorized lab's real helpers. No fixture route runs in production.
func TestFileClusterBrowserHarness(t *testing.T) {
	output := os.Getenv("SAMBAADM_CLUSTER_BROWSER")
	if output == "" {
		t.Skip("browser harness only")
	}
	s := testWorkspaceServer(t)
	s.cfg.Server.SettingsDir = t.TempDir()
	realm := "corp.example"
	var helpers *agent.Client
	if lab := os.Getenv("SAMBAADM_CLUSTER_BROWSER_LAB"); lab != "" {
		cfg, err := config.Load(filepath.Join(lab, "cli-config.json"))
		if err != nil {
			t.Fatal(err)
		}
		helpers = &agent.Client{Config: cfg.Helpers}
		if os.Getenv("SAMBAADM_SERVICE_DASHBOARD_ONLY") != "" {
			for _, node := range cfg.Helpers.Nodes {
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				err := helpers.Call(ctx, node.Name, "host.services", service.HostOperation{}, &service.HostServices{})
				cancel()
				if err != nil {
					t.Fatalf("service inventory on %s: %v", node.Name, err)
				}
			}
		}
		realm = "sambaadm.test"
	} else {
		helpers = fixtureClusterPair(t)
	}
	s.cfg.LDAP.BaseDN = "DC=" + strings.ReplaceAll(realm, ".", ",DC=")
	s.svcs = service.NewWithOptions(ldapproto.NewClient(s.cfg.LDAP), nil, service.ServiceOptions{Helpers: helpers})
	sess, _ := s.sessions.Create("cluster-admin@"+realm, "CN=cluster-admin", auth.RoleAdmin)
	helpdesk, _ := s.sessions.Create("cluster-helpdesk@"+realm, "CN=cluster-helpdesk", auth.RoleHelpdesk)
	readonly, _ := s.sessions.Create("cluster-readonly@"+realm, "CN=cluster-readonly", auth.RoleReadonly)
	mode := os.Getenv("SAMBAADM_SERVICE_DASHBOARD_ONLY")
	if mode == "history" || mode == "notifications" || mode == "mail" {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go s.MonitorHA(ctx)
		if mode == "mail" {
			go s.MonitorHAMail(ctx)
		}
	}
	var handler http.Handler = s.Router()
	infoFields := map[string]any{"session": sess.ID, "helpdesk": helpdesk.ID, "readonly": readonly.ID}
	if mode == "mail" {
		sink := startHASMTPSink(t, false)
		mux := http.NewServeMux()
		mux.Handle("/", handler)
		mux.HandleFunc("GET /__ha_mail_test_sink", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, sink.snapshot())
		})
		handler = mux
		infoFields["smtpPort"] = sink.port
	}
	host := httptest.NewServer(handler)
	defer host.Close()
	infoFields["url"] = host.URL
	info, _ := json.Marshal(infoFields)
	if err := os.WriteFile(filepath.Join(output, "browser.json"), info, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(6 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(output, "done")); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("browser did not finish")
}

func fixtureClusterPair(t *testing.T) *agent.Client {
	t.Helper()
	dir := t.TempDir()
	private, public := filepath.Join(dir, "key"), filepath.Join(dir, "key.pub")
	if err := agent.GenerateKey(private, public); err != nil {
		t.Fatal(err)
	}
	client := &agent.Client{Config: agent.Config{PrivateKey: private}}
	nodes := []string{"fs-01.corp.example", "fs-02.corp.example"}
	boots := map[string]int{}
	var mu sync.Mutex
	var staged clusterRef
	const revision = "cd00000000000000000000000000000000000000000000000000000000000000"
	const wwid = "360000000000000000e00000000010001"
	const target = "iqn.2026-11.corp.example:team"
	for i, node := range nodes {
		verifier, err := agent.NewVerifier(node, []string{public})
		if err != nil {
			t.Fatal(err)
		}
		handler := func(_ context.Context, method string, raw json.RawMessage) (any, error) {
			mu.Lock()
			defer mu.Unlock()
			var operation service.HostOperation
			if err := json.Unmarshal(raw, &operation); err != nil {
				return nil, err
			}
			var input struct {
				RequestID string
				Reference string
				Target    string
				Cluster   filecluster.Input
			}
			if len(operation.Input) > 0 {
				_ = json.Unmarshal(operation.Input, &input)
			}
			job := func(result any) filecluster.JobStatus {
				data, _ := json.Marshal(result)
				return filecluster.JobStatus{ID: input.RequestID, State: "completed", Result: data, Log: []string{"Действие подтверждено хелпером"}}
			}
			switch method {
			case "filecluster.catalog":
				rows := []clusterRef{}
				if staged.Name != "" {
					rows = append(rows, staged)
				}
				return map[string]any{"clusters": rows}, nil
			case "storage.inventory":
				return map[string]any{"platform": "p11", "stateDir": "/var/lib/sambaadm-helper", "workerHash": "same", "bootID": fmt.Sprint(boots[node]),
					"zfsReadiness": map[string]any{"ready": true, "moduleVersion": "2.4.2-1", "hostID": fmt.Sprint(i + 1)}}, nil
			case "filecluster.prerequisites":
				return map[string]string{"revision": revision}, nil
			case "filecluster.prepare", "filecluster.online", "storage.multipath.configure":
				return job(map[string]any{}), nil
			case "storage.iscsi.discover":
				return json.RawMessage(`{"discoveries":[{"targets":[{"iqn":"` + target + `"}]},{"targets":[{"iqn":"` + target + `"}]}]}`), nil
			case "storage.iscsi.connect":
				return job(map[string]any{"luns": []clusterLUN{{WWID: wwid, Size: 2 << 40}}}), nil
			case "filecluster.credentials.put":
				return map[string]string{"reference": input.Reference}, nil
			case "filecluster.fence.test":
				boots[input.Target]++
				return job(map[string]bool{"offConfirmed": true, "onConfirmed": true}), nil
			case "filecluster.stage":
				return job(map[string]string{"revision": revision, "platform": "p11", "zfsVersion": "2.4.2-1", "hostID": fmt.Sprint(i + 1)}), nil
			case "filecluster.initialize":
				staged = clusterRef{Name: "files", Realm: "corp.example", VIP: "10.77.0.50", Nodes: nodes, Revision: revision}
				return job(map[string]any{}), nil
			case "filecluster.status":
				return map[string]any{"owner": nodes[0], "localNode": node, "quorum": true, "platform": "p11", "onlineNodes": nodes,
					"snapshots": []map[string]string{{"label": "Перед обновлением", "name": "sambaadm_2026.11.26-14.15.16"}},
				}, nil
			}
			return nil, fmt.Errorf("unexpected fixture operation %s", method)
		}
		server := httptest.NewTLSServer(agent.API(verifier, handler))
		t.Cleanup(server.Close)
		ca := filepath.Join(dir, node+".crt")
		if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
			t.Fatal(err)
		}
		client.Config.Nodes = append(client.Config.Nodes, agent.Node{Name: node, Transport: "https", Endpoint: server.URL, CACert: ca})
	}
	return client
}
