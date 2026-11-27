package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sambaadm/internal/auth"
)

func TestOverviewAndFileClusterRoles(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			session, _ := s.sessions.Create("cluster-"+string(role), "CN=cluster", role)
			for _, path := range []string{"/", "/file-clusters", "/api/v1/file-clusters", "/api/v1/services/overview"} {
				req := httptest.NewRequest("GET", path, nil)
				req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: session.ID})
				rec := httptest.NewRecorder()
				s.Router().ServeHTTP(rec, req)
				if rec.Code != 200 {
					t.Fatalf("GET %s: %d: %s", path, rec.Code, rec.Body.String())
				}
				if path == "/file-clusters" && strings.Contains(rec.Body.String(), `id="fc-setup"`) != auth.CanAdmin(role) {
					t.Fatal("role and available controls differ")
				}
			}
			if auth.CanAdmin(role) {
				return
			}
			for _, operation := range []struct{ method, path string }{
				{"GET", "/jobs/00000000000000000000000000000000"},
				{"GET", "/setup/00000000000000000000000000000000"},
				{"POST", "/setup"},
				{"POST", "/setup/00000000000000000000000000000000/deploy"},
				{"POST", "/snapshot"},
				{"POST", "/snapshot-schedule"},
				{"POST", "/restore/browse"},
				{"POST", "/restore/preview"},
				{"POST", "/restore/apply"},
			} {
				req := httptest.NewRequest(operation.method, "/api/v1/file-clusters"+operation.path, strings.NewReader("{}"))
				req.Header.Set(csrfHeader, session.CSRFToken)
				req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: session.ID})
				rec := httptest.NewRecorder()
				s.Router().ServeHTTP(rec, req)
				if rec.Code != http.StatusForbidden {
					t.Errorf("%s %s: got %d, expected 403", operation.method, operation.path, rec.Code)
				}
			}
		})
	}
	req := httptest.NewRequest("GET", "/api/v1/services/overview", nil)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("unauthenticated overview returned %d", rec.Code)
	}
}

func TestDashboardClusterUsesConfirmedOwner(t *testing.T) {
	ref := clusterRef{Name: "files", Realm: "example.test", Nodes: []string{"fs1", "fs2"}}
	if got := summarizeDashboardCluster(ref, nil); got.State != "unknown" {
		t.Fatalf("missing results interpreted as outage: %+v", got)
	}
	mp := json.RawMessage(`{"paths":[{"ready":true},{"ready":true}]}`)
	fs1 := clusterNodeStatus{Node: "fs1", LocalNode: "fs1", Owner: "fs2", OnlineNodes: ref.Nodes, Quorum: true, Multipath: mp}
	if got := summarizeDashboardCluster(ref, []clusterNodeStatus{fs1}); got.Owner != "" || got.State != "unknown" {
		t.Fatalf("claimed owner accepted without its reply: %+v", got)
	}
	noOwner := fs1
	noOwner.Owner = ""
	if got := summarizeDashboardCluster(ref, []clusterNodeStatus{noOwner}); got.State != "no-owner" {
		t.Fatalf("confirmed cluster without SMB not reported: %+v", got)
	}
	fs2 := clusterNodeStatus{Node: "fs2", LocalNode: "fs2", Owner: "fs2", OnlineNodes: ref.Nodes, Quorum: true, Multipath: mp}
	if got := summarizeDashboardCluster(ref, []clusterNodeStatus{fs1, fs2}); got.State != "active" || got.Nodes[0].State != "reserve" || got.Nodes[1].State != "active" {
		t.Fatalf("expected healthy service: %+v", got)
	}
	ready := false
	fs2.SMBReady = &ready
	if got := summarizeDashboardCluster(ref, []clusterNodeStatus{fs1, fs2}); got.State != "transition" || got.Owner != "" || got.Nodes[1].State != "transition" {
		t.Fatalf("SMB shown ready before its listener: %+v", got)
	}
	ready = true
	fs2.Multipath = json.RawMessage(`{"paths":[{"ready":true},{"ready":false}]}`)
	if got := summarizeDashboardCluster(ref, []clusterNodeStatus{fs1, fs2}); got.State != "degraded" || got.Owner != "fs2" || got.Nodes[1].ReadyPaths != 1 {
		t.Fatalf("path failure was not reported: %+v", got)
	}
}
