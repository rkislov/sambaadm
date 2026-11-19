package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
	"strings"
	"testing"
)

func TestObjectBackupAccessAndCSRF(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.BackupDir = t.TempDir()
	routes := []struct{ method, path string }{{"GET", "/api/v1/backups/full"}, {"POST", "/api/v1/backups/full/prepare"}, {"GET", "/api/v1/backups/full/invalid"}, {"POST", "/api/v1/backups/full/invalid/start"}, {"GET", "/backups"}, {"POST", "/backups"}, {"GET", "/api/v1/backups"}, {"POST", "/api/v1/backups"}, {"GET", "/api/v1/backups/invalid"}, {"GET", "/api/v1/backups/invalid/objects/invalid/preview"}, {"POST", "/api/v1/backups/invalid/objects/invalid/restore"}}
	for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk} {
		sess, _ := s.sessions.Create("tester", "CN=test", role)
		for _, route := range routes {
			req := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			req.Header.Set(csrfHeader, sess.CSRFToken)
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			if rec.Code != 403 {
				t.Fatalf("%s %s %s: %d", role, route.method, route.path, rec.Code)
			}
		}
	}
	sess, _ := s.sessions.Create("admin", "CN=admin", auth.RoleAdmin)
	for _, route := range routes {
		if route.method != "POST" {
			continue
		}
		req := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Fatalf("missing CSRF %s: %d", route.path, rec.Code)
		}
	}
	req := httptest.NewRequest("GET", "/backups", nil)
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), sess.CSRFToken) || !strings.Contains(rec.Body.String(), "Создать резервную копию") {
		t.Fatalf("page: %d %s", rec.Code, rec.Body.String())
	}
}

func TestFullBackupPreparationFormAndStatusRender(t *testing.T) {
	s := testWorkspaceServer(t)
	rec := httptest.NewRecorder()
	s.render(rec, "backups.html", pageData{Role: auth.RoleAdmin, CSRF: "test-csrf", Content: backupPageContent{Nodes: []string{"dc.example.com"}, FullPlan: &service.DomainBackupRequest{ID: "00000000-0000-0000-0000-000000000001", Controller: "dc.example.com", PlanRevision: "prepared-revision"}, FullJob: &service.DomainBackupJob{Status: "failed", Error: "<script>unsafe</script>"}}})
	body := rec.Body.String()
	for _, want := range []string{"full-prepare", "full-start", "confirmStopped", "prepared-revision", "test-csrf", "&lt;script&gt;unsafe&lt;/script&gt;"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %s in %s", want, body)
		}
	}
	if strings.Contains(body, "<script>unsafe</script>") {
		t.Fatal("unescaped worker error")
	}
}
