package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sambaadm/internal/auth"
	"sambaadm/internal/i18n"
	"sambaadm/internal/service"
)

func TestTimeSettingsAccessAndCSRF(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, route := range []struct{ method, path string }{{"GET", "/settings/time"}, {"GET", "/api/v1/system/time"}, {"POST", "/settings/time"}, {"POST", "/api/v1/system/time/plan"}, {"PUT", "/api/v1/system/time"}} {
		for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
			sess, _ := s.sessions.Create("tester", "CN=tester", role)
			req := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			if role != auth.RoleAdmin || route.method != "GET" {
				if rec.Code != 403 {
					t.Fatalf("%s %s %s: %d", role, route.method, route.path, rec.Code)
				}
			} else if route.path == "/settings/time" && (rec.Code != 200 || !strings.Contains(rec.Body.String(), "Настройки времени")) {
				t.Fatalf("page: %d %s", rec.Code, rec.Body.String())
			}
		}
	}
	sess, _ := s.sessions.Create("admin", "CN=admin", auth.RoleAdmin)
	req := httptest.NewRequest("POST", "/api/v1/system/time/plan", strings.NewReader(`{"settings":{},"unexpected":true}`))
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	req.Header.Set(csrfHeader, sess.CSRFToken)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("unknown field accepted: %d", rec.Code)
	}
}
func TestTimeSettingsEscapesRemoteConfiguration(t *testing.T) {
	s := testWorkspaceServer(t)
	rec := httptest.NewRecorder()
	content := timePageContent{Nodes: []string{"node"}, Node: "node", Plan: &service.TimePlan{Proposed: "<script>bad()</script>"}, Settings: service.TimeSettings{Mode: "isolated", Stratum: 10}}
	s.render(rec, "settings/time.html", pageData{Lang: i18n.RU, Content: content})
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "<script>bad()") || !strings.Contains(rec.Body.String(), "&lt;script&gt;bad()") {
		t.Fatalf("unsafe or broken preview: %d %s", rec.Code, rec.Body.String())
	}
}
