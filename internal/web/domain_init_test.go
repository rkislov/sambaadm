package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"strings"
	"testing"
)

func TestDomainInitRequiresAdminAndRejectsForestOrForeignTarget(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk} {
		session, _ := s.sessions.Create("test-"+string(role), "cn=test", role)
		for _, path := range []string{"/api/v1/domain-init/plan", "/api/v1/domain-init/start"} {
			r := httptest.NewRequest("POST", path, strings.NewReader(`{"mode":"forest"}`))
			r.Header.Set("X-CSRF-Token", session.CSRFToken)
			r.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: session.ID})
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal(role, path, w.Code, w.Body)
			}
		}
	}
	admin, _ := s.sessions.Create("admin", "cn=admin", auth.RoleAdmin)
	for _, body := range []string{`{"mode":"forest","realm":"example.com","hostname":"dc1","node":"dc1.example.com"}`, `{"mode":"DC","realm":"other.test","hostname":"dc1","node":"dc1.other.test"}`} {
		r := httptest.NewRequest("POST", "/api/v1/domain-init/start", strings.NewReader(body))
		r.Header.Set("X-CSRF-Token", admin.CSRFToken)
		r.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: admin.ID})
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
	r := httptest.NewRequest("GET", "/settings/domain-init", nil)
	r.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: admin.ID})
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "data-domain-init") {
		t.Fatal(w.Code, w.Body)
	}
}
