package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"strings"
	"testing"
)

func TestDemoteAdminCSRFAndIdentityGates(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk} {
		session, _ := s.sessions.Create(string(role), "cn=test", role)
		for _, path := range []string{"/api/v1/domain-demote/plan", "/api/v1/domain-demote/start", "/api/v1/domain-demote/resume"} {
			r := httptest.NewRequest("POST", path, strings.NewReader(`{}`))
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
	for _, body := range []string{`{"node":"dc1.corp.test","source":"dc1.corp.test","realm":"corp.test","username":"admin","password":"test"}`, `{"node":"dc2.other.test","source":"dc1.other.test","realm":"other.test","username":"admin","password":"test"}`, `{"command":"rm"}`, `{} {}`} {
		r := httptest.NewRequest("POST", "/api/v1/domain-demote/start", strings.NewReader(body))
		r.Header.Set("X-CSRF-Token", admin.CSRFToken)
		r.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: admin.ID})
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
	r := httptest.NewRequest("POST", "/api/v1/domain-demote/start", strings.NewReader(`{}`))
	r.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: admin.ID})
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("missing CSRF", w.Code)
	}
	r = httptest.NewRequest("GET", "/settings/domain-demote", nil)
	r.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: admin.ID})
	w = httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "data-domain-demote") {
		t.Fatal(w.Code, w.Body)
	}
}
