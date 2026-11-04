package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"strings"
	"testing"
)

func TestControllerOverviewAccessAndTimeValidation(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{"", auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		sess, _ := s.sessions.Create("test", "CN=test", role)
		for _, path := range []string{"/sites/controllers/dc/authentications?after=invalid", "/sites/controllers/dc/authentications?before=invalid", "/sites/controllers/dc/authentications?after=2026-11-04T00:00:00Z&before=2026-11-03T00:00:00Z", "/sites/controllers/dc/authentications?account=" + strings.Repeat("x", 257)} {
			req := httptest.NewRequest("GET", "/api/v1"+path, nil)
			if role != "" {
				req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			}
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, req)
			want := 400
			if role == "" {
				want = 401
			} else if role != auth.RoleAdmin {
				want = 403
			}
			if w.Code != want {
				t.Fatalf("%s %s: %d %s", role, path, w.Code, w.Body.String())
			}
		}
		if role == auth.RoleAdmin {
			continue
		}
		for _, path := range []string{"/sites/controllers/dc/inventory", "/sites/topology/audit"} {
			method := "GET"
			if strings.HasSuffix(path, "audit") {
				method = "POST"
			}
			req := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(`{}`))
			req.Header.Set(csrfHeader, sess.CSRFToken)
			if role != "" {
				req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			}
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, req)
			want := 403
			if role == "" {
				want = 401
			}
			if w.Code != want {
				t.Fatalf("%s %s: %d", role, path, w.Code)
			}
		}
	}
	sess, _ := s.sessions.Create("test", "CN=test", auth.RoleAdmin)
	req := httptest.NewRequest("POST", "/api/v1/sites/topology/audit", strings.NewReader(`{}`))
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
