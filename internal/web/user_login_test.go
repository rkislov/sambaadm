package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"strings"
	"testing"
)

func TestUnlockRequiresRoleCSRFAndExplicitConfirmation(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, test := range []struct {
		role auth.Role
		csrf bool
		body string
		want int
	}{
		{auth.RoleReadonly, true, `{"revision":"r","confirm":true}`, 403},
		{auth.RoleHelpdesk, false, `{"revision":"r","confirm":true}`, 403},
		{auth.RoleHelpdesk, true, `{"revision":"r","confirm":false}`, 400},
		{auth.RoleAdmin, true, `{"confirm":true}`, 400},
		{auth.RoleAdmin, true, `{"revision":"r","confirm":true,"userAccountControl":512}`, 400},
		{auth.RoleAdmin, true, `{"revision":"r","confirm":true} {}`, 400},
	} {
		sess, _ := s.sessions.Create("actor", "CN=actor", test.role)
		req := httptest.NewRequest("POST", "/api/v1/users/alice/unlock", strings.NewReader(test.body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		if test.csrf {
			req.Header.Set("X-CSRF-Token", sess.CSRFToken)
		}
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		if rec.Code != test.want {
			t.Fatalf("role=%s csrf=%v: got %d, want %d", test.role, test.csrf, rec.Code, test.want)
		}
	}
	req := httptest.NewRequest("GET", "/api/v1/users/alice/login-status", nil)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatal("anonymous diagnosis allowed")
	}
}
