package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func TestPolicyModelSessionCSRFAndReadonlyAccess(t *testing.T) {
	s := testWorkspaceServer(t)
	s.svcs = &service.Services{GPO: &service.GPOService{}}
	for _, role := range []auth.Role{"", auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		sess, _ := s.sessions.Create("test", "CN=test", role)
		for _, csrf := range []bool{false, true} {
			request := httptest.NewRequest("POST", "/api/v1/gpo/model", strings.NewReader(`{}`))
			request.Header.Set("Content-Type", "application/json")
			if role != "" {
				request.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			}
			if csrf {
				request.Header.Set(csrfHeader, sess.CSRFToken)
			}
			response := httptest.NewRecorder()
			s.Router().ServeHTTP(response, request)
			want := http.StatusBadRequest // Any authenticated role can simulate; empty input fails before accessing LDAP.
			if role == "" {
				want = http.StatusUnauthorized
			} else if !csrf {
				want = http.StatusForbidden
			}
			if response.Code != want {
				t.Fatalf("role=%s csrf=%v: got %d, want %d: %s", role, csrf, response.Code, want, response.Body.String())
			}
		}
	}
}
