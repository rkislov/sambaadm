package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
	"strings"
	"testing"
)

func TestConsistencySessionCSRFAndReadRoles(t *testing.T) {
	s := testWorkspaceServer(t)
	s.svcs = &service.Services{GPO: &service.GPOService{}}
	for _, role := range []auth.Role{"", auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		sess, _ := s.sessions.Create("test", "CN=test", role)
		for _, csrf := range []bool{false, true} {
			req := httptest.NewRequest("POST", "/api/v1/gpo/invalid/consistency", strings.NewReader(`{}`))
			req.Header.Set("Content-Type", "application/json")
			if role != "" {
				req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			}
			if csrf {
				req.Header.Set(csrfHeader, sess.CSRFToken)
			}
			res := httptest.NewRecorder()
			s.Router().ServeHTTP(res, req)
			want := 400
			if role == "" {
				want = 401
			} else if !csrf {
				want = 403
			}
			if res.Code != want {
				t.Fatalf("%s csrf=%v: %d %s", role, csrf, res.Code, res.Body.String())
			}
		}
	}
}
