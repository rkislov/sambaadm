package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
	"strings"
	"testing"
)

func TestDelegationMutationRolesCSRFAndValidation(t *testing.T) {
	s := testWorkspaceServer(t)
	s.svcs = &service.Services{GPO: &service.GPOService{}}
	for _, role := range []auth.Role{"", auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		sess, _ := s.sessions.Create("test", "CN=test", role)
		for _, suffix := range []string{"delegation", "delegation/full"} {
			for _, method := range []string{"POST", "PUT"} {
				for _, csrf := range []bool{false, true} {
					req := httptest.NewRequest(method, "/api/v1/gpo/test/"+suffix, strings.NewReader(`{}`))
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
					} else if role != auth.RoleAdmin || !csrf {
						want = 403
					}
					if res.Code != want {
						t.Fatalf("role=%s method=%s csrf=%v: %d %s", role, method, csrf, res.Code, res.Body.String())
					}
				}
			}
		}
	}
}

func TestFullDelegationHistoryRequiresAdmin(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk} {
		sess, _ := s.sessions.Create("test", "CN=test", role)
		req := httptest.NewRequest("GET", "/api/v1/gpo/test/delegation/full", nil)
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		res := httptest.NewRecorder()
		s.Router().ServeHTTP(res, req)
		if res.Code != 403 {
			t.Fatalf("%s: %d", role, res.Code)
		}
	}
}
