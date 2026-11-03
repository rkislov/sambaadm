package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
	"strings"
	"testing"
)

func TestRepairAdminAndCSRF(t *testing.T) {
	s := testWorkspaceServer(t)
	s.svcs = &service.Services{GPO: &service.GPOService{}}
	for _, role := range []auth.Role{"", auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		sess, _ := s.sessions.Create("test", "CN=test", role)
		for _, csrf := range []bool{false, true} {
			for _, method := range []string{"GET", "POST", "PUT"} {
				req := httptest.NewRequest(method, "/api/v1/gpo/invalid/repair", strings.NewReader(`{"operation":"prune","record":"10000000-0000-0000-0000-000000000001","preview":"stale"}`))
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
				} else if (!csrf && method != "GET") || role != auth.RoleAdmin {
					want = 403
				}
				if res.Code != want {
					t.Fatalf("%s csrf=%v: %d %s", role, csrf, res.Code, res.Body.String())
				}
			}
		}
	}
}
