package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
	"strings"
	"testing"
)

func TestRODCRequiresAdminAndCSRFForMutations(t *testing.T) {
	s := testWorkspaceServer(t)
	s.svcs = &service.Services{RODC: &service.RODCService{}}
	for _, role := range []auth.Role{"", auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		sess, _ := s.sessions.Create("test", "CN=test", role)
		for _, method := range []string{"POST", "PUT", "GET"} {
			for _, csrf := range []bool{false, true} {
				path := "/api/v1/sites/controllers/dc1/rodc"
				if method == "GET" {
					path += "/authentications?after=invalid"
				}
				req := httptest.NewRequest(method, path, strings.NewReader(`{"operation":"invalid"}`))
				req.Header.Set("Content-Type", "application/json")
				if role != "" {
					req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
				}
				if csrf {
					req.Header.Set(csrfHeader, sess.CSRFToken)
				}
				w := httptest.NewRecorder()
				s.Router().ServeHTTP(w, req)
				want := 400
				if role == "" {
					want = 401
				} else if role != auth.RoleAdmin || (!csrf && method != "GET") {
					want = 403
				}
				if w.Code != want {
					t.Fatalf("%s %s csrf=%v: %d %s", role, method, csrf, w.Code, w.Body.String())
				}
			}
		}
	}
}
