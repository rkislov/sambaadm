package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"strings"
	"testing"
)

func TestDNSRoutingAccessAndStrictInput(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, route := range []struct{ method, path string }{{"GET", "/dns/routing"}, {"GET", "/api/v1/dns/routing/nodes"}, {"GET", "/api/v1/dns/forwarding"}, {"POST", "/api/v1/dns/forwarding/plan"}, {"PUT", "/api/v1/dns/forwarding"}, {"GET", "/api/v1/dns/zones/ipr.loc/delegations"}, {"POST", "/api/v1/dns/zones/ipr.loc/delegations/plan"}, {"PUT", "/api/v1/dns/zones/ipr.loc/delegations"}, {"POST", "/api/v1/dns/backend/plan"}, {"POST", "/api/v1/dns/backend/start"}, {"GET", "/api/v1/dns/backend/status"}} {
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
			} else if route.path == "/dns/routing" && (rec.Code != 200 || !strings.Contains(rec.Body.String(), "Условная пересылка")) {
				t.Fatalf("page: %d %s", rec.Code, rec.Body.String())
			}
		}
	}
	sess, _ := s.sessions.Create("admin", "CN=admin", auth.RoleAdmin)
	req := httptest.NewRequest("POST", "/api/v1/dns/zones/ipr.loc/delegations/plan", strings.NewReader(`{"unexpected":true}`))
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	req.Header.Set(csrfHeader, sess.CSRFToken)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("unknown input allowed: %d", rec.Code)
	}
}
