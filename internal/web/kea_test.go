package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sambaadm/internal/auth"
	"sambaadm/internal/i18n"
	"strings"
	"testing"
)

func TestKeaAccessAndCSRF(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, route := range []struct{ method, path string }{{"POST", "/api/v1/dhcp/gss/ad/pair/plan"}, {"POST", "/api/v1/dhcp/gss/ad/pair/apply"}, {"POST", "/api/v1/dhcp/gss/install/plan"}, {"POST", "/api/v1/dhcp/gss/install/start"}, {"GET", "/api/v1/dhcp/gss/install/status?jobID=123"}, {"POST", "/api/v1/dhcp/gss/ad/plan"}, {"POST", "/api/v1/dhcp/gss/ad/apply"}, {"GET", "/dhcp"}, {"GET", "/api/v1/dhcp"}, {"GET", "/api/v1/dhcp/ddns"}, {"POST", "/api/v1/dhcp/ddns/plan"}, {"POST", "/api/v1/dhcp/ddns/apply"}, {"POST", "/api/v1/dhcp/ddns/service"}, {"GET", "/api/v1/dhcp/leases?subnetID=1"}, {"POST", "/api/v1/dhcp/leases/delete"}, {"POST", "/api/v1/dhcp/leases/reservation/plan"}, {"POST", "/api/v1/dhcp/plan"}, {"POST", "/api/v1/dhcp/apply"}, {"POST", "/api/v1/dhcp/service"}, {"POST", "/api/v1/dhcp/install/plan"}, {"POST", "/api/v1/dhcp/install"}} {
		for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
			sess, _ := s.sessions.Create("tester", "CN=tester", role)
			req := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			if role != auth.RoleAdmin || route.method != "GET" {
				if rec.Code != 403 {
					t.Fatalf("%s %s %s: %d", role, route.method, route.path, rec.Code)
				}
			} else if route.path == "/dhcp" && rec.Code != 200 {
				t.Fatalf("page: %d %s", rec.Code, rec.Body.String())
			}
		}
	}
	sess, _ := s.sessions.Create("admin", "CN=admin", auth.RoleAdmin)
	for _, body := range []string{`{"family":"4","unexpected":true}`, `{"family":"4"} {}`} {
		req := httptest.NewRequest("POST", "/api/v1/dhcp/plan", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		req.Header.Set(csrfHeader, sess.CSRFToken)
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("bad request: %d", rec.Code)
		}
	}
}
func TestKeaBrowserFixture(t *testing.T) {
	dir := os.Getenv("SAMBAADM_KEA_FIXTURE_DIR")
	if dir == "" {
		t.Skip("browser fixture")
	}
	s := testWorkspaceServer(t)
	rec := httptest.NewRecorder()
	s.render(rec, "dhcp/index.html", pageData{Lang: i18n.RU, Title: "DHCP", CSRF: "test-csrf", Role: auth.RoleAdmin, Content: keaPageContent{Nodes: []string{"dhcp1.example.test", "dhcp2.example.test"}}})
	if rec.Code != 200 {
		t.Fatalf("render: %s", rec.Body.String())
	}
	if e := os.WriteFile(filepath.Join(dir, "dhcp.html"), rec.Body.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
}
