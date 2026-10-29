package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"sambaadm/internal/i18n"
	"sambaadm/internal/service"
	"strings"
	"testing"
)

func TestDiagnosticsAccessAndCSRF(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{"", auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		for _, path := range []string{"/diagnostics/run", "/api/v1/system/diagnostics"} {
			req := httptest.NewRequest("POST", path, nil)
			if role != "" {
				sess, _ := s.sessions.Create("tester", "CN=tester", role)
				req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
				if role != auth.RoleAdmin {
					req.Header.Set(csrfHeader, sess.CSRFToken)
				}
			}
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden && rec.Code != http.StatusUnauthorized && rec.Code != http.StatusSeeOther {
				t.Fatalf("%s %s: %d", role, path, rec.Code)
			}
		}
	}
	sess, _ := s.sessions.Create("tester", "CN=tester", auth.RoleAdmin)
	req := httptest.NewRequest("GET", "/diagnostics", nil)
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "/diagnostics/run") || !strings.Contains(rec.Body.String(), sess.CSRFToken) {
		t.Fatalf("diagnostics page: %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/diagnostics", nil)
	low, _ := s.sessions.Create("reader", "CN=reader", auth.RoleReadonly)
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: low.ID})
	rec = httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("readonly page: %d", rec.Code)
	}
}

func TestDiagnosticsReportEscapesRemoteErrors(t *testing.T) {
	s := testWorkspaceServer(t)
	report := &service.DiagnosticReport{Checks: []service.DiagnosticCheck{{ID: "ldap", Status: "error", Detail: "<script>bad()</script>", Hint: "Check service account"}}}
	rec := httptest.NewRecorder()
	s.render(rec, "diagnostics/report", pageData{Lang: i18n.RU, Content: report})
	body := rec.Body.String()
	if strings.Contains(body, "<script>") || !strings.Contains(body, "&lt;script&gt;") || !strings.Contains(body, "badge-failed") {
		t.Fatalf("invalid report: %s", body)
	}
}

func TestScriptBackupEndpointsRequireAdmin(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk} {
		sess, _ := s.sessions.Create("test", "CN=test", role)
		for _, suffix := range []string{"maintenance", "preview?source=pending&mode=before", "backup?name=pending&revision=x"} {
			req := httptest.NewRequest("GET", "/api/v1/gpo/{00000000-0000-0000-0000-000000000001}/scripts/"+suffix, nil)
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			if rec.Code != 403 {
				t.Fatalf("%s %s: %d", role, suffix, rec.Code)
			}
		}
	}
}
