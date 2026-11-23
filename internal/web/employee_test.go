package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"strings"
	"testing"
)

func TestEmployeeRequiresAdminCSRFAndConfirmation(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		for _, csrf := range []bool{false, true} {
			for _, operation := range []string{"apply", "review"} {
				sess, _ := s.sessions.Create("actor", "CN=actor", role)
				req := httptest.NewRequest("POST", "/api/v1/employees/plans/"+strings.Repeat("a", 32)+"/"+operation, strings.NewReader(`{"confirm":false}`))
				req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
				if csrf {
					req.Header.Set("X-CSRF-Token", sess.CSRFToken)
				}
				rec := httptest.NewRecorder()
				s.Router().ServeHTTP(rec, req)
				want := 403
				if role == auth.RoleAdmin && csrf {
					want = 400
				}
				if rec.Code != want {
					t.Fatalf("%s %s csrf %v: got %d want %d %s", role, operation, csrf, rec.Code, want, rec.Body)
				}
			}
		}
	}
	for _, path := range []string{"/employees/plans", "/employees/context?login=alice", "/employees/choices?kind=user&q=al", "/employees/parent?dn=DC=example,DC=com"} {
		for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk} {
			sess, _ := s.sessions.Create("actor", "CN=actor", role)
			req := httptest.NewRequest("GET", "/api/v1"+path, nil)
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			if rec.Code != 403 {
				t.Fatal("read access", rec.Code)
			}
		}
	}
}
func TestEmployeePreviewRejectsPassword(t *testing.T) {
	s := testWorkspaceServer(t)
	sess, _ := s.sessions.Create("actor", "CN=actor", auth.RoleAdmin)
	req := httptest.NewRequest("POST", "/api/v1/employees/plans", strings.NewReader(`{"scenario":"join","login":"alice","password":"Secret-Do-Not-Persist"}`))
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	req.Header.Set("X-CSRF-Token", sess.CSRFToken)
	rec := httptest.NewRecorder()
	s.Router().ServeHTTP(rec, req)
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "Secret-Do-Not-Persist") {
		t.Fatal(rec.Code, rec.Body)
	}
}
