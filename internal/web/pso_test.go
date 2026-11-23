package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"strings"
	"testing"
)

func TestPSOMutationsRequireAdminCSRFAndConfirmation(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
			for _, csrf := range []bool{false, true} {
				path := "/api/v1/domain/password-policies"
				if method != "POST" {
					path += "/31323334353637383930616263646566"
				}
				sess, _ := s.sessions.Create("actor", "CN=actor", role)
				req := httptest.NewRequest(method, path, strings.NewReader(`{"confirm":false}`))
				req.Header.Set("Content-Type", "application/json")
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
					t.Fatalf("%s %s csrf=%v: got %d want %d", method, role, csrf, rec.Code, want)
				}
			}
		}
	}
	for _, path := range []string{"/api/v1/domain/password-policies", "/api/v1/users/alice/password-policy"} {
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 401 {
			t.Fatal("anonymous PSO access allowed")
		}
	}
}

func TestPSOWriteRequiresEveryPolicyField(t *testing.T) {
	s := testWorkspaceServer(t)
	sess, _ := s.sessions.Create("actor", "CN=actor", auth.RoleAdmin)
	complete := map[string]any{"name": "PSO", "description": "", "precedence": 1, "minLength": 18, "historyLength": 24, "complexity": true, "minAgeDays": 0, "maxAgeDays": 42, "lockoutThreshold": 5, "lockoutDurationMinutes": 30, "lockoutWindowMinutes": 30, "reversibleEncryption": false, "subjects": []any{}, "confirm": true}
	for _, key := range []string{"complexity", "subjects", "reversibleEncryption", "minLength"} {
		for _, null := range []bool{false, true} {
			body := map[string]any{}
			for k, v := range complete {
				body[k] = v
			}
			if null {
				body[key] = nil
			} else {
				delete(body, key)
			}
			raw, _ := json.Marshal(body)
			req := httptest.NewRequest("POST", "/api/v1/domain/password-policies", strings.NewReader(string(raw)))
			req.Header.Set("X-CSRF-Token", sess.CSRFToken)
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			if rec.Code != 400 {
				t.Fatalf("missing/null %s reached LDAP: %d", key, rec.Code)
			}
		}
	}
}
