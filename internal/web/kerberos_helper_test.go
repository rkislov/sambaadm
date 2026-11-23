package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/agent"
	"testing"
)

func TestSSOSYSVOLUsesExplicitServiceCredentials(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.LDAP.Bind.User = "sysvol-service@example.test"
	s.cfg.LDAP.Bind.PasswordEnv = "TEST_SSO_SYSVOL_PASSWORD"
	t.Setenv("TEST_SSO_SYSVOL_PASSWORD", "service-secret")
	for _, method := range []string{"kerberos", ""} {
		sess, err := s.sessions.Create("alice@example.test", "CN=alice", "admin")
		if err != nil {
			t.Fatal(err)
		}
		sess.AuthMethod = method
		handler := s.requireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			credentials, present, err := agent.OperationCredentials(r.Context())
			if method == "kerberos" {
				if err != nil || !present || credentials.Username != s.cfg.LDAP.Bind.User || credentials.Password != "service-secret" {
					t.Fatal("SSO SYSVOL must use configured service identity")
				}
			} else if err != nil || present {
				t.Fatal("password login without helper opt-in changed")
			}
			if s.sessions.HasHelperCredentials(sess.ID) {
				t.Fatal("service password stored in session")
			}
		}))
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		handler.ServeHTTP(httptest.NewRecorder(), req)
	}
}
