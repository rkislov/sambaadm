package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"sambaadm/internal/auth"
)

func TestBulkDistributionRequiresAdminAndCSRF(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, tc := range []struct {
		role auth.Role
		csrf bool
		want int
	}{
		{want: http.StatusUnauthorized},
		{role: auth.RoleReadonly, csrf: true, want: http.StatusForbidden},
		{role: auth.RoleHelpdesk, csrf: true, want: http.StatusForbidden},
		{role: auth.RoleAdmin, want: http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/gpo/distribute", nil)
		if tc.role != "" {
			sess, err := s.sessions.Create("test", "CN=test", tc.role)
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			if tc.csrf {
				req.Header.Set(csrfHeader, sess.CSRFToken)
			}
		}
		res := httptest.NewRecorder()
		s.Router().ServeHTTP(res, req)
		if res.Code != tc.want {
			t.Errorf("role %q, CSRF %v: got %d, want %d (%s)", tc.role, tc.csrf, res.Code, tc.want, res.Body)
		}
	}
}
