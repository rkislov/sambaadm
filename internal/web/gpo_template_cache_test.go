package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/auth"
	"strings"
	"testing"
	"time"
)

func TestTemplateImportRequiresAdminAndCSRF(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
		for _, csrf := range []bool{false, true} {
			sess, _ := s.sessions.Create("test", "CN=test", role)
			req := httptest.NewRequest("POST", "/api/v1/gpo/templates/import", nil)
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			if csrf {
				req.Header.Set(csrfHeader, sess.CSRFToken)
			}
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, req)
			expected := 403
			if role == auth.RoleAdmin && csrf {
				expected = 503
			}
			if w.Code != expected {
				t.Fatalf("role=%s csrf=%v status=%d body=%s", role, csrf, w.Code, w.Body.String())
			}
		}
	}
}
func TestEditorDeadlineIsGatewayTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	w := httptest.NewRecorder()
	editorError(w, ctx.Err())
	if w.Code != 504 || !strings.Contains(w.Body.String(), "deadline") {
		t.Fatal(w.Code, w.Body.String())
	}
}
