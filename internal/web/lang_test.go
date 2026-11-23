package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/i18n"
	"strings"
	"testing"
)

func TestRussianDefaultAndExplicitEnglish(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, tt := range []struct{ cookie, want string }{{"", "Вход"}, {"ru", "Вход"}, {"en", "Sign in"}} {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		if tt.cookie != "" {
			req.AddCookie(&http.Cookie{Name: langCookie, Value: tt.cookie})
		}
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		if !strings.Contains(rec.Body.String(), tt.want) {
			t.Fatalf("cookie %q: expected %s", tt.cookie, tt.want)
		}
	}
	rec := httptest.NewRecorder()
	s.render(rec, "dashboard.html", pageData{Lang: i18n.RU, Content: map[string]any{}})
	if !strings.Contains(rec.Body.String(), "Обзор домена") || strings.Contains(rec.Body.String(), "Domain overview") {
		t.Fatal("Russian language branch was not rendered")
	}
}
