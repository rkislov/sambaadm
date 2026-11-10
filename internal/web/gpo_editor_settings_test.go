package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sambaadm/internal/auth"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
)

func TestGPOEditorSettingAdminCSRFAndPersistence(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.GPO.ManagedEditorFile = filepath.Join(t.TempDir(), "settings", "gpo-editor.json")
	s.svcs = service.NewWithOptions(ldapproto.NewClient(s.cfg.LDAP), nil, service.ServiceOptions{GPO: s.cfg.GPO})
	post := func(role auth.Role, csrf bool, enabled string) *httptest.ResponseRecorder {
		sess, _ := s.sessions.Create("test", "CN=test", role)
		form := url.Values{"enabled": {enabled}}
		if csrf {
			form.Set("csrf_token", sess.CSRFToken)
		}
		req := httptest.NewRequest("POST", "/settings/gpo-editor", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if role != "" {
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		}
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, req)
		return w
	}
	for _, tc := range []struct {
		role   auth.Role
		csrf   bool
		status int
	}{
		{"", true, 303}, {auth.RoleReadonly, true, 403}, {auth.RoleHelpdesk, true, 403}, {auth.RoleAdmin, false, 403},
	} {
		if w := post(tc.role, tc.csrf, "true"); w.Code != tc.status {
			t.Fatalf("role=%s csrf=%v: %d %s", tc.role, tc.csrf, w.Code, w.Body)
		}
	}
	if _, err := os.Stat(s.cfg.GPO.ManagedEditorFile); !os.IsNotExist(err) {
		t.Fatal("unauthorized request saved setting", err)
	}
	for _, value := range []string{"true", ""} {
		w := post(auth.RoleAdmin, true, value)
		if w.Code != 303 {
			t.Fatalf("save: %d %s", w.Code, w.Body)
		}
		enabled, err := s.svcs.GPO.EditorEnabled()
		if err != nil || enabled != (value == "true") {
			t.Fatal("setting not applied", enabled, err)
		}
		reloaded := service.NewWithOptions(ldapproto.NewClient(s.cfg.LDAP), nil, service.ServiceOptions{GPO: s.cfg.GPO})
		enabled, err = reloaded.GPO.EditorEnabled()
		if err != nil || enabled != (value == "true") {
			t.Fatal("setting lost after reload", enabled, err)
		}
		info, err := os.Stat(s.cfg.GPO.ManagedEditorFile)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("unsafe setting permissions", err)
		}
	}
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReadonly} {
		sess, _ := s.sessions.Create("test", "CN=test", role)
		req := httptest.NewRequest("GET", "/settings", nil)
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, req)
		if w.Code != 200 || strings.Contains(w.Body.String(), `action="/settings/gpo-editor"`) != (role == auth.RoleAdmin) {
			t.Fatalf("settings view role=%s: %d %s", role, w.Code, w.Body)
		}
	}
	if w := post(auth.RoleAdmin, true, "garbage"); w.Code != 400 {
		t.Fatal("accepted malformed setting", w.Code)
	}
}
