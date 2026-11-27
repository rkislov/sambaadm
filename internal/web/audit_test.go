package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
)

func TestConsoleAuditRecordsAllRolesAndDeniedActions(t *testing.T) {
	s := testWorkspaceServer(t)
	path := filepath.Join(t.TempDir(), "audit.log")
	logger, err := audit.New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	s.audit = logger
	type entry struct {
		actor, method, path, route, body string
		role                             auth.Role
		status                           int
	}
	cases := []entry{
		{"reader", "GET", "/settings?token=query-secret", "/settings", "", auth.RoleReadonly, 200},
		{"operator", "GET", "/audit", "/audit", "", auth.RoleHelpdesk, 403},
		{"operator", "PUT", "/api/v1/dns/zones/private-zone/records?token=query-secret", "/api/v1/dns/zones/{zone}/records", "body-secret", auth.RoleHelpdesk, 403},
		{"admin", "GET", "/audit", "/audit", "", auth.RoleAdmin, 200},
	}
	for _, c := range cases {
		sess, err := s.sessions.Create(c.actor, "CN=Fixture", c.role)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		req.RemoteAddr = "192.0.2.1:23456"
		req.Header.Set("X-Forwarded-For", "192.0.2.42")
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		if rec.Code != c.status {
			t.Fatalf("%s gave %d, want %d", c.path, rec.Code, c.status)
		}
	}
	events, err := logger.Recent(4)
	if err != nil || len(events) != len(cases) {
		t.Fatalf("recent=%+v err=%v", events, err)
	}
	for i, c := range cases {
		event := events[i]
		wantResult := "success"
		if c.status >= 400 {
			wantResult = "failure"
		}
		if event.Action != "web.request" || event.Actor != c.actor || event.Role != string(c.role) ||
			event.Result != wantResult || event.Target != c.route || event.Method != c.method ||
			event.IP != "192.0.2.1" || event.HTTPStatus != c.status {
			t.Errorf("action %s: %+v", c.path, event)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-zone", "query-secret", "body-secret", "192.0.2.42"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("audit includes private request data %q", forbidden)
		}
	}
}
