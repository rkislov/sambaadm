package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
	"strings"
	"testing"
	"time"

	"sambaadm/internal/auth"
	"sambaadm/internal/config"
)

func TestDirectoryTreeEscapedDNAndContainers(t *testing.T) {
	entries := []directoryEntry{
		{`CN=Smith\, Alice,OU=People,DC=example,DC=com`, "alice", "user"},
		{`CN=Bob,CN=Users,DC=EXAMPLE,DC=COM`, "bob", "user"},
		{`OU=People,DC=example,DC=com`, "People", "ou"},
		{`CN=Outside,DC=another,DC=com`, "outside", "user"},
		{`CN=App+UID=17,OU=People,DC=example,DC=com`, "app", "user"},
	}
	root, err := directoryTree("DC=example,DC=com", entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(root.Children) != 2 {
		t.Fatalf("expected OU and Users container: %+v", root.Children)
	}
	var people, users *DirectoryNode
	for _, n := range root.Children {
		if n.Kind == "ou" {
			people = n
		} else {
			users = n
		}
	}
	if people == nil || len(people.Children) != 2 || people.Children[0].Label != "alice" {
		t.Fatalf("escaped RDN was split or ordering is wrong: %+v", people)
	}
	if users == nil || len(users.Children) != 1 || users.Children[0].ParentDN != users.DN {
		t.Fatalf("standard Users container missing: %+v", users)
	}
	if people.Children[0].ObjectDN != entries[0].DN {
		t.Fatal("original DN not preserved")
	}
	if _, e := directoryTree("", nil); e == nil {
		t.Fatal("empty base DN accepted")
	}
	if _, e := directoryTree("DC=example,DC=com", []directoryEntry{{"invalid", "x", "user"}}); e == nil {
		t.Fatal("invalid entry accepted")
	}
}
func testWorkspaceServer(t *testing.T) *Server {
	t.Helper()
	s, e := New(Options{Config: &config.Config{LDAP: config.LDAPConfig{BaseDN: "DC=example,DC=com"}}, Sessions: auth.NewStore(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	return s
}

// Service pointers are intentionally nil: rejected requests must never reach a mutation.
func TestExtendedMutationsEnforceSessionRoleCSRFAndInput(t *testing.T) {
	routes := []struct{ method, path string }{
		{"PUT", "/api/v1/gpo/{00000000-0000-0000-0000-000000000001}/alt-settings"},
		{"POST", "/api/v1/users/alice/move"}, {"POST", "/api/v1/computers/pc/move"},
		{"POST", "/api/v1/groups/Finance/members"}, {"DELETE", "/api/v1/groups/Finance/members"},
		{"POST", "/api/v1/ou/move"}, {"POST", "/api/v1/subnets/delete"},
		{"POST", "/api/v1/domain/fsmo/seize"}, {"POST", "/api/v1/domain/level/raise"},
		{"PUT", "/api/v1/dns/zones/example.com/records"}, {"POST", "/api/v1/shares/server/param"},
	}
	s := testWorkspaceServer(t)
	for _, route := range routes {
		for _, role := range []auth.Role{"", auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin} {
			sess, _ := s.sessions.Create("test", "CN=test", role)
			for _, csrf := range []bool{false, true} {
				req := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
				req.Header.Set("Content-Type", "application/json")
				if role != "" {
					req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
				}
				if csrf {
					req.Header.Set(csrfHeader, sess.CSRFToken)
				}
				rec := httptest.NewRecorder()
				s.Router().ServeHTTP(rec, req)
				expected := http.StatusForbidden
				if role == "" {
					expected = http.StatusUnauthorized
				} else if role == auth.RoleAdmin && csrf {
					expected = http.StatusBadRequest
				}
				if rec.Code != expected {
					t.Fatalf("%s %s role=%q csrf=%v got %d want %d: %s", route.method, route.path, role, csrf, rec.Code, expected, rec.Body.String())
				}
			}
		}
	}
}
func TestWorkspacePagesRenderWithoutLDAP(t *testing.T) {
	s := testWorkspaceServer(t)
	sess, _ := s.sessions.Create("test", "CN=test", auth.RoleAdmin)
	for _, path := range []string{"/users", "/groups", "/computers", "/ou", "/dns", "/gpo", "/domain", "/repl", "/sites", "/trusts", "/shares", "/printers"} {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `data-module="`+path+`"`) || !strings.Contains(rec.Body.String(), "workspace.js") {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
}

// Called by testdata/web/workspace.cjs to render the real authenticated shell.
func TestWorkspaceBrowserFixtures(t *testing.T) {
	dir := os.Getenv("SAMBAADM_WEB_FIXTURE_DIR")
	if dir == "" {
		t.Skip("browser harness only")
	}
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleHelpdesk, auth.RoleReadonly} {
		sess, _ := s.sessions.Create("fixture@example.com", "CN=fixture", role)
		for _, path := range []string{"users", "groups", "computers", "ou", "dns", "gpo", "domain", "sites", "repl", "trusts", "shares", "printers"} {
			req := httptest.NewRequest("GET", "/"+path, nil)
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Fatal(rec.Code)
			}
			if err := os.WriteFile(filepath.Join(dir, string(role)+"-"+path+".html"), rec.Body.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestExtendedToolOperationsUseDecodedIdentifiersAndJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "arguments")
	tool := filepath.Join(dir, "samba-tool")
	t.Setenv("SAMBAADM_TEST_TOOL_LOG", logPath)
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SAMBAADM_TEST_TOOL_LOG\"\nprintf 'ok\\n'\n"
	if e := os.WriteFile(tool, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	auditLog, e := audit.New(filepath.Join(dir, "audit.log"))
	if e != nil {
		t.Fatal(e)
	}
	defer auditLog.Close()
	s := testWorkspaceServer(t)
	s.audit = auditLog
	s.svcs = service.NewWithOptions(ldapproto.NewClient(config.LDAPConfig{URI: "ldaps://dc1.example.com:636", BaseDN: "DC=example,DC=com"}), auditLog, service.ServiceOptions{SambaTool: tool})
	sess, _ := s.sessions.Create("admin", "CN=admin", auth.RoleAdmin)
	cases := []struct{ method, path, body, want string }{
		{"PUT", "/api/v1/dns/zones/example.com/records", `{"name":"files","type":"A","oldData":"192.0.2.20","newData":"192.0.2.21"}`, "dns\nupdate\ndc1.example.com\nexample.com\nfiles\nA\n192.0.2.20\n192.0.2.21\n"},
		{"GET", "/api/v1/gpo/%7Babc%7D", "", "gpo\nshow\n{abc}\n"},
		{"GET", "/api/v1/gpo/links?container=OU%3DPeople%2CDC%3Dexample%2CDC%3Dcom", "", "gpo\ngetlink\nOU=People,DC=example,DC=com\n"},
		{"POST", "/api/v1/domain/fsmo/seize", `{"role":"pdc"}`, "fsmo\nseize\n--role=pdc\n"},
		{"POST", "/api/v1/domain/level/raise", `{"forest":"2016"}`, "domain\nlevel\nraise\n--forest-level=2016\n"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		req.Header.Set(csrfHeader, sess.CSRFToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		s.Router().ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", tc.path, rec.Code, rec.Body.String())
		}
		got, e := os.ReadFile(logPath)
		if e != nil || string(got) != tc.want {
			t.Fatalf("%s arguments %q want %q, error %v", tc.path, got, tc.want, e)
		}
	}
}
