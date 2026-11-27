package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
	"strings"
	"testing"
)

func TestShareTreePagesAndPermissions(t *testing.T) {
	s := testWorkspaceServer(t)
	root := t.TempDir()
	docs := filepath.Join(root, "docs")
	nested := filepath.Join(docs, "Отдел & проекты")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}
	smb := filepath.Join(root, "smb.conf")
	if err := os.WriteFile(smb, []byte("[docs]\npath = "+docs+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := audit.New("")
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	s.svcs = service.NewWithOptions(ldapproto.NewClient(config.LDAPConfig{}), log, service.ServiceOptions{Samba: config.SambaConfig{SMBConf: smb, SharesRoot: root}})
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReadonly} {
		sess, err := s.sessions.Create("tester", "CN=tester", role)
		if err != nil {
			t.Fatal(err)
		}
		request := func(method, path, body string, csrf bool) *httptest.ResponseRecorder {
			req := httptest.NewRequest(method, path, strings.NewReader(body))
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
			if body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			if csrf {
				req.Header.Set(csrfHeader, sess.CSRFToken)
			}
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			return rec
		}
		path := "/shares/docs/acl?path=" + url.QueryEscape("Отдел & проекты")
		rec := request("GET", path, "", false)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "share-directory-tree") || !strings.Contains(rec.Body.String(), "Отдел &amp; проекты") {
			t.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "share-domain-group") != (role == auth.RoleAdmin) {
			t.Fatal("editor role mismatch")
		}
		if dir := os.Getenv("SAMBAADM_SHARE_FIXTURE_DIR"); dir != "" {
			if err := os.WriteFile(filepath.Join(dir, string(role)+"-share-acl.html"), rec.Body.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
		rec = request("GET", "/api/v1/shares/docs/directories", "", false)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Отдел") {
			t.Fatalf("tree %d %s", rec.Code, rec.Body.String())
		}
		rec = request("GET", "/api/v1/shares/docs/directories?path=../", "", false)
		if rec.Code != 400 {
			t.Fatalf("traversal: %d", rec.Code)
		}
		rec = request("POST", path, "action=fs&mode=0700", false)
		if rec.Code != 403 {
			t.Fatalf("CSRF: %d", rec.Code)
		}
		rec = request("POST", path, "action=fs&mode=0700", true)
		if role == auth.RoleReadonly {
			if rec.Code != 403 {
				t.Fatalf("readonly write: %d", rec.Code)
			}
		} else {
			if rec.Code != 303 || !strings.Contains(rec.Header().Get("Location"), "path=") {
				t.Fatalf("save %d %s", rec.Code, rec.Body.String())
			}
			info, _ := os.Stat(nested)
			if info.Mode().Perm() != 0700 {
				t.Fatal("selected directory not updated")
			}
		}
	}
}

func TestShareTreeBrowserFixture(t *testing.T) {
	dir := os.Getenv("SAMBAADM_SHARE_FIXTURE_DIR")
	if dir == "" {
		t.Skip("browser harness only")
	}
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleAdmin, auth.RoleReadonly} {
		rec := httptest.NewRecorder()
		s.render(rec, "shares/acl.html", pageData{Lang: "ru", Role: role, CSRF: "fixture-csrf", HostNode: "files-02", Content: map[string]any{
			"Share": &service.Share{Name: "docs", Path: "/srv/samba/docs"}, "RelativePath": "Отдел & проекты/nested",
			"ACL": &service.PathACL{Path: "/srv/samba/docs/Отдел & проекты/nested", Exists: true, IsDir: true, Owner: "administrator", Group: `EXAMPLE\Domain Users`, Mode: "0770", Entries: []service.ACLEntry{
				{Kind: "user", Perms: "rwx"}, {Kind: "group", Perms: "rwx"}, {Kind: "group", Qualifier: "12345", Identity: `EXAMPLE\Finance`, Perms: "rwx", Effective: "r-x"}, {Kind: "group", Qualifier: "12345", Identity: `EXAMPLE\Finance`, Perms: "r-x", Default: true},
			}},
		}})
		if rec.Code != 200 {
			t.Fatal(rec.Code)
		}
		if err := os.WriteFile(filepath.Join(dir, string(role)+"-tree.html"), rec.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
		rec = httptest.NewRecorder()
		s.render(rec, "shares/permission-map.html", pageData{Lang: "ru", Role: role, CSRF: "fixture-csrf", HostNode: "files-02", Content: map[string]any{"Share": &service.Share{Name: "docs", Path: "/srv/samba/docs"}, "Root": "."}})
		if err := os.WriteFile(filepath.Join(dir, string(role)+"-map.html"), rec.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
