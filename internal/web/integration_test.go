package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
)

// This test uses real HTTP, real LDAP/TLS and real samba-tool inside the lab DC.
func TestIntegrationWebDomainOperations(t *testing.T) {
	if os.Getenv("SAMBAADM_IT") != "1" {
		t.Skip("disposable Samba DC integration only")
	}
	if os.Getenv("SAMBAADM_IT_MUTATE") != "SAMBAADM.TEST" {
		t.Fatal("SAMBAADM_IT_MUTATE=SAMBAADM.TEST is required")
	}
	cfg := &config.Config{LDAP: config.LDAPConfig{URI: os.Getenv("SAMBAADM_IT_URI"), BaseDN: "DC=sambaadm,DC=test", Bind: config.BindConfig{Type: "simple", User: os.Getenv("SAMBAADM_IT_USER"), PasswordEnv: "SAMBAADM_PASSWORD"}}, Auth: config.AuthConfig{Roles: config.RolesConfig{Admins: []string{"CN=Domain Admins,CN=Users,DC=sambaadm,DC=test"}}}}
	if cfg.LDAP.URI == "" || cfg.LDAP.Bind.User == "" || cfg.BindPassword() == "" {
		t.Fatal("lab LDAP URI and credentials required")
	}
	ldapClient := ldapproto.NewServiceClient(cfg.LDAP, cfg.BindPassword)
	defer ldapClient.Close()
	auditLog, e := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if e != nil {
		t.Fatal(e)
	}
	defer auditLog.Close()
	svcs := service.NewWithOptions(ldapClient, auditLog, service.ServiceOptions{ToolUser: cfg.LDAP.Bind.User, ToolPassword: cfg.BindPassword})
	templatePath := filepath.Join(t.TempDir(), "ALT.admx")
	if e = os.WriteFile(templatePath, []byte(`<policyDefinitions><policies><policy name="chronyd.service" class="Machine" key="Software\BaseALT\Policies\SystemdUnits" valueName="chronyd.service"><enabledValue><decimal value="1"/></enabledValue><disabledValue><decimal value="0"/></disabledValue></policy></policies></policyDefinitions>`), 0600); e != nil {
		t.Fatal(e)
	}
	cfg.GPO = config.GPOConfig{EditorEnabled: true, ADMXPath: templatePath}
	svcs = service.NewWithOptions(ldapClient, auditLog, service.ServiceOptions{ToolUser: cfg.LDAP.Bind.User, ToolPassword: cfg.BindPassword, GPO: cfg.GPO})
	app, e := New(Options{Config: cfg, LDAP: ldapClient, Services: svcs, Sessions: auth.NewStore(time.Hour), RBAC: auth.NewRBAC(cfg.Auth.Roles), Audit: auditLog})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(app.Router())
	defer server.Close()
	login := func(user, password string) (*http.Client, string) {
		t.Helper()
		jar, _ := cookiejar.New(nil)
		client := &http.Client{Jar: jar, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.PostForm(server.URL+"/login", url.Values{"username": {user}, "password": {password}})
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 303 {
			t.Fatalf("web login rejected: %d %s", response.StatusCode, body)
		}
		response, err = client.Get(server.URL + "/users")
		if err != nil {
			t.Fatal(err)
		}
		body, _ = io.ReadAll(response.Body)
		response.Body.Close()
		m := regexp.MustCompile(`name="csrf-token" content="([^"]+)"`).FindSubmatch(body)
		if len(m) != 2 {
			t.Fatal("CSRF token not found in actual HTML")
		}
		return client, string(m[1])
	}
	admin, token := login(cfg.LDAP.Bind.User, cfg.BindPassword())
	request := func(client *http.Client, csrf, method, path string, body any, want int) []byte {
		t.Helper()
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		req, err := http.NewRequest(method, server.URL+"/api/v1"+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(csrfHeader, csrf)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		result, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("%s %s: %d want %d: %s", method, path, response.StatusCode, want, result)
		}
		return result
	}
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	user := "web" + id
	ouName := "WebIT-" + id
	ouDN := "OU=" + ouName + "," + cfg.LDAP.BaseDN
	request(admin, token, "POST", "/ou", map[string]any{"name": ouName}, 201)
	defer func() { request(admin, token, "DELETE", "/ou?dn="+url.QueryEscape(ouDN), nil, 200) }()
	request(admin, token, "POST", "/users", map[string]any{"login": user, "displayName": user, "password": "Web-User-Pass1!", "ou": ouDN, "enabled": true}, 201)
	defer func() { request(admin, token, "DELETE", "/users/"+user, nil, 200) }()
	tree := request(admin, token, "GET", "/directory/tree?kind=users", nil, 200)
	if !bytes.Contains(tree, []byte(user)) {
		t.Fatal("created user missing from HTTP directory tree")
	}
	var initial service.User
	if e = json.Unmarshal(request(admin, token, "GET", "/users/"+user, nil, 200), &initial); e != nil {
		t.Fatal(e)
	}
	fields := map[string]string{"revision": initial.Revision, "displayName": "Updated User", "givenName": "Иван", "surname": "Тестовый", "mail": "user@example.test", "telephone": "12345", "department": "IT", "title": "Engineer", "description": "Profile test"}
	updatedBytes := request(admin, token, "PUT", "/users/"+user, fields, 200)
	var updated service.User
	if e = json.Unmarshal(updatedBytes, &updated); e != nil || updated.DN != initial.DN || updated.Mail != "user@example.test" || updated.GivenName != "Иван" || updated.Revision == initial.Revision {
		t.Fatalf("profile update: %s %v", updatedBytes, e)
	}
	request(admin, token, "PUT", "/users/"+user, fields, 409)
	request(admin, token, "PUT", "/users/"+user, map[string]string{"revision": updated.Revision, "enabled": "false"}, 400)
	request(admin, token, "PUT", "/users/"+user, map[string]string{"revision": updated.Revision, "mail": ""}, 200)
	var memberships []service.UserGroup
	if e = json.Unmarshal(request(admin, token, "GET", "/users/"+user+"/groups", nil, 200), &memberships); e != nil {
		t.Fatal(e)
	}
	primary := false
	for _, group := range memberships {
		if group.Primary {
			primary = true
		}
	}
	if !primary {
		t.Fatalf("primary group absent: %+v", memberships)
	}
	groupName := "profile" + id
	request(admin, token, "POST", "/groups", map[string]string{"name": groupName, "ou": ouDN}, 201)
	defer func() { request(admin, token, "DELETE", "/groups/"+groupName, nil, 200) }()
	request(admin, token, "POST", "/groups/"+groupName+"/members", map[string]string{"memberDN": initial.DN}, 200)
	if data := request(admin, token, "GET", "/users/"+user+"/groups", nil, 200); !bytes.Contains(data, []byte(groupName)) {
		t.Fatal("direct group absent from profile")
	}
	request(admin, token, "DELETE", "/groups/"+groupName+"/members", map[string]string{"memberDN": initial.DN}, 200)
	request(admin, token, "POST", "/users/"+user+"/password", map[string]string{"password": "Web-User-New-Pass2!"}, 200)
	viewer, viewerToken := login(user+"@sambaadm.test", "Web-User-New-Pass2!")
	request(viewer, viewerToken, "GET", "/users", nil, 200)
	request(viewer, viewerToken, "PUT", "/users/"+user, fields, 403)
	request(admin, "", "PUT", "/users/"+user, fields, 403)
	request(viewer, viewerToken, "GET", "/users/"+user+"/groups", nil, 200)
	request(viewer, viewerToken, "POST", "/users/"+user+"/disable", map[string]string{}, 403)
	request(admin, "", "POST", "/users/"+user+"/disable", map[string]string{}, 403)
	request(admin, token, "POST", "/users/"+user+"/disable", map[string]string{}, 200)
	request(admin, token, "POST", "/users/"+user+"/enable", map[string]string{}, 200)
	zone := "web" + id + ".sambaadm.test"
	zonePath := "/dns/zones/" + zone
	request(admin, token, "POST", "/dns/zones", map[string]string{"name": zone}, 201)
	defer func() { request(admin, token, "DELETE", zonePath, nil, 200) }()
	request(admin, token, "POST", zonePath+"/records", map[string]string{"name": "files", "type": "A", "data": "192.0.2.20"}, 201)
	request(admin, token, "PUT", zonePath+"/records", map[string]string{"name": "files", "type": "A", "oldData": "192.0.2.20", "newData": "192.0.2.21"}, 200)
	records := request(admin, token, "GET", zonePath+"/records?name=files&type=A", nil, 200)
	if !bytes.Contains(records, []byte("192.0.2.21")) {
		t.Fatal("HTTP DNS update not reflected by Samba")
	}
	request(admin, token, "DELETE", zonePath+"/records", map[string]string{"name": "files", "type": "A", "data": "192.0.2.21"}, 200)
	policy := "Web-GPO-" + id
	request(admin, token, "POST", "/gpo", map[string]string{"name": policy}, 201)
	findGUID := func(name string) string {
		t.Helper()
		data := request(admin, token, "GET", "/gpo", nil, 200)
		var list []service.GPO
		if e := json.Unmarshal(data, &list); e != nil {
			t.Fatal(e)
		}
		for _, g := range list {
			if g.DisplayName == name {
				return g.GUID
			}
		}
		t.Fatalf("GPO %s not found", name)
		return ""
	}
	guid := findGUID(policy)
	defer func() { request(admin, token, "DELETE", "/gpo/"+url.PathEscape(guid), nil, 200) }()
	gpoPath := "/gpo/" + url.PathEscape(guid)
	altPath := gpoPath + "/alt-settings"
	var alt service.ALTPolicy
	if e = json.Unmarshal(request(viewer, viewerToken, "GET", altPath, nil, 200), &alt); e != nil {
		t.Fatal(e)
	}
	change := service.ALTChange{ID: "chronyd.service", State: "enabled", Revision: alt.Revision}
	request(viewer, viewerToken, "PUT", altPath, change, 403)
	request(admin, "", "PUT", altPath, change, 403)
	result := request(admin, token, "PUT", altPath, change, 200)
	var saved service.ALTPolicy
	if e = json.Unmarshal(result, &saved); e != nil || saved.Settings[0].State != "enabled" || saved.Version != alt.Version+1 {
		t.Fatalf("HTTP ALT editor: %s %v", result, e)
	}
	request(admin, token, "PUT", altPath, change, 409)
	// A fresh Registry.pol must have Samba-inherited ACLs: ordinary domain
	// users can read it, and a separate Domain Admin can edit it over SMB.
	editorAdmin := "ga" + id
	var account service.User
	created := request(admin, token, "POST", "/users", map[string]any{"login": editorAdmin, "password": "Editor-Admin-Pass1!", "ou": ouDN, "enabled": true}, 201)
	if e = json.Unmarshal(created, &account); e != nil {
		t.Fatal(e)
	}
	defer func() { request(admin, token, "DELETE", "/users/"+editorAdmin, nil, 200) }()
	request(admin, token, "POST", "/groups/Domain%20Admins/members", map[string]string{"memberDN": account.DN}, 200)
	script := `import os,sys
from samba.param import LoadParm
from samba.credentials import Credentials
from samba.netcmd.gpo import smb_connection
lp=LoadParm();lp.load_default()
creds=Credentials();creds.guess(lp);creds.set_domain("SAMBAADM")
creds.set_username(os.environ["EDITOR_TEST_USER"]);creds.set_password(os.environ["EDITOR_TEST_PASSWORD"])
conn=smb_connection("127.0.0.1","sysvol",lp=lp,creds=creds)
data=conn.loadfile(sys.argv[1]);assert data[:4]==b"PReg"
if os.environ["EDITOR_TEST_WRITE"]=="1": conn.savefile(sys.argv[1],data)
`
	for _, who := range []struct{ user, password, write string }{{user, "Web-User-New-Pass2!", "0"}, {editorAdmin, "Editor-Admin-Pass1!", "1"}} {
		cmd := exec.Command("/usr/bin/python3", "-c", script, `sambaadm.test\Policies\`+guid+`\Machine\Registry.pol`)
		cmd.Env = append(os.Environ(), "EDITOR_TEST_USER="+who.user, "EDITOR_TEST_PASSWORD="+who.password, "EDITOR_TEST_WRITE="+who.write)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("inherited SMB policy permissions: %s %v", output, err)
		}
	}
	t.Log("new Registry.pol is readable by domain user and writable by a separate Domain Admin over SMB")
	request(admin, token, "POST", gpoPath+"/link", map[string]string{"container": ouDN}, 200)
	links := request(admin, token, "GET", "/gpo/links?container="+url.QueryEscape(ouDN), nil, 200)
	if !strings.Contains(strings.ToLower(string(links)), strings.ToLower(strings.Trim(guid, "{}"))) {
		t.Fatal("HTTP GPO link not visible")
	}
	backup := t.TempDir()
	request(admin, token, "POST", gpoPath+"/backup", map[string]string{"path": backup}, 200)
	restored := policy + "-restored"
	request(admin, token, "POST", "/gpo/restore", map[string]string{"name": restored, "path": filepath.Join(backup, "policy", guid)}, 200)
	restoredGUID := findGUID(restored)
	if restoredGUID == guid {
		t.Fatal("restore reused original GPO")
	}
	defer func() { request(admin, token, "DELETE", "/gpo/"+url.PathEscape(restoredGUID), nil, 200) }()
	request(admin, token, "POST", gpoPath+"/unlink", map[string]string{"container": ouDN}, 200)
	t.Log("real HTTP login/RBAC/CSRF, directory tree, password reset, DNS changes and GPO backup/restore passed")
}
