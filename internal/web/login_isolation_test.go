package web

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sambaadm/internal/agent"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
	"sambaadm/internal/testldap"
)

const testAdminDN = "CN=Domain Admins,CN=Users,DC=example,DC=com"
const testHelpdeskDN = "CN=Helpdesk,CN=Users,DC=example,DC=com"

func newLoginTestServer(t *testing.T, uri string, roles config.RolesConfig, password string) *Server {
	t.Helper()
	cfg := &config.Config{LDAP: config.LDAPConfig{URI: uri, BaseDN: "DC=example,DC=com", Bind: config.BindConfig{User: "service", Type: "simple"}}, Auth: config.AuthConfig{Roles: roles}}
	client := ldapproto.NewServiceClient(cfg.LDAP, func() string { return password })
	t.Cleanup(func() { client.Close() })
	log, e := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { log.Close() })
	s, e := New(Options{Config: cfg, LDAP: client, Services: service.New(client, log), Audit: log, RBAC: auth.NewRBAC(roles), Sessions: auth.NewStore(time.Hour)})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func loginRequest(s *Server, user, password string) *httptest.ResponseRecorder {
	form := url.Values{"username": {user}, "password": {password}}
	r := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, r)
	return w
}
func TestParallelLoginsDoNotChangeServiceOrOtherUsersRoles(t *testing.T) {
	passwords := map[string]string{"service": "service-password", "alice@example.com": "alice-pass", "bob@example.com": "bob-pass", "helper@example.com": "helper-pass"}
	var mismatch atomic.Bool
	fake := testldap.New(t, passwords, func(q testldap.Search) ([]testldap.Entry, int64) {
		if q.User != "service" && !bytes.Contains(q.Filter.Bytes(), []byte(q.User)) {
			mismatch.Store(true)
		}
		attrs := map[string][]string{"sAMAccountName": {q.User}, "displayName": {q.User}}
		if q.User == "alice@example.com" {
			attrs["memberOf"] = []string{testAdminDN}
		} else if q.User == "helper@example.com" {
			attrs["memberOf"] = []string{testHelpdeskDN}
		}
		return []testldap.Entry{{DN: "CN=" + q.User + ",CN=Users,DC=example,DC=com", Attributes: attrs}}, 0
	})
	s := newLoginTestServer(t, fake.URI(), config.RolesConfig{Admins: []string{testAdminDN}, Helpdesk: []string{testHelpdeskDN}}, "service-password")
	// Exercise authenticated reads concurrently with additional successful and failed logins.
	first := loginRequest(s, "alice@example.com", "alice-pass")
	if first.Code != 303 {
		t.Fatalf("initial login: %d %s", first.Code, first.Body.String())
	}
	cookie := first.Result().Cookies()[0]
	var wg sync.WaitGroup
	users := []string{"alice@example.com", "bob@example.com", "helper@example.com"}
	roles := []auth.Role{auth.RoleAdmin, auth.RoleReadonly, auth.RoleHelpdesk}
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			u := i % len(users)
			w := loginRequest(s, users[u], passwords[users[u]])
			if w.Code != 303 {
				t.Errorf("login %s: %d %s", users[u], w.Code, w.Body.String())
				return
			}
			cookies := w.Result().Cookies()
			if len(cookies) == 0 {
				t.Error("login cookie missing")
				return
			}
			sess, ok := s.sessions.Get(cookies[0].Value)
			if !ok || sess.Role != roles[u] || sess.Username != users[u] {
				t.Errorf("mixed session identity: %+v expected %s", sess, roles[u])
			}
			failed := loginRequest(s, users[u], "invalid")
			if failed.Code == 303 || len(failed.Result().Cookies()) != 0 {
				t.Error("invalid credentials created a session")
			}
			req := httptest.NewRequest("GET", "/api/v1/users", nil)
			req.AddCookie(cookie)
			rec := httptest.NewRecorder()
			s.Router().ServeHTTP(rec, req)
			if rec.Code != 200 {
				t.Errorf("service read after login failed: %d %s", rec.Code, rec.Body.String())
			}
		}(i)
	}
	wg.Wait()
	if mismatch.Load() {
		t.Fatal("one user's role search ran under a different identity")
	}
	for _, bind := range fake.Binds() {
		if bind.User == "service" && !bind.Success {
			t.Fatal("unexpected service bind failure")
		}
	}
	if _, e := s.ldap.Search(context.Background(), ldapproto.SearchOptions{}); e != nil {
		t.Fatal(e)
	}
	// Every persistent service connection is bound only once, and only as service.
	serviceConnections := map[int]bool{}
	for _, bind := range fake.Binds() {
		if bind.User == "service" {
			serviceConnections[bind.Connection] = true
		}
	}
	for _, bind := range fake.Binds() {
		if serviceConnections[bind.Connection] && bind.User != "service" {
			t.Fatalf("browser bind on service connection: %+v", bind)
		}
	}
	for _, q := range fake.Searches() {
		if q.User == "" {
			t.Fatal("anonymous directory query")
		}
	}
	deadline := time.Now().Add(time.Second)
	for fake.Active() > 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if fake.Active() != 1 {
		t.Fatalf("temporary login connections leaked: %d active", fake.Active())
	}
}
func TestIdentityLookupFailureCannotCreateAdminSession(t *testing.T) {
	for _, code := range []int64{0, 50} {
		t.Run(fmt.Sprintf("ldap_result_%d", code), func(t *testing.T) {
			fake := testldap.New(t, map[string]string{"alice": "pass", "service": "service-password"}, func(q testldap.Search) ([]testldap.Entry, int64) { return nil, code })
			// Empty role configuration previously promoted failed lookups to admin.
			s := newLoginTestServer(t, fake.URI(), config.RolesConfig{}, "service-password")
			w := loginRequest(s, "alice", "pass")
			if w.Code == 303 || len(w.Result().Cookies()) != 0 {
				t.Fatal("lookup failure created an admin session")
			}
			if !strings.Contains(w.Body.String(), "Не удалось определить") {
				t.Fatalf("missing identity error: %s", w.Body.String())
			}
			for _, b := range fake.Binds() {
				if b.User == "service" {
					t.Fatal("service bind attempted before identity was established")
				}
			}
		})
	}
}
func TestServiceBindFailureDeniesLoginAndLeavesNoUserIdentity(t *testing.T) {
	fake := testldap.New(t, map[string]string{"alice": "pass", "service": "correct"}, func(q testldap.Search) ([]testldap.Entry, int64) {
		return []testldap.Entry{{DN: "CN=Alice,DC=example,DC=com", Attributes: map[string][]string{"sAMAccountName": {"alice"}}}}, 0
	})
	s := newLoginTestServer(t, fake.URI(), config.RolesConfig{}, "wrong-service-password")
	w := loginRequest(s, "alice", "pass")
	if w.Code == 303 || len(w.Result().Cookies()) != 0 {
		t.Fatal("service failure created a session")
	}
	if !strings.Contains(w.Body.String(), "Служебное подключение") {
		t.Fatalf("missing actionable service error: %s", w.Body.String())
	}
	if _, err := s.ldap.Conn(context.Background()); err == nil {
		t.Fatal("service failure retained a browser connection")
	}
	binds := fake.Binds()
	if len(binds) != 3 || binds[0].Connection == binds[1].Connection {
		t.Fatalf("identities were not isolated: %+v", binds)
	}
}

func TestBuiltinUPNIdentityFallback(t *testing.T) {
	for _, domain := range []string{"example.com", "foreign.test"} {
		t.Run(domain, func(t *testing.T) {
			user := "Administrator@" + domain
			fake := testldap.New(t, map[string]string{user: "test-password", "service": "service-password"}, func(q testldap.Search) ([]testldap.Entry, int64) {
				if bytes.Contains(q.Filter.Bytes(), []byte("@")) {
					return nil, 0
				}
				return []testldap.Entry{{DN: "CN=Administrator,CN=Users,DC=example,DC=com", Attributes: map[string][]string{"memberOf": {testAdminDN}}}}, 0
			})
			s := newLoginTestServer(t, fake.URI(), config.RolesConfig{Admins: []string{testAdminDN}}, "service-password")
			response := loginRequest(s, user, "test-password")
			if domain == "example.com" && response.Code != 303 {
				t.Fatalf("built-in account login failed: %d", response.Code)
			}
			if domain != "example.com" && response.Code == 303 {
				t.Fatal("foreign UPN must not fall back to local account")
			}
		})
	}
}

func TestSessionHelperIdentityIsRevokedAtLogout(t *testing.T) {
	fake := testldap.New(t, map[string]string{"service": "service-password", "alice@example.com": "alice-pass"}, func(q testldap.Search) ([]testldap.Entry, int64) {
		return []testldap.Entry{{DN: "CN=Alice,CN=Users,DC=example,DC=com", Attributes: map[string][]string{"sAMAccountName": {"alice"}, "memberOf": {testAdminDN}}}}, 0
	})
	s := newLoginTestServer(t, fake.URI(), config.RolesConfig{Admins: []string{testAdminDN}}, "service-password")
	form := url.Values{"username": {"alice@example.com"}, "password": {"alice-pass"}, "helper_auth": {"session"}, "ldap_legacy_cn": {"allow"}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logged := httptest.NewRecorder()
	s.Router().ServeHTTP(logged, req)
	if logged.Code != 303 {
		t.Fatal(logged.Code, logged.Body)
	}
	cookie := logged.Result().Cookies()[0]
	sess, ok := s.sessions.Get(cookie.Value)
	if !ok || !s.sessions.HasHelperCredentials(sess.ID) {
		t.Fatal("session credentials missing")
	}
	if !sess.AllowLegacyCN {
		t.Fatal("login TLS profile not retained")
	}
	var operation context.Context
	protected := s.requireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allowed, err := ldapproto.LegacyCNAllowed(r.Context(), s.cfg.LDAP)
		if err != nil || !allowed {
			t.Error("session TLS profile not propagated")
		}
		operation = agent.CarryCredentials(context.Background(), r.Context())
	}))
	next := httptest.NewRequest("GET", "/test", nil)
	next.AddCookie(cookie)
	protected.ServeHTTP(httptest.NewRecorder(), next)
	credentials, present, err := agent.OperationCredentials(operation)
	if err != nil || !present || credentials.Username != "alice@example.com" || credentials.Password != "alice-pass" {
		t.Fatal("wrong helper identity")
	}
	if s.ldap.URI() != fake.URI() {
		t.Fatal("shared LDAP client changed")
	}
	logout := httptest.NewRequest("POST", "/logout", strings.NewReader(url.Values{"csrf_token": {sess.CSRFToken}}.Encode()))
	logout.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logout.AddCookie(cookie)
	s.Router().ServeHTTP(httptest.NewRecorder(), logout)
	if _, present, err := agent.OperationCredentials(operation); !present || err == nil {
		t.Fatal("captured background operation retained credentials after logout")
	}
	if s.sessions.HasHelperCredentials(sess.ID) {
		t.Fatal("logout retained encrypted record")
	}
}
