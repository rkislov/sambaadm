package web

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/pki"
	"sambaadm/internal/service"
	"sambaadm/internal/testkerberos"
	"sambaadm/internal/testldap"
	"strings"
	"testing"
	"time"
)

func TestKerberosLoginUsesADRoleAndKeepsPasswordLogin(t *testing.T) {
	principal, realm := "HTTP/sambaadm.example.test", "EXAMPLE.TEST"
	kt, keytab := testkerberos.Keytab(t, principal, realm)
	webTLS := httptest.NewTLSServer(nil)
	pair := webTLS.TLS.Certificates[0]
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: webTLS.Certificate().Raw})
	webTLS.Close()
	adminDN := "CN=Domain Admins,CN=Users,DC=example,DC=test"
	fake := testldap.NewTLS(t, map[string]string{"service": "service-password", "alice@example.test": "alice-password"}, func(q testldap.Search) ([]testldap.Entry, int64) {
		user := "bob"
		for _, candidate := range []string{"alice", "disabled", "expired"} {
			if strings.Contains(q.BaseDN, candidate) || bytes.Contains(q.Filter.Bytes(), []byte(candidate)) {
				user = candidate
				break
			}
		}
		attrs := map[string][]string{"sAMAccountName": {user}, "userPrincipalName": {user + "@example.test"}, "userAccountControl": {"512"}, "accountExpires": {"9223372036854775807"}, "objectGUID": {string(bytes.Repeat([]byte{1}, 16))}}
		if user == "alice" {
			attrs["memberOf"] = []string{adminDN}
		}
		if user == "disabled" {
			attrs["userAccountControl"] = []string{"514"}
		}
		if user == "expired" {
			attrs["accountExpires"] = []string{"132223104000000000"}
		}
		return []testldap.Entry{{DN: "CN=" + user + ",CN=Users,DC=example,DC=test", Attributes: attrs}}, 0
	}, &tls.Config{Certificates: []tls.Certificate{pair}})
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "web.crt"), filepath.Join(dir, "web.key")
	webCA, webCAKey, _, err := pki.LoadAuthority(filepath.Join(dir, "web-ca"))
	if err != nil {
		t.Fatal(err)
	}
	webKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	webCert, err := pki.SignServerCertificate(webCA, webCAKey, "sambaadm.example.test", &webKey.PublicKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(certPath, webCert, 0600)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(webKey)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	caPath := filepath.Join(dir, "ca.pem")
	os.WriteFile(caPath, ca, 0600)
	cfg := &config.Config{LDAP: config.LDAPConfig{URI: fake.URI(), CACert: caPath, BaseDN: "DC=example,DC=test", Bind: config.BindConfig{Type: "simple", User: "service"}}, Server: config.ServerConfig{PublicURL: "https://sambaadm.example.test", TLS: config.TLSConfig{Cert: certPath, Key: keyPath}}, Auth: config.AuthConfig{Roles: config.RolesConfig{Admins: []string{adminDN}}, SSO: config.SSOConfig{Enabled: true, Keytab: keytab, Principal: principal, Realm: realm}}}
	client := ldapproto.NewServiceClient(cfg.LDAP, func() string { return "service-password" })
	defer client.Close()
	logger, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	s, err := New(Options{Config: cfg, LDAP: client, Services: service.New(client, logger), Audit: logger, RBAC: auth.NewRBAC(cfg.Auth.Roles), Sessions: auth.NewStore(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		user, realm string
		code        int
		role        auth.Role
	}{{"alice", realm, 303, auth.RoleAdmin}, {"bob", realm, 303, auth.RoleReadonly}, {"disabled", realm, 403, ""}, {"expired", realm, 403, ""}, {"alice", "FOREIGN.TEST", 401, ""}} {
		t.Run(item.user+item.realm, func(t *testing.T) {
			token := testkerberos.Token(t, kt, principal, realm, item.user, item.realm, 20*time.Minute)
			req := httptest.NewRequest("GET", "https://sambaadm.example.test/auth/kerberos", nil)
			req.Header.Set("Authorization", token)
			w := httptest.NewRecorder()
			s.Router().ServeHTTP(w, req)
			if w.Code != item.code {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			cookies := w.Result().Cookies()
			if item.code != 303 {
				if len(cookies) != 0 {
					t.Fatal("invalid user obtained session")
				}
				return
			}
			if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
				t.Fatal("unsafe SSO cookie")
			}
			session, ok := s.sessions.Get(cookies[0].Value)
			if !ok || session.Username != item.user+"@example.test" || session.Role != item.role || session.AuthMethod != "kerberos" || session.SkipLDAPVerify || session.AllowLegacyCN || s.sessions.HasHelperCredentials(session.ID) {
				t.Fatal("SSO identity, role or credential isolation failed")
			}
			if session.ExpiresAt.After(time.Now().Add(21 * time.Minute)) {
				t.Fatal("session outlives Kerberos ticket")
			}
		})
	}
	w := loginRequest(s, "alice@example.test", "alice-password")
	if w.Code != 303 {
		t.Fatal("password fallback stopped working", w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	session, _ := s.sessions.Get(cookie.Value)
	if session.Role != auth.RoleAdmin || session.AuthMethod == "kerberos" {
		t.Fatal("password login was replaced by SSO")
	}
	req := httptest.NewRequest("GET", "https://sambaadm.example.test/login?manual=1", nil)
	w = httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)
	html := w.Body.String()
	if !strings.Contains(html, `name="password"`) || !strings.Contains(html, `data-auto="false"`) {
		t.Fatal("manual login is not accessible")
	}
	for _, bind := range fake.Binds() {
		if bind.User != "service" && bind.User != "alice@example.test" {
			t.Fatal("SSO reused an unexpected identity")
		}
	}
}
