package web

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sambaadm/internal/agent"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	"sambaadm/internal/service"
)

func TestCertificateMenuIssueTrustAndReset(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.CertificateDir = filepath.Join(t.TempDir(), "certificates")
	s.cfg.LDAP.ManagedCAFile = filepath.Join(s.cfg.Server.CertificateDir, "ldap-ca.pem")
	admin, _ := s.sessions.Create("admin", "cn=admin", auth.RoleAdmin)
	request := func(form url.Values) *httptest.ResponseRecorder {
		form.Set("csrf_token", admin.CSRFToken)
		req := httptest.NewRequest("POST", "/settings/certificates", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: admin.ID})
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, req)
		return w
	}
	issue := func() map[string][]byte {
		w := request(url.Values{"action": {"issue"}, "node": {"dc0.ipr.loc"}, "key_mode": {"generate"}})
		if w.Code != 200 || w.Header().Get("Content-Type") != "application/zip" {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		z, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
		if err != nil {
			t.Fatal(err)
		}
		files := map[string][]byte{}
		for _, f := range z.File {
			if f.Mode().Perm() != 0600 {
				t.Fatal(f.Name, f.Mode())
			}
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			files[f.Name], err = io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		return files
	}
	first, second := issue(), issue()
	if !bytes.Equal(first["ca.pem"], second["ca.pem"]) {
		t.Fatal("renewal replaced CA")
	}
	block, _ := pem.Decode(first["cert.pem"])
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(first["ca.pem"])
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "dc0.ipr.loc", Roots: roots}); err != nil {
		t.Fatal(err)
	}
	if cert.VerifyHostname("dc00.ipr.loc") == nil {
		t.Fatal("wrong SAN accepted")
	}
	keyBlock, _ := pem.Decode(first["key.pem"])
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatal("key mismatch")
	}
	for _, form := range []url.Values{{"action": {"trust-local"}}, {"action": {"trust"}, "ca": {string(first["ca.pem"])}}} {
		w := request(form)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Доверие сохранено") {
			t.Fatal(w.Code, w.Body)
		}
		got, err := os.ReadFile(s.cfg.LDAP.LDAPCAFile())
		if err != nil || !bytes.Equal(got, first["ca.pem"]) {
			t.Fatal(err, "CA not selected")
		}
	}
	// Uploaded trust must survive a full configuration reload.
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("server:\n  certificate_dir: "+s.cfg.Server.CertificateDir+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.LDAP.LDAPCAFile() != s.cfg.LDAP.ManagedCAFile {
		t.Fatal("uploaded trust lost on restart")
	}
	for _, raw := range [][]byte{first["key.pem"], first["cert.pem"], append(append([]byte{}, first["ca.pem"]...), first["key.pem"]...)} {
		w := request(url.Values{"action": {"trust"}, "ca": {string(raw)}})
		if strings.Contains(w.Body.String(), "Доверие сохранено") {
			t.Fatal("non-CA accepted")
		}
		got, _ := os.ReadFile(s.cfg.LDAP.ManagedCAFile)
		if !bytes.Equal(got, first["ca.pem"]) {
			t.Fatal("invalid input replaced trusted CA")
		}
	}
	st, err := os.Stat(filepath.Join(s.cfg.Server.CertificateDir, "authority.json"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal(st, err)
	}
	w := request(url.Values{"action": {"reset-trust"}})
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if _, err := os.Stat(s.cfg.LDAP.ManagedCAFile); !os.IsNotExist(err) {
		t.Fatal("trust reset failed", err)
	}
}

func TestCertificateMenuRequiresAdminAndCSRF(t *testing.T) {
	s := testWorkspaceServer(t)
	for _, role := range []auth.Role{auth.RoleHelpdesk, auth.RoleReadonly} {
		sess, _ := s.sessions.Create("operator", "cn=operator", role)
		req := httptest.NewRequest("GET", "/settings/certificates", nil)
		req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
		w := httptest.NewRecorder()
		s.Router().ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatal(role, w.Code)
		}
	}
	sess, _ := s.sessions.Create("admin", "cn=admin", auth.RoleAdmin)
	req := httptest.NewRequest("POST", "/settings/certificates", strings.NewReader("action=trust-local"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code)
	}
}

func TestDashboardMetricsStayLocalWithHelpersConfigured(t *testing.T) {
	s := testWorkspaceServer(t)
	s.svcs = &service.Services{Helpers: &agent.Client{Config: agent.Config{HostNode: "remote.invalid"}}}
	// Construct through New to reproduce the previous remote-helper wiring.
	server, err := New(Options{Config: s.cfg, Services: s.svcs, Sessions: s.sessions, RBAC: s.rbac, LDAP: s.ldap, Audit: s.audit})
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := s.sessions.Create("admin", "cn=admin", auth.RoleAdmin)
	req := httptest.NewRequest("GET", "/api/v1/system/metrics", nil)
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	w := httptest.NewRecorder()
	server.Router().ServeHTTP(w, req)
	var metrics service.HostMetrics
	if err := json.Unmarshal(w.Body.Bytes(), &metrics); err != nil {
		t.Fatal(err, w.Body)
	}
	host, _ := os.Hostname()
	if w.Code != 200 || metrics.Host != host || metrics.CPUs < 1 || len(metrics.Samples) != 1 {
		t.Fatal(w.Code, metrics)
	}
}

func TestCertificateInspectionDoesNotAuthenticateOrTrustPeer(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("inspection sent application data") }))
	defer upstream.Close()
	s := testWorkspaceServer(t)
	s.cfg.LDAP.URI = "ldaps://" + strings.TrimPrefix(upstream.URL, "https://")
	view := certificatePage{}
	status := s.inspectLDAPCertificate(t.Context(), &view)
	if !strings.Contains(status, "Проверка не пройдена") || view.Subject == "" || view.Expires == "" {
		t.Fatal(status, view)
	}
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "trusted.pem")
	if err := os.WriteFile(path, ca, 0600); err != nil {
		t.Fatal(err)
	}
	s.cfg.LDAP.CACert = path
	status = s.inspectLDAPCertificate(t.Context(), &view)
	if !strings.Contains(status, "Сертификат действителен") {
		t.Fatal(status)
	}
}
