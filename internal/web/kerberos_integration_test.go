package web

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/jcmturner/gokrb5/v8/client"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/pki"
	"sambaadm/internal/service"
	"strings"
	"testing"
	"time"
)

func TestIntegrationKerberosSSOAndPasswordFallback(t *testing.T) {
	if os.Getenv("SAMBAADM_IT") != "1" {
		t.Skip("disposable Samba AD only")
	}
	if os.Getenv("SAMBAADM_IT_MUTATE") != "SAMBAADM.TEST" {
		t.Fatal("explicit disposable-domain mutation required")
	}
	dir := t.TempDir()
	principal, host := "HTTP/sambaadm.sambaadm.test", "sambaadm.sambaadm.test"
	account := "http-sso-fixture"
	tool := func(args ...string) {
		t.Helper()
		out, err := exec.Command("/usr/bin/samba-tool", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("fixture setup: %v: %s", err, out)
		}
	}
	tool("user", "create", account, "--random-password")
	defer exec.Command("/usr/bin/samba-tool", "user", "delete", account).Run()
	tool("spn", "add", principal, account)
	keytab := filepath.Join(dir, "http.keytab")
	tool("domain", "exportkeytab", keytab, "--principal="+principal)
	os.Chmod(keytab, 0600)
	ca, caKey, caPEM, err := pki.LoadAuthority(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM, err := pki.SignServerCertificate(ca, caKey, host, &key.PublicKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPath, keyPath, caPath := filepath.Join(dir, "web.crt"), filepath.Join(dir, "web.key"), filepath.Join(dir, "ca.pem")
	os.WriteFile(certPath, certPEM, 0600)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600)
	os.WriteFile(caPath, caPEM, 0600)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	publicURL := "https://" + net.JoinHostPort(host, port)
	cfg := &config.Config{LDAP: config.LDAPConfig{URI: os.Getenv("SAMBAADM_IT_URI"), CACert: os.Getenv("SAMBAADM_IT_CA"), BaseDN: "DC=sambaadm,DC=test", Bind: config.BindConfig{Type: "simple", User: os.Getenv("SAMBAADM_IT_USER"), PasswordEnv: "SAMBAADM_PASSWORD"}}, Server: config.ServerConfig{PublicURL: publicURL, TLS: config.TLSConfig{Cert: certPath, Key: keyPath}}, Auth: config.AuthConfig{Roles: config.RolesConfig{Admins: []string{"CN=Domain Admins,CN=Users,DC=sambaadm,DC=test"}}, SSO: config.SSOConfig{Enabled: true, Realm: "SAMBAADM.TEST", Principal: principal, Keytab: keytab}}}
	ldap := ldapproto.NewServiceClient(cfg.LDAP, cfg.BindPassword)
	defer ldap.Close()
	logger, err := audit.New(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	server, err := New(Options{Config: cfg, LDAP: ldap, Services: service.New(ldap, logger), Audit: logger, RBAC: auth.NewRBAC(cfg.Auth.Roles), Sessions: auth.NewStore(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: server.Router(), ReadHeaderTimeout: 10 * time.Second}
	defer httpServer.Close()
	go httpServer.ServeTLS(listener, certPath, keyPath)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	krbCfg, err := krbconfig.Load("/etc/krb5.conf")
	if err != nil {
		t.Fatal(err)
	}
	krbClient := client.NewWithPassword("Administrator", "SAMBAADM.TEST", cfg.BindPassword(), krbCfg, client.DisablePAFXFAST(true))
	defer krbClient.Destroy()
	if err = krbClient.Login(); err != nil {
		t.Fatal(err)
	}
	cookies, _ := cookiejar.New(nil)
	webClient := &http.Client{Transport: transport, Jar: cookies, Timeout: 30 * time.Second}
	negotiate := spnego.NewClient(krbClient, webClient, principal)
	response, err := negotiate.Get(publicURL + "/auth/kerberos")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || !bytes.Contains(bytes.ToLower(body), []byte("administrator@sambaadm.test")) {
		t.Fatalf("SSO did not create the expected session: %d", response.StatusCode)
	}
	// MIT GSSAPI verifies the AP_REP, unlike an HTTP client which only sends AP_REQ.
	env := append(os.Environ(), "KRB5CCNAME=FILE:"+filepath.Join(dir, "ccache"))
	kinit := exec.Command("/usr/bin/kinit", "Administrator@SAMBAADM.TEST")
	kinit.Env = env
	kinit.Stdin = strings.NewReader(cfg.BindPassword() + "\n")
	if out, err := kinit.CombinedOutput(); err != nil {
		t.Fatalf("kinit: %v: %s", err, out)
	}
	curl := exec.Command("/usr/bin/curl", "--silent", "--show-error", "--fail", "--negotiate", "--user", ":", "--cacert", caPath, "--resolve", net.JoinHostPort(host, port)+":127.0.0.1", "--location", "--cookie-jar", filepath.Join(dir, "curl.cookies"), publicURL+"/auth/kerberos")
	curl.Env = env
	out, err := curl.CombinedOutput()
	if err != nil || !bytes.Contains(bytes.ToLower(out), []byte("administrator@sambaadm.test")) {
		t.Fatalf("native GSSAPI mutual authentication failed: %v: %.1200s", err, out)
	}
	// Fresh password-only session, with no Kerberos header and no previous cookie.
	cookies, _ = cookiejar.New(nil)
	passwordClient := &http.Client{Transport: transport, Jar: cookies, Timeout: 30 * time.Second}
	response, err = passwordClient.PostForm(publicURL+"/login", url.Values{"username": {"Administrator@sambaadm.test"}, "password": {cfg.BindPassword()}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || !bytes.Contains(bytes.ToLower(body), []byte("administrator@sambaadm.test")) {
		t.Fatal("password fallback failed", response.StatusCode)
	}
	fmt.Println("Kerberos SSO, MIT GSSAPI mutual authentication, verified HTTPS and password fallback: PASS")
}
