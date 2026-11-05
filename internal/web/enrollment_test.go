package web

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sambaadm/internal/auth"
	"sambaadm/internal/config"
)

func TestHelperEnrollment(t *testing.T) {
	s := testWorkspaceServer(t)
	dir := filepath.Join(t.TempDir(), "enrollment")
	s.cfg.Server.EnrollmentDir = dir
	admin, _ := s.sessions.Create("admin", "cn=admin", auth.RoleAdmin)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"unrequested.example"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"node": {"dc1.example.org"}, "domain": {"example.org"}, "csr": {string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))}, "csrf_token": {admin.CSRFToken}}
	req := httptest.NewRequest("POST", "/settings/helpers", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: admin.ID})
	w := httptest.NewRecorder()
	s.Router().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err = os.WriteFile(path, []byte("server:\n  enrollment_dir: "+dir+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Helpers.HostNode != "dc1.example.org" || len(cfg.Helpers.Nodes) != 1 {
		t.Fatal(cfg.Helpers)
	}
	ca, err := os.ReadFile(cfg.Helpers.Nodes[0].CACert)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca)
	zipReader, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(zipReader.File) != 3 {
		t.Fatal("unexpected kit contents")
	}
	f, err := zipReader.Open("tls.crt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{DNSName: cfg.Helpers.HostNode, Roots: pool}); err != nil {
		t.Fatal(err)
	}
	if !key.PublicKey.Equal(leaf.PublicKey) || leaf.VerifyHostname("unrequested.example") == nil {
		t.Fatal("incorrect certificate binding")
	}
}
