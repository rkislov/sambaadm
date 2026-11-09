package web

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/auth"
	"sambaadm/internal/config"
)

var dnsLabel = regexp.MustCompile("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

func enrollmentDNS(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func helperCertificate(node string, csr *x509.CertificateRequest) (ca, cert []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sambaadm " + node}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root, err := x509.CreateCertificate(rand.Reader, parent, parent, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: node}, DNSNames: []string{node}, NotBefore: parent.NotBefore, NotAfter: parent.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, parent, csr.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	encode := func(raw []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}) }
	return encode(root), encode(der), nil
}

func (s *Server) enrollHelper(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	dir := s.cfg.Server.EnrollmentDir
	if r.Method == "GET" {
		s.render(w, "enrollment.html", s.page(r, "settings.title", dir != ""))
		return
	}
	if dir == "" {
		http.Error(w, "Регистрация отключена", 409)
		return
	}
	node := strings.ToLower(strings.TrimSpace(r.FormValue("node")))
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	var keyPEM []byte
	csrPEM := []byte(r.FormValue("csr"))
	if r.FormValue("key_mode") == "generate" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			http.Error(w, "Ошибка создания ключа", 500)
			return
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			http.Error(w, "Ошибка кодирования ключа", 500)
			return
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if err != nil {
			http.Error(w, "Ошибка создания CSR", 500)
			return
		}
		csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	}
	block, _ := pem.Decode(csrPEM)
	if !enrollmentDNS(node) || !enrollmentDNS(domain) || block == nil || len(block.Bytes) > 16384 || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "Проверьте DNS-имена и CSR", 400)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		http.Error(w, "Недействительный CSR", 400)
		return
	}
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	bundle, err := s.registerHelper(dir, node, domain, csr, r.FormValue("host") == "on", r.FormValue("sysvol") == "on", keyPEM)
	if err != nil {
		http.Error(w, "Ошибка подготовки комплекта: "+err.Error(), 500)
		return
	}
	if s.audit != nil {
		s.audit.Success(sessionFrom(r).Username, "helper.enroll", node, r.RemoteAddr)
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+node+"-helper.zip")
	w.Write(bundle)
}

func (s *Server) registerHelper(dir, node, domain string, csr *x509.CertificateRequest, host, sysvol bool, keyPEM []byte) ([]byte, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("enrollment_dir requires mode 0700")
	}
	c, err := config.ManagedHelpers(dir)
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "management.key")
	key, err := agent.LoadPrivate(keyPath)
	if errors.Is(err, os.ErrNotExist) && len(c.Nodes) == 0 {
		if err = agent.GenerateKey(keyPath, filepath.Join(dir, "management.pub")); err != nil {
			return nil, err
		}
		key, err = agent.LoadPrivate(keyPath)
	}
	if err != nil {
		return nil, err
	}
	ca, cert, err := helperCertificate(node, csr)
	if err != nil {
		return nil, err
	}
	caPath := filepath.Join(dir, fmt.Sprintf("%x.pem", sha256.Sum256(ca)))
	entry := agent.Node{Name: node, Transport: "https", Endpoint: "https://" + node + ":8444", CACert: caPath}
	replaced := false
	for i, n := range c.Nodes {
		if n.Name == node {
			c.Nodes[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		c.Nodes = append(c.Nodes, entry)
	}
	if c.HostNode == "" || host {
		c.HostNode = node
	}
	c.PrivateKey = keyPath
	if err = c.Validate(); err != nil {
		return nil, err
	}
	const root = "/etc/sambaadm-helper/"
	helper := map[string]any{"node": node, "trusted_keys": []string{root + "management.pub"}, "listen": ":8444", "tls": map[string]string{"cert": root + "tls.crt", "key": root + "tls.key"}, "sysvol_prefix": domain + "/Policies", "backup_root": "/var/lib/sambaadm-helper/backups"}
	if sysvol {
		helper["password_file"] = root + "domain.password"
	}
	payload, err := json.MarshalIndent(map[string]any{"helper": helper, "ldap": map[string]any{"uri": "ldaps://127.0.0.1:636", "base_dn": s.cfg.LDAP.BaseDN, "bind": map[string]string{"type": "simple", "user": s.cfg.LDAP.Bind.User, "password_env": "SAMBAADM_PASSWORD"}}, "audit": map[string]string{"file": "/var/log/sambaadm-helper/audit.log"}}, "", "  ")
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	files := map[string][]byte{"config.yaml": payload, "tls.crt": cert, "management.pub": []byte(base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) + "\n")}
	if len(keyPEM) > 0 {
		files["tls.key"] = keyPEM
	}
	for name, data := range files {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0600)
		f, e := z.CreateHeader(header)
		if e != nil {
			return nil, e
		}
		if _, e = f.Write(data); e != nil {
			return nil, e
		}
	}
	if err = z.Close(); err != nil {
		return nil, err
	}
	record, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(caPath, ca, 0600); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, ".nodes-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(record)
	closeErr := tmp.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return nil, err
	}
	if err = os.Rename(tmp.Name(), filepath.Join(dir, "nodes.json")); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
