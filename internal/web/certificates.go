package web

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sambaadm/internal/auth"
	"sambaadm/internal/config"
)

type certificatePage struct {
	Host, URI, Trust, Status       string
	Subject, Issuer, SANs, Expires string
	Helpers                        []string
}

type certificateAuthority struct{ Certificate, Key []byte }

func certificateDir(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return fmt.Errorf("server.certificate_dir должен быть абсолютным путём")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("каталог сертификатов должен иметь права 0700")
	}
	return nil
}

func saveCertificateFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".certificate-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func (s *Server) localCertificateAuthority() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	dir := s.cfg.Server.CertificateDir
	if err := certificateDir(dir); err != nil {
		return nil, nil, nil, err
	}
	path := filepath.Join(dir, "authority.json")
	raw, err := os.ReadFile(path)
	var state certificateAuthority
	if os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, nil, nil, err
		}
		root := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "sambaadm local LDAP CA"}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
		if err != nil {
			return nil, nil, nil, err
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, nil, err
		}
		state = certificateAuthority{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}
		raw, err = json.Marshal(state)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := saveCertificateFile(path, raw); err != nil {
			return nil, nil, nil, err
		}
	} else if err != nil {
		return nil, nil, nil, err
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, nil, nil, err
	}
	certBlock, _ := pem.Decode(state.Certificate)
	keyBlock, _ := pem.Decode(state.Key)
	if certBlock == nil || keyBlock == nil {
		return nil, nil, nil, fmt.Errorf("повреждены данные локального УЦ")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	if !cert.IsCA || !key.PublicKey.Equal(cert.PublicKey) || time.Now().After(cert.NotAfter) {
		return nil, nil, nil, fmt.Errorf("локальный УЦ недействителен")
	}
	return cert, key, state.Certificate, nil
}

func validCABundle(raw []byte) error {
	if len(raw) > 256<<10 {
		return fmt.Errorf("CA-файл не должен превышать 256 КБ")
	}
	count := 0
	for len(bytes.TrimSpace(raw)) > 0 {
		raw = bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
			return fmt.Errorf("нужен PEM с сертификатами CA, без закрытых ключей")
		}
		block, rest := pem.Decode(raw)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("неверный PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		if !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
			return fmt.Errorf("нужен действующий сертификат центра сертификации")
		}
		count++
		raw = rest
	}
	if count == 0 {
		return fmt.Errorf("вставьте сертификат CA в формате PEM")
	}
	return nil
}

func (s *Server) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	u, _ := url.Parse(s.cfg.LDAP.URI)
	view := certificatePage{URI: s.cfg.LDAP.URI, Trust: s.cfg.LDAP.LDAPCAFile()}
	if u != nil && enrollmentDNS(u.Hostname()) {
		view.Host = u.Hostname()
	}
	nodes := s.cfg.Helpers.Nodes
	if s.cfg.Server.EnrollmentDir != "" {
		managed, err := config.ManagedHelpers(s.cfg.Server.EnrollmentDir)
		if err == nil {
			nodes = managed.Nodes
		} else {
			view.Status = "Не удалось прочитать реестр helper: " + err.Error()
		}
	}
	for _, node := range nodes {
		view.Helpers = append(view.Helpers, node.Name)
	}
	pd := s.page(r, "settings.title", nil)
	pd.Title = "Сертификаты и подключения"
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Слишком большой или неверный запрос", 400)
			return
		}
		action := r.FormValue("action")
		switch action {
		case "download-ca":
			s.certMu.Lock()
			_, _, ca, err := s.localCertificateAuthority()
			s.certMu.Unlock()
			if err != nil {
				pd.Error = err.Error()
			} else {
				w.Header().Set("Content-Type", "application/x-pem-file")
				w.Header().Set("Content-Disposition", "attachment; filename=sambaadm-ldap-ca.pem")
				w.Write(ca)
				return
			}
		case "inspect":
			view.Status = s.inspectLDAPCertificate(r.Context(), &view)
		case "trust", "trust-local", "reset-trust":
			s.certMu.Lock()
			dir := s.cfg.Server.CertificateDir
			err := certificateDir(dir)
			path := filepath.Join(dir, "ldap-ca.pem")
			if err == nil && action == "reset-trust" {
				err = os.Remove(path)
				if os.IsNotExist(err) {
					err = nil
				}
			} else if err == nil {
				raw := []byte(r.FormValue("ca"))
				if action == "trust-local" {
					_, _, raw, err = s.localCertificateAuthority()
				}
				if err == nil {
					err = validCABundle(raw)
				}
				if err == nil {
					err = saveCertificateFile(path, raw)
				}
			}
			s.certMu.Unlock()
			if err != nil {
				pd.Error = err.Error()
			} else {
				if s.ldap != nil {
					s.ldap.Close()
				}
				pd.Flash = "Доверие сохранено. Новые LDAP-соединения используют обновлённый CA; перезапуск не требуется."
				if s.audit != nil {
					s.audit.Success(sessionFrom(r).Username, "certificate."+action, "LDAP CA", r.RemoteAddr)
				}
				view.Trust = s.cfg.LDAP.LDAPCAFile()
			}
		case "issue":
			if err := s.issueLDAPCertificate(w, r); err != nil {
				pd.Error = err.Error()
			} else {
				return
			}
		default:
			http.Error(w, "Неизвестное действие", 400)
			return
		}
	}
	pd.Content = view
	s.render(w, "certificates.html", pd)
}

// Certificate discovery sends no LDAP credentials. The observed chain is verified
// separately, so an invalid certificate can be displayed without trusting it.
func (s *Server) inspectLDAPCertificate(ctx context.Context, view *certificatePage) string {
	u, err := url.Parse(s.cfg.LDAP.URI)
	if err != nil || u.Hostname() == "" {
		return "Для проверки нужен LDAP-адрес с DNS-именем контроллера."
	}
	port := "636"
	if u.Scheme == "ldaps" && u.Port() != "" {
		port = u.Port()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), InsecureSkipVerify: true}}).DialContext(ctx, "tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return "Не удалось получить сертификат: " + err.Error()
	}
	defer conn.Close()
	chain := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return "Контроллер не предоставил сертификат."
	}
	cert := chain[0]
	view.Subject = cert.Subject.String()
	view.Issuer = cert.Issuer.String()
	view.SANs = strings.Join(cert.DNSNames, ", ")
	view.Expires = cert.NotAfter.UTC().Format("2006-01-02 15:04 UTC")
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if path := s.cfg.LDAP.LDAPCAFile(); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err.Error()
		}
		if !roots.AppendCertsFromPEM(raw) {
			return "Файл доверия не содержит сертификатов CA."
		}
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: u.Hostname(), Roots: roots, Intermediates: intermediates}); err != nil {
		return "Проверка не пройдена: " + err.Error()
	}
	return "Сертификат действителен: имя, срок и цепочка доверия проверены."
}

func (s *Server) issueLDAPCertificate(w http.ResponseWriter, r *http.Request) error {
	if len(r.FormValue("csr")) > 64<<10 {
		return fmt.Errorf("CSR не должен превышать 64 КБ")
	}
	name := strings.ToLower(strings.TrimSpace(r.FormValue("node")))
	if !enrollmentDNS(name) {
		return fmt.Errorf("укажите полное DNS-имя контроллера")
	}
	var pub any
	var keyPEM []byte
	if r.FormValue("key_mode") == "generate" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		pub = &key.PublicKey
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	} else {
		block, rest := pem.Decode([]byte(r.FormValue("csr")))
		if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
			return fmt.Errorf("вставьте CSR в формате PEM или выберите создание нового ключа")
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return err
		}
		if err := csr.CheckSignature(); err != nil {
			return err
		}
		pub = csr.PublicKey
	}
	s.certMu.Lock()
	defer s.certMu.Unlock()
	ca, key, caPEM, err := s.localCertificateAuthority()
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	expiry := time.Now().AddDate(1, 0, 0)
	if expiry.After(ca.NotAfter) {
		expiry = ca.NotAfter
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: expiry, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, key)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	files := map[string][]byte{"ca.pem": caPEM, "cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "smb.conf.fragment": []byte("# Добавьте параметры в существующую секцию [global].\n# Пути задаются на контроллере после установки файлов.\n[global]\n  tls enabled = yes\n  tls cafile = /etc/samba/tls-sambaadm/ca.pem\n  tls certfile = /etc/samba/tls-sambaadm/cert.pem\n  tls keyfile = /etc/samba/tls-sambaadm/key.pem\n"), "README.txt": []byte("Установите ca.pem и cert.pem на контроллер в /etc/samba/tls-sambaadm с владельцем root:root и правами 0600. Если архив содержит key.pem, установите его туда же; иначе используйте закрытый ключ, для которого создан CSR. Сохраните исходные TLS-файлы и smb.conf. Добавьте параметры из smb.conf.fragment в существующий [global], проверьте testparm и перезапустите службу Samba. В меню сертификатов sambaadm нажмите «Доверять локальному УЦ» и проверьте LDAPS. Файлы на контроллере не меняются автоматически. Закрытый ключ нового сертификата выдаётся только в этом архиве; храните его приватно. Закрытый ключ УЦ остаётся на сервере sambaadm.\n")}
	if len(keyPEM) > 0 {
		files["key.pem"] = keyPEM
	}
	for name, data := range files {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0600)
		f, err := z.CreateHeader(h)
		if err != nil {
			return err
		}
		if _, err = f.Write(data); err != nil {
			return err
		}
	}
	if err := z.Close(); err != nil {
		return err
	}
	if s.audit != nil {
		s.audit.Success(sessionFrom(r).Username, "certificate.issue", name, r.RemoteAddr)
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+name+"-ldaps.zip")
	_, err = w.Write(buf.Bytes())
	return err
}
