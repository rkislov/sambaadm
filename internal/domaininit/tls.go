package domaininit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sambaadm/internal/pki"
	"strconv"
)

// Each key is generated and retained at the destination. Only the CSR crosses
// the signed helper channel. A fresh package/revision requires a new plan.
func (e *Engine) certificateKey(revision string, in Input) ([]byte, []byte, error) {
	if len(revision) != 64 {
		return nil, nil, fmt.Errorf("Некорректная версия плана")
	}
	for _, r := range revision {
		if !(r >= 'a' && r <= 'f' || r >= '0' && r <= '9') {
			return nil, nil, fmt.Errorf("Некорректная версия плана")
		}
	}
	dir := filepath.Join(e.Dir, "plans", revision)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	path := filepath.Join(dir, "key.pem")
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, err
		}
		raw = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err = pki.SaveFile(path, raw); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, nil, fmt.Errorf("Ключ плана должен быть обычным файлом 0600")
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, nil, fmt.Errorf("Повреждён ключ плана")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Повреждён ключ плана")
	}
	name := in.Hostname + "." + in.Realm
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}}, key)
	return raw, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}), err
}

func SignPlan(plan *Plan, in Input, dir string) error {
	block, _ := pem.Decode(plan.CSR)
	if block == nil {
		return fmt.Errorf("Helper не вернул CSR; обновите его до версии панели")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return fmt.Errorf("Некорректная подпись CSR контроллера")
	}
	ca, key, public, err := pki.LoadAuthority(dir)
	if err != nil {
		return err
	}
	cert, err := pki.SignServerCertificate(ca, key, in.Hostname+"."+in.Realm, csr.PublicKey, 10)
	if err != nil {
		return err
	}
	plan.Certificate, plan.CA = cert, public
	// Bootstrap runs as root; the permanent unprivileged panel owns its CA.
	if (in.Mode == "forest" || in.Mode == "existing") && os.Geteuid() == 0 {
		account, err := user.Lookup("sambaadm")
		if err != nil {
			return fmt.Errorf("Установите пакет sambaadm перед созданием леса")
		}
		uid, err := strconv.Atoi(account.Uid)
		if err != nil {
			return err
		}
		gid, err := strconv.Atoi(account.Gid)
		if err != nil {
			return err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				if err = os.Lchown(filepath.Join(dir, entry.Name()), uid, gid); err != nil {
					return err
				}
			}
		}
		return os.Chown(dir, uid, gid)
	}
	return nil
}
func ValidateCertificate(in Input, expectedCA []byte) error {
	if !bytes.Equal(in.CA, expectedCA) {
		return fmt.Errorf("УЦ изменился после предпросмотра; повторите проверку")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(in.CA) {
		return fmt.Errorf("Некорректный УЦ контроллера")
	}
	block, _ := pem.Decode(in.Certificate)
	if block == nil {
		return fmt.Errorf("Предпросмотр не содержит сертификата контроллера")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("Некорректный сертификат контроллера")
	}
	_, err = cert.Verify(x509.VerifyOptions{DNSName: in.Hostname + "." + in.Realm, Roots: roots})
	if err != nil {
		return fmt.Errorf("Проверка сертификата контроллера не пройдена: %w", err)
	}
	return nil
}
func (e *Engine) deploymentTLS(in Input) (map[string][]byte, error) {
	if err := ValidateCertificate(in, in.CA); err != nil {
		return nil, err
	}
	key, _, err := e.certificateKey(in.Revision, in)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(key)
	secret, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(in.Certificate)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	public, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(&secret.PublicKey) {
		return nil, fmt.Errorf("Ключ контроллера изменился; повторите предпросмотр")
	}
	return map[string][]byte{"tls.key": key, "tls.crt": in.Certificate, "tls-ca.pem": in.CA}, nil
}
