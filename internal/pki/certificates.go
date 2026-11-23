package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Authority struct{ Certificate, Key []byte }

func EnsureDir(dir string) error {
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

func SaveFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".certificate-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func LoadAuthority(dir string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	if err := EnsureDir(dir); err != nil {
		return nil, nil, nil, err
	}
	unlock, err := lockAuthority(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	defer unlock()
	return loadAuthority(dir)
}
func loadAuthority(dir string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	if err := EnsureDir(dir); err != nil {
		return nil, nil, nil, err
	}
	path := filepath.Join(dir, "authority.json")
	raw, err := os.ReadFile(path)
	var state Authority
	if os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, nil, nil, err
		}
		root := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "sambaadm local LDAP CA"}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(20, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
		if err != nil {
			return nil, nil, nil, err
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, nil, nil, err
		}
		state = Authority{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}
		raw, err = json.Marshal(state)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := SaveFile(path, raw); err != nil {
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

// Renew only the CA certificate, retaining the issuer key and identity. All
// existing certificates remain signed by the same key; rollout installs the
// renewed public root on every DC before installing any new server certificate.
func AuthorityForYears(dir string, years int, renew bool) (*x509.Certificate, *ecdsa.PrivateKey, []byte, bool, error) {
	if err := EnsureDir(dir); err != nil {
		return nil, nil, nil, false, err
	}
	unlock, err := lockAuthority(dir)
	if err != nil {
		return nil, nil, nil, false, err
	}
	defer unlock()
	ca, key, caPEM, err := loadAuthority(dir)
	if err != nil || !renew || ca.NotAfter.After(time.Now().AddDate(years, 0, 1)) {
		return ca, key, caPEM, false, err
	}
	root := *ca
	root.NotBefore = time.Now().Add(-5 * time.Minute)
	root.NotAfter = time.Now().AddDate(20, 0, 0)
	root.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, false, err
	}
	der, err := x509.CreateCertificate(rand.Reader, &root, &root, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, false, err
	}
	path := filepath.Join(dir, "authority.json")
	old, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, false, err
	}
	fingerprint := sha256.Sum256(ca.Raw)
	if err = SaveFile(filepath.Join(dir, fmt.Sprintf("authority-before-%x.json", fingerprint[:8])), old); err != nil {
		return nil, nil, nil, false, err
	}
	var state Authority
	if err = json.Unmarshal(old, &state); err != nil {
		return nil, nil, nil, false, err
	}
	state.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	raw, err := json.Marshal(state)
	if err != nil {
		return nil, nil, nil, false, err
	}
	if err = SaveFile(path, raw); err != nil {
		return nil, nil, nil, false, err
	}
	ca, err = x509.ParseCertificate(der)
	return ca, key, state.Certificate, true, err
}

func SignServerCertificate(ca *x509.Certificate, key *ecdsa.PrivateKey, name string, pub any, years int) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	expiry := time.Now().AddDate(years, 0, 0)
	if expiry.After(ca.NotAfter) {
		expiry = ca.NotAfter
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: expiry, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
