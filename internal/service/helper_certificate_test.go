package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sambaadm/internal/config"
	"strings"
	"testing"
	"time"
)

func TestHelperCertificateTransactionAndFailedRestartRollback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("disposable root container required")
	}
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			dir := t.TempDir()
			if err := certificateSafeDir(dir); err != nil {
				t.Skip("set TMPDIR to a root-owned directory below /var/lib for this test")
			}
			node := "dc1.example.org"
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(20, 0, 0)}
			der, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
			ca, _ := x509.ParseCertificate(der)
			caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			os.WriteFile(filepath.Join(dir, "ca.pem"), caPEM, 0600)
			os.WriteFile(filepath.Join(dir, "cert.pem"), caPEM, 0600)
			conf := filepath.Join(dir, "smb.conf")
			original := []byte("[global]\n realm = EXAMPLE.ORG\n netbios name = DC1\n server role = active directory domain controller\n[share]\n path = /srv/share\n")
			os.WriteFile(conf, original, 0640)
			cfg := &config.Config{Samba: config.SambaConfig{SMBConf: conf}, Helper: config.HelperServerConfig{Node: node, StateDir: dir}}
			restarts := 0
			runtime := certificateRuntime{tlsRoot: filepath.Join(dir, "tls"), trustRoot: filepath.Join(dir, "anchors"), trustCommand: filepath.Join(dir, "trust-tool")}
			os.WriteFile(runtime.trustCommand, []byte("tool"), 0700)
			runtime.command = func(ctx context.Context, path string, args ...string) ([]byte, error) {
				if path == "/usr/bin/testparm" && len(args) > 1 && strings.HasPrefix(args[1], "--parameter-name=") {
					param := strings.TrimPrefix(args[1], "--parameter-name=")
					values := map[string]string{"server role": "active directory domain controller", "realm": "EXAMPLE.ORG", "netbios name": "DC1", "tls certfile": filepath.Join(dir, "cert.pem"), "tls cafile": filepath.Join(dir, "ca.pem"), "private dir": dir}
					return []byte(values[param]), nil
				}
				if len(args) > 0 && args[0] == "restart" {
					restarts++
				}
				return nil, nil
			}
			runtime.probe = func(ctx context.Context, node string, expected, roots []byte) error {
				if fail && len(roots) > 0 {
					return fmt.Errorf("new certificate verification failed")
				}
				return nil
			}
			in := CertificateDeployInput{ID: strings.Repeat("a", 32), Node: node}
			call := func(method string) (*CertificateDeployState, error) {
				data, _ := json.Marshal(in)
				return helperCertificateWith(t.Context(), cfg, method, data, runtime)
			}
			state, err := call("certificate.prepare")
			if err != nil {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(state)
			if bytes.Contains(encoded, []byte("PRIVATE KEY")) {
				t.Fatal("helper exported private key")
			}
			if got, _ := os.ReadFile(conf); !bytes.Equal(got, original) {
				t.Fatal("prepare changed live configuration")
			}
			block, _ := pem.Decode(state.CSR)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil || csr.CheckSignature() != nil {
				t.Fatal("invalid CSR", err)
			}
			leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{node}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			leaf, _ := x509.CreateCertificate(rand.Reader, leafTemplate, ca, csr.PublicKey, key)
			in.CA = caPEM
			in.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
			if _, err = call("certificate.install"); err == nil {
				t.Fatal("install before trust accepted")
			}
			if _, err = call("certificate.trust"); err != nil {
				t.Fatal(err)
			}
			beforeInstall, _ := os.ReadFile(conf)
			state, err = call("certificate.install")
			if fail {
				if err == nil {
					t.Fatal("verification failure hidden")
				}
				got, _ := os.ReadFile(conf)
				if !bytes.Equal(got, beforeInstall) {
					t.Fatal("failed install did not restore previous configuration")
				}
				if restarts != 3 {
					t.Fatalf("expected trust, install and rollback restarts, got %d", restarts)
				}
			} else {
				if err != nil || state.Phase != "installed" {
					t.Fatal(state, err)
				}
				if _, err = call("certificate.rollback"); err != nil {
					t.Fatal(err)
				}
				got, _ := os.ReadFile(conf)
				if !bytes.Equal(got, original) {
					t.Fatal("rollback did not restore original configuration")
				}
			}
			// Simulate a process interruption after the journal was saved but before
			// the install configuration was written. The trusted predecessor must be
			// recognized for an explicit rollback, rather than overwritten blindly.
			if !fail {
				os.WriteFile(conf, beforeInstall, 0640)
				statePath := filepath.Join(dir, "ldap-certificates", in.ID, "state.json")
				interrupted := *state
				interrupted.Phase = "applying"
				interrupted.Revision = certificateDigest([]byte("unwritten proposed configuration"))
				interrupted.PreviousRevision = certificateDigest(beforeInstall)
				journal, _ := json.Marshal(interrupted)
				os.WriteFile(statePath, journal, 0600)
				if _, err = call("certificate.rollback"); err != nil {
					t.Fatal("interrupted install could not be rolled back", err)
				}
				restored, _ := os.ReadFile(conf)
				if !bytes.Equal(restored, original) {
					t.Fatal("interrupted rollback did not restore original")
				}
			}
			info, _ := os.Stat(conf)
			if info.Mode().Perm() != 0640 {
				t.Fatal("configuration permissions changed")
			}
			os.WriteFile(conf, []byte("external change"), 0640)
			if _, err = call("certificate.rollback"); err == nil {
				t.Fatal("overwrote external configuration change")
			}
		})
	}
}
