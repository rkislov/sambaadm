package web

import (
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
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/service"
)

func TestLDAPCertificateLifetimeAndIssuerLimit(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.CertificateDir = filepath.Join(t.TempDir(), "ca")
	ca, key, _, err := s.localCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	for _, years := range []int{1, 3, 5, 10} {
		leaf, err := signLDAPCertificate(ca, key, "dc1.example.org", &key.PublicKey, years)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(leaf)
		cert, _ := x509.ParseCertificate(block.Bytes)
		want := time.Now().AddDate(years, 0, 0)
		if cert.NotAfter.Sub(want) > time.Second || want.Sub(cert.NotAfter) > 2*time.Second {
			t.Fatalf("%d years: %s", years, cert.NotAfter)
		}
		if err = cert.VerifyHostname("dc1.example.org"); err != nil {
			t.Fatal(err)
		}
	}
	limited := *ca
	limited.NotAfter = time.Now().Add(6 * time.Hour).Truncate(time.Second)
	leaf, err := signLDAPCertificate(&limited, key, "dc1.example.org", &key.PublicKey, 10)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(leaf)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if !cert.NotAfter.Equal(limited.NotAfter) {
		t.Fatal("leaf outlives issuer")
	}
	for _, value := range []string{"0", "11", "-1", "1.5", "garbage"} {
		if _, err := certificateYears(value); err == nil {
			t.Fatalf("invalid years %q accepted", value)
		}
	}
	years, err := certificateYears("")
	if err != nil || years != 10 {
		t.Fatal("default must be ten years")
	}
}
func TestCertificateRolloutTrustsEveryDCBeforeInstallingAndStopsOnFailure(t *testing.T) {
	for _, failure := range []string{"", "certificate.trust@dc2.example.org", "certificate.install@dc1.example.org"} {
		t.Run(failure, func(t *testing.T) {
			s := testWorkspaceServer(t)
			s.cfg.Server.CertificateDir = filepath.Join(t.TempDir(), "certificates")
			s.cfg.LDAP.CACert = ""
			s.cfg.LDAP.ManagedCAFile = filepath.Join(s.cfg.Server.CertificateDir, "ldap-ca.pem")
			ca, caKey, caPEM, err := s.localCertificateAuthority()
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			private, public := filepath.Join(dir, "signing.key"), filepath.Join(dir, "signing.pub")
			if err = agent.GenerateKey(private, public); err != nil {
				t.Fatal(err)
			}
			job := &certificateRollout{ID: strings.Repeat("a", 32), Status: "running", Created: time.Now(), Years: 10, CA: caPEM, Actor: "admin"}
			client := &agent.Client{Config: agent.Config{PrivateKey: private}}
			var calls []string
			addresses := map[string]string{}
			for _, node := range []string{"dc1.example.org", "dc2.example.org"} {
				node := node
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				leaf, err := signLDAPCertificate(ca, caKey, node, &key.PublicKey, 10)
				if err != nil {
					t.Fatal(err)
				}
				keyDER, _ := x509.MarshalECPrivateKey(key)
				pair, err := tls.X509KeyPair(leaf, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
				if err != nil {
					t.Fatal(err)
				}
				tlsServer := httptest.NewUnstartedServer(nil)
				tlsServer.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
				tlsServer.StartTLS()
				defer tlsServer.Close()
				addresses[node] = strings.TrimPrefix(tlsServer.URL, "https://")
				verifier, err := agent.NewVerifier(node, []string{public})
				if err != nil {
					t.Fatal(err)
				}
				phase := "prepared"
				helper := httptest.NewTLSServer(agent.API(verifier, func(ctx context.Context, method string, raw json.RawMessage) (any, error) {
					calls = append(calls, method+"@"+node)
					if method+"@"+node == failure {
						return nil, fmt.Errorf("injected node failure")
					}
					if method == "certificate.trust" {
						phase = "trusted"
					}
					if method == "certificate.install" {
						phase = "installed"
					}
					return service.CertificateDeployState{ID: job.ID, Node: node, Phase: phase}, nil
				}))
				defer helper.Close()
				helperCA := filepath.Join(dir, node+".pem")
				os.WriteFile(helperCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: helper.Certificate().Raw}), 0600)
				client.Config.Nodes = append(client.Config.Nodes, agent.Node{Name: node, Transport: "https", Endpoint: helper.URL, CACert: helperCA})
				job.Nodes = append(job.Nodes, certificateRolloutNode{Node: node, Phase: "prepared", Certificate: leaf})
			}
			if err = s.saveCertificateRollout(job); err != nil {
				t.Fatal(err)
			}
			s.runCertificateRolloutWith(job, client, func(ctx context.Context, node string, leaf, ca []byte) error {
				return verifyRolloutLDAPSAt(ctx, node, addresses[node], leaf, ca)
			})
			expected := []string{"certificate.status@dc1.example.org", "certificate.status@dc2.example.org", "certificate.trust@dc1.example.org", "certificate.trust@dc2.example.org"}
			if failure != "certificate.trust@dc2.example.org" {
				expected = append(expected, "certificate.install@dc1.example.org")
				if failure == "" {
					expected = append(expected, "certificate.install@dc2.example.org")
				}
			}
			if failure != "" {
				parts := strings.Split(failure, "@")
				expected = append(expected, "certificate.status@"+parts[1])
			}
			if !reflect.DeepEqual(calls, expected) {
				t.Fatalf("unsafe call order: %v, want %v", calls, expected)
			}
			persisted, err := s.loadCertificateRollout(job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "" && persisted.Status != "complete" {
				t.Fatal(persisted.Status, persisted.Error)
			}
			if failure != "" && persisted.Status != "failed" {
				t.Fatal("failure was reported successful")
			}
			trust, err := os.ReadFile(s.cfg.LDAP.ManagedCAFile)
			if err != nil || !bytes.Contains(trust, caPEM) {
				t.Fatal("management trust missing", err)
			}
			if failure == "" {
				wrong, _ := signLDAPCertificate(ca, caKey, "wrong.example.org", &caKey.PublicKey, 10)
				if err = verifyRolloutLDAPSAt(t.Context(), "dc1.example.org", addresses["dc1.example.org"], wrong, caPEM); err == nil {
					t.Fatal("unexpected server certificate accepted")
				}
			}
		})
	}
}
func TestSignLDAPCertificateUsesOnlyApprovedDNSName(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.CertificateDir = filepath.Join(t.TempDir(), "ca")
	ca, key, _, err := s.localCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	nodeKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "other.example.org"}, DNSNames: []string{"other.example.org", "*.example.org"}}, nodeKey)
	csr, _ := x509.ParseCertificateRequest(csrDER)
	raw, err := signLDAPCertificate(ca, key, "dc1.example.org", csr.PublicKey, 10)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	cert, _ := x509.ParseCertificate(block.Bytes)
	if !reflect.DeepEqual(cert.DNSNames, []string{"dc1.example.org"}) {
		t.Fatal("CSR expanded DNS authorization", cert.DNSNames)
	}
}

func TestCertificateAuthorityRenewalPreservesKeyAndPriorSignatures(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.CertificateDir = filepath.Join(t.TempDir(), "ca")
	ca, key, _, err := s.localCertificateAuthority()
	if err != nil {
		t.Fatal(err)
	}
	short := *ca
	short.NotAfter = time.Now().AddDate(2, 0, 0)
	der, err := x509.CreateCertificate(rand.Reader, &short, &short, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	oldCA, _ := x509.ParseCertificate(der)
	oldPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(key)
	state := certificateAuthority{Certificate: oldPEM, Key: pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}
	raw, _ := json.Marshal(state)
	path := filepath.Join(s.cfg.Server.CertificateDir, "authority.json")
	os.WriteFile(path, raw, 0600)
	oldLeaf, err := signLDAPCertificate(oldCA, key, "dc1.example.org", &key.PublicKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	limited, _, _, changed, err := s.certificateAuthorityForYears(10, false)
	if err != nil || changed || !limited.NotAfter.Equal(oldCA.NotAfter) {
		t.Fatal("issuer changed without request")
	}
	renewed, renewedKey, _, changed, err := s.certificateAuthorityForYears(10, true)
	if err != nil || !changed {
		t.Fatal(changed, err)
	}
	if !renewedKey.PublicKey.Equal(&key.PublicKey) || !renewed.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("renewal replaced CA key")
	}
	if renewed.NotAfter.Before(time.Now().AddDate(19, 0, 0)) {
		t.Fatal("renewed CA does not support ten-year leaves")
	}
	block, _ := pem.Decode(oldLeaf)
	cert, _ := x509.ParseCertificate(block.Bytes)
	roots := x509.NewCertPool()
	roots.AddCert(renewed)
	if _, err = cert.Verify(x509.VerifyOptions{DNSName: "dc1.example.org", Roots: roots}); err != nil {
		t.Fatal("old leaf stopped validating", err)
	}
	copies, _ := filepath.Glob(filepath.Join(s.cfg.Server.CertificateDir, "authority-before-*.json"))
	if len(copies) != 1 {
		t.Fatal("previous authority not backed up")
	}
}
