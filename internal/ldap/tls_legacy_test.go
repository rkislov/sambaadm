package ldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sambaadm/internal/config"
	"sambaadm/internal/testldap"
)

func legacyCertificate(t *testing.T, cn string, sans []string, expired, wrongEKU, constrained, uriSAN bool) ([]*x509.Certificate, *x509.CertPool, tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	if constrained {
		ca.PermittedDNSDomainsCritical = true
		ca.PermittedDNSDomains = []string{"allowed.example"}
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: cn}, DNSNames: sans, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	if expired {
		leaf.NotAfter = time.Now().Add(-time.Minute)
	}
	if wrongEKU {
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if uriSAN {
		raw, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 6, Bytes: []byte("https://localhost")}})
		leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: raw}}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	keyDER, _ := x509.MarshalECPrivateKey(key)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	return []*x509.Certificate{cert, root}, pool, pair, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
}

func TestLegacyCNDoesNotDisableCertificateValidation(t *testing.T) {
	for _, tc := range []struct {
		name, cn, host                                               string
		sans                                                         []string
		expired, wrongEKU, constrained, uriSAN, unknown, allow, want bool
	}{
		{name: "strict rejects no SAN", cn: "dc0.example.org", host: "dc0.example.org"},
		{name: "exact CN allowed", cn: "DC0.example.org", host: "dc0.example.org", allow: true, want: true},
		{name: "wrong CN", cn: "dc1.example.org", host: "dc0.example.org", allow: true},
		{name: "wrong SAN not hidden by CN", cn: "dc0.example.org", host: "dc0.example.org", sans: []string{"dc1.example.org"}, allow: true},
		{name: "matching SAN remains standard", cn: "other.example.org", host: "dc0.example.org", sans: []string{"dc0.example.org"}, allow: true, want: true},
		{name: "expired", cn: "dc0.example.org", host: "dc0.example.org", expired: true, allow: true},
		{name: "untrusted", cn: "dc0.example.org", host: "dc0.example.org", unknown: true, allow: true},
		{name: "client cert", cn: "dc0.example.org", host: "dc0.example.org", wrongEKU: true, allow: true},
		{name: "wildcard CN rejected", cn: "*.example.org", host: "dc0.example.org", allow: true},
		{name: "IPv6 scope CN rejected", cn: "fe80::1%eth0", host: "fe80::1%eth0", allow: true},
		{name: "IP CN rejected", cn: "127.0.0.1", host: "127.0.0.1", allow: true},
		{name: "name constraints preserved", cn: "dc0.example.org", host: "dc0.example.org", constrained: true, allow: true},
		{name: "non-DNS SAN prevents fallback", cn: "localhost", host: "localhost", uriSAN: true, allow: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain, roots, _, _ := legacyCertificate(t, tc.cn, tc.sans, tc.expired, tc.wrongEKU, tc.constrained, tc.uriSAN)
			if tc.unknown {
				roots = x509.NewCertPool()
			}
			err := VerifyServerCertificate(chain, tc.host, roots, tc.allow)
			if (err == nil) != tc.want {
				t.Fatalf("accepted=%v, expected=%v: %v", err == nil, tc.want, err)
			}
		})
	}
}

func TestSharedServiceDoesNotLendLegacyConnectionsToStrictSessions(t *testing.T) {
	_, _, pair, root := legacyCertificate(t, "localhost", nil, false, false, false, false)
	fake := testldap.NewTLS(t, map[string]string{"service": "service-password"}, nil, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, root, 0600); err != nil {
		t.Fatal(err)
	}
	uri := strings.Replace(fake.URI(), "127.0.0.1", "localhost", 1)
	client := NewServiceClient(config.LDAPConfig{URI: uri, CACert: ca, Bind: config.BindConfig{User: "service", Type: "simple"}}, func() string { return "service-password" })
	defer client.Close()
	legacy := WithLegacyCN(t.Context(), true)
	strict := WithLegacyCN(t.Context(), false)
	first, err := client.Conn(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				if _, err := client.Conn(strict); err == nil {
					t.Error("strict user reused CN-only connection")
				}
			} else {
				conn, err := client.Conn(legacy)
				if err != nil || conn != first {
					t.Error("legacy service connection not reused")
				}
			}
		}(i)
	}
	wg.Wait()
	binds := fake.Binds()
	if len(binds) != 1 || binds[0].User != "service" {
		t.Fatal("service identity changed", binds)
	}
}

func TestInsecureLDAPProfileIsExplicitAndIsolated(t *testing.T) {
	_, _, pair, _ := legacyCertificate(t, "wrong.example.org", nil, true, false, false, false)
	fake := testldap.NewTLS(t, map[string]string{"service": "service-password"}, nil, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
	client := NewServiceClient(config.LDAPConfig{URI: fake.URI(), Bind: config.BindConfig{User: "service", Type: "simple"}}, func() string { return "service-password" })
	defer client.Close()
	insecure := WithInsecureTLS(t.Context(), true)
	first, err := client.Conn(insecure)
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []context.Context{t.Context(), WithLegacyCN(t.Context(), true), WithInsecureTLS(t.Context(), false)} {
		if _, err := client.Conn(ctx); err == nil {
			t.Fatal("verified profile reused insecure connection")
		}
	}
	carried := CarryTLSProfile(context.Background(), insecure)
	if !InsecureTLSAllowed(carried) {
		t.Fatal("background profile lost")
	}
	if got, err := client.Conn(carried); err != nil || got != first {
		t.Fatal("insecure connection not reused within profile", err)
	}
	if InsecureTLSAllowed(CarryTLSProfile(insecure, WithInsecureTLS(t.Context(), false))) {
		t.Fatal("explicit strict profile lost")
	}
}
