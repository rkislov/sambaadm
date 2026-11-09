package ldap

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"net/netip"
	"strings"

	"sambaadm/internal/config"
)

type legacyCNKey struct{}

func WithLegacyCN(ctx context.Context, allow bool) context.Context {
	return context.WithValue(ctx, legacyCNKey{}, allow)
}
func CarryTLSProfile(to, from context.Context) context.Context {
	if allow, ok := from.Value(legacyCNKey{}).(bool); ok {
		return WithLegacyCN(to, allow)
	}
	return to
}
func LegacyCNAllowed(ctx context.Context, cfg config.LDAPConfig) (bool, error) {
	if allow, ok := ctx.Value(legacyCNKey{}).(bool); ok {
		return allow, nil
	}
	return cfg.LegacyCNAllowed()
}

// VerifyServerCertificate retains normal chain/EKU/time/name validation. The
// explicit compatibility profile only permits an exact DNS CN when SAN is absent.
func VerifyServerCertificate(chain []*x509.Certificate, host string, roots *x509.CertPool, allowLegacy bool) error {
	if len(chain) == 0 {
		return fmt.Errorf("LDAP server provided no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	opts := x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	_, normalError := chain[0].Verify(opts)
	if normalError == nil {
		return nil
	}
	_, ipError := netip.ParseAddr(host)
	if !allowLegacy || ipError == nil {
		return normalError
	}
	for _, extension := range chain[0].Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			return normalError
		}
	}
	cn := chain[0].Subject.CommonName
	if strings.Contains(cn, "*") || !strings.EqualFold(strings.TrimSuffix(cn, "."), strings.TrimSuffix(host, ".")) {
		return normalError
	}
	opts.DNSName = ""
	verified, err := chain[0].Verify(opts)
	if err != nil {
		return err
	}
	// CN is not a SAN and cannot participate in Go's DNS name-constraint checks.
	// Fail closed for constrained chains rather than bypassing those constraints.
	for _, candidate := range verified {
		constrained := false
		for _, issuer := range candidate[1:] {
			for _, extension := range issuer.Extensions {
				if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 30}) {
					constrained = true
				}
			}
		}
		if !constrained {
			return nil
		}
	}
	return fmt.Errorf("legacy CN with CA name constraints requires a certificate with SAN")
}
