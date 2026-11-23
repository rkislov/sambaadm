package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

func LoadServerPair(certFile, keyFile, dns string) (tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return pair, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return pair, err
	}
	if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return pair, fmt.Errorf("HTTPS certificate is not currently valid")
	}
	if dns != "" {
		if err = leaf.VerifyHostname(dns); err != nil {
			return pair, fmt.Errorf("HTTPS hostname: %w", err)
		}
	}
	pair.Leaf = leaf
	return pair, nil
}
