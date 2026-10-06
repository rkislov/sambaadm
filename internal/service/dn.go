package service

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// BuildDN constructs "RDNType=value,parentDN".
func BuildDN(rdnType, value, parentDN string) string {
	return fmt.Sprintf("%s=%s,%s", rdnType, ldap.EscapeDN(value), parentDN)
}

// DefaultUsersOU returns CN=Users,<baseDN> when ou is empty.
func DefaultUsersOU(ou, baseDN string) string {
	if strings.TrimSpace(ou) != "" {
		return ou
	}
	return "CN=Users," + baseDN
}

// DefaultComputersOU returns CN=Computers,<baseDN> when ou is empty.
func DefaultComputersOU(ou, baseDN string) string {
	if strings.TrimSpace(ou) != "" {
		return ou
	}
	return "CN=Computers," + baseDN
}

// cnFromDN returns the unescaped value of the first RDN attribute
// (CN/OU/etc). Uses RFC 4514 parsing so escaped commas in values work.
func cnFromDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return cnFromDNFallback(dn)
	}
	return parsed.RDNs[0].Attributes[0].Value
}

// rdnFromDN returns the first RDN as a properly escaped string for ModifyDN
// (e.g. `CN=Smith\, John`).
func rdnFromDN(dn string) (string, error) {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return "", fmt.Errorf("parse DN: %w", err)
	}
	if len(parsed.RDNs) == 0 {
		return "", fmt.Errorf("empty DN")
	}
	return parsed.RDNs[0].String(), nil
}

func cnFromDNFallback(dn string) string {
	// Last resort: split on unescaped commas only.
	var b strings.Builder
	escaped := false
	for i := 0; i < len(dn); i++ {
		c := dn[i]
		if escaped {
			b.WriteByte(c)
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			b.WriteByte(c)
			continue
		}
		if c == ',' {
			break
		}
		b.WriteByte(c)
	}
	kv := strings.SplitN(b.String(), "=", 2)
	if len(kv) != 2 {
		return b.String()
	}
	return kv[1]
}
