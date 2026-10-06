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

func cnFromDN(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return dn
	}
	kv := strings.SplitN(parts[0], "=", 2)
	if len(kv) != 2 {
		return parts[0]
	}
	return kv[1]
}
