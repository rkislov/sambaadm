package service

import (
	"strings"
)

// ConfigDN derives CN=Configuration,<domainDN> from the domain base DN.
func ConfigDN(baseDN string) string {
	return "CN=Configuration," + baseDN
}

// SchemaDN returns the schema naming context DN.
func SchemaDN(baseDN string) string {
	return "CN=Schema," + ConfigDN(baseDN)
}

// SitesContainerDN returns CN=Sites,CN=Configuration,<base>.
func SitesContainerDN(baseDN string) string {
	return "CN=Sites," + ConfigDN(baseDN)
}

// SubnetsContainerDN returns CN=Subnets,CN=Sites,CN=Configuration,<base>.
func SubnetsContainerDN(baseDN string) string {
	return "CN=Subnets," + SitesContainerDN(baseDN)
}

// TrustDirectionName maps AD trustDirection bitmask to a label.
func TrustDirectionName(v string) string {
	switch strings.TrimSpace(v) {
	case "1":
		return "inbound"
	case "2":
		return "outbound"
	case "3":
		return "bidirectional"
	default:
		if v == "" {
			return "unknown"
		}
		return v
	}
}

// TrustTypeName maps AD trustType to a label.
func TrustTypeName(v string) string {
	switch strings.TrimSpace(v) {
	case "1":
		return "windows_non_ad"
	case "2":
		return "windows_ad"
	case "3":
		return "mit"
	case "4":
		return "dormant"
	default:
		if v == "" {
			return "unknown"
		}
		return v
	}
}
