package service

import (
	"fmt"
	"github.com/go-ldap/ldap/v3"
)

func parseBackupBase(value string) (*ldap.DN, error) {
	dn, err := ldap.ParseDN(value)
	if err != nil || len(dn.RDNs) == 0 {
		return nil, fmt.Errorf("invalid backup domain DN")
	}
	return dn, nil
}
func backupDNWithin(value string, base *ldap.DN) bool {
	dn, err := ldap.ParseDN(value)
	return err == nil && (base.EqualFold(dn) || base.AncestorOfFold(dn))
}
