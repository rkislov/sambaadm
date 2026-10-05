package service

import (
	"context"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// DomainInfo holds basic domain metadata.
type DomainInfo struct {
	DNSRoot     string `json:"dnsRoot,omitempty"`
	NetBIOS     string `json:"netbios,omitempty"`
	DomainSID   string `json:"domainSid,omitempty"`
	FunctionLvl string `json:"functionLevel,omitempty"`
	BaseDN      string `json:"baseDN"`
}

// DomainService exposes domain / FSMO operations.
type DomainService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// Info returns basic domain information.
func (s *DomainService) Info(ctx context.Context) (*DomainInfo, error) {
	info := &DomainInfo{BaseDN: s.ldap.BaseDN()}
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		BaseDN:     s.ldap.BaseDN(),
		Filter:     "(objectClass=domainDNS)",
		Scope:      ldapproto.ScopeBase(),
		Attributes: []string{"dc", "name", "objectSid", "msDS-Behavior-Version"},
		PageSize:   1,
	})
	if err == nil && len(entries) > 0 {
		e := entries[0]
		info.NetBIOS = e.GetAttributeValue("dc")
		info.DNSRoot = e.GetAttributeValue("name")
		info.FunctionLvl = e.GetAttributeValue("msDS-Behavior-Version")
	}
	return info, nil
}
