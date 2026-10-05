package service

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// Computer is a domain computer account.
type Computer struct {
	DN             string `json:"dn"`
	SAMAccountName string `json:"samAccountName"`
	DNSHostName    string `json:"dnsHostName,omitempty"`
	OS             string `json:"operatingSystem,omitempty"`
	Description    string `json:"description,omitempty"`
}

// ComputerService manages computer objects.
type ComputerService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// List returns computer accounts.
func (s *ComputerService) List(ctx context.Context, q string) ([]Computer, error) {
	filter := "(objectClass=computer)"
	if q != "" {
		esc := ldap.EscapeFilter(q)
		filter = fmt.Sprintf("(&(objectClass=computer)(|(sAMAccountName=*%s*)(cn=*%s*)(dNSHostName=*%s*)))", esc, esc, esc)
	}
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		Filter:     filter,
		Attributes: ldapproto.ComputerAttrs,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Computer, 0, len(entries))
	for _, e := range entries {
		out = append(out, Computer{
			DN:             e.DN,
			SAMAccountName: e.GetAttributeValue(ldapproto.AttrSAMAccountName),
			DNSHostName:    e.GetAttributeValue(ldapproto.AttrDNSHostName),
			OS:             e.GetAttributeValue(ldapproto.AttrOperatingSystem),
			Description:    e.GetAttributeValue(ldapproto.AttrDescription),
		})
	}
	return out, nil
}
