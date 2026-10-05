package service

import (
	"context"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// DNSZone is a DNS zone stored in AD.
type DNSZone struct {
	Name string `json:"name"`
	DN   string `json:"dn"`
}

// DNSService manages AD-integrated DNS (basic).
type DNSService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// ListZones returns dnsZone objects under MicrosoftDNS (when present).
func (s *DNSService) ListZones(ctx context.Context) ([]DNSZone, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		Filter:     "(objectClass=dnsZone)",
		Attributes: []string{"name", "dc"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]DNSZone, 0, len(entries))
	for _, e := range entries {
		name := e.GetAttributeValue("name")
		if name == "" {
			name = e.GetAttributeValue("dc")
		}
		out = append(out, DNSZone{Name: name, DN: e.DN})
	}
	return out, nil
}
