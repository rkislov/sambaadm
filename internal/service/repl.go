package service

import (
	"context"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// ReplPartner is a replication partner summary.
type ReplPartner struct {
	Name   string `json:"name"`
	DN     string `json:"dn,omitempty"`
	Status string `json:"status,omitempty"`
}

// ReplService manages AD replication.
type ReplService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// Partners returns known nTDSDSA objects (stub).
func (s *ReplService) Partners(ctx context.Context) ([]ReplPartner, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		Filter:     "(objectClass=nTDSDSA)",
		Attributes: []string{"cn", "dNSHostName", "invocationId"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]ReplPartner, 0, len(entries))
	for _, e := range entries {
		name := e.GetAttributeValue("dNSHostName")
		if name == "" {
			name = e.GetAttributeValue("cn")
		}
		out = append(out, ReplPartner{Name: name, DN: e.DN, Status: "unknown"})
	}
	return out, nil
}
