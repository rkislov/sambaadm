package service

import (
	"context"
	"fmt"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// Trust describes a domain trust relationship.
// Full create/validate/delete will wrap samba-tool / RPC in later stages.
type Trust struct {
	Domain    string `json:"domain"`
	Direction string `json:"direction,omitempty"`
	Type      string `json:"type,omitempty"`
	DN        string `json:"dn,omitempty"`
}

// TrustService manages domain trusts.
type TrustService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// List returns trust objects from the configuration partition (stub via LDAP).
func (s *TrustService) List(ctx context.Context) ([]Trust, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		Filter:     "(objectClass=trustedDomain)",
		Attributes: []string{"cn", "trustDirection", "trustType", "trustPartner"},
	})
	if err != nil {
		return nil, fmt.Errorf("list trusts: %w", err)
	}
	out := make([]Trust, 0, len(entries))
	for _, e := range entries {
		out = append(out, Trust{
			Domain:    e.GetAttributeValue("trustPartner"),
			Direction: e.GetAttributeValue("trustDirection"),
			Type:      e.GetAttributeValue("trustType"),
			DN:        e.DN,
		})
	}
	return out, nil
}
