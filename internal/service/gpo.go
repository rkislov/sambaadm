package service

import (
	"context"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// GPO is a Group Policy Object summary.
type GPO struct {
	DisplayName string `json:"displayName"`
	GUID        string `json:"guid,omitempty"`
	DN          string `json:"dn"`
}

// GPOService manages GPOs (basic LDAP listing; CRUD via samba-tool later).
type GPOService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// List returns groupPolicyContainer objects.
func (s *GPOService) List(ctx context.Context) ([]GPO, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		Filter:     "(objectClass=groupPolicyContainer)",
		Attributes: []string{"displayName", "cn", "name"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]GPO, 0, len(entries))
	for _, e := range entries {
		out = append(out, GPO{
			DisplayName: e.GetAttributeValue("displayName"),
			GUID:        e.GetAttributeValue("cn"),
			DN:          e.DN,
		})
	}
	return out, nil
}
