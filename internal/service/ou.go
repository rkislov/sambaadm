package service

import (
	"context"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// OU is an organizational unit.
type OU struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// OUService manages organizational units.
type OUService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// List returns OUs under the base DN.
func (s *OUService) List(ctx context.Context) ([]OU, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		Filter:     "(objectClass=organizationalUnit)",
		Attributes: []string{ldapproto.AttrCN, "ou", ldapproto.AttrDescription, "name"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]OU, 0, len(entries))
	for _, e := range entries {
		name := e.GetAttributeValue("ou")
		if name == "" {
			name = e.GetAttributeValue("name")
		}
		out = append(out, OU{
			DN:          e.DN,
			Name:        name,
			Description: e.GetAttributeValue(ldapproto.AttrDescription),
		})
	}
	return out, nil
}
