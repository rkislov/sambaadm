package service

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// Group is a security/distribution group.
type Group struct {
	DN             string   `json:"dn"`
	SAMAccountName string   `json:"samAccountName"`
	Description    string   `json:"description,omitempty"`
	Members        []string `json:"members,omitempty"`
}

// GroupService manages AD groups.
type GroupService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// List returns groups matching optional query.
func (s *GroupService) List(ctx context.Context, q string) ([]Group, error) {
	filter := "(objectClass=group)"
	if q != "" {
		esc := ldap.EscapeFilter(q)
		filter = fmt.Sprintf("(&(objectClass=group)(|(sAMAccountName=*%s*)(cn=*%s*)))", esc, esc)
	}
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		Filter:     filter,
		Attributes: ldapproto.GroupAttrs,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Group, 0, len(entries))
	for _, e := range entries {
		out = append(out, Group{
			DN:             e.DN,
			SAMAccountName: e.GetAttributeValue(ldapproto.AttrSAMAccountName),
			Description:    e.GetAttributeValue(ldapproto.AttrDescription),
			Members:        e.GetAttributeValues(ldapproto.AttrMember),
		})
	}
	return out, nil
}
