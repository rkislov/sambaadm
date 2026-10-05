package service

import (
	"context"
	"fmt"
	"strconv"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// User is a domain user account.
type User struct {
	DN             string `json:"dn"`
	SAMAccountName string `json:"samAccountName"`
	DisplayName    string `json:"displayName,omitempty"`
	UPN            string `json:"userPrincipalName,omitempty"`
	Mail           string `json:"mail,omitempty"`
	Enabled        bool   `json:"enabled"`
	Description    string `json:"description,omitempty"`
}

// UserService manages AD users.
type UserService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// List returns users under optional OU, with optional substring filter.
func (s *UserService) List(ctx context.Context, ou, q string) ([]User, error) {
	filter := "(&(objectCategory=person)(objectClass=user))"
	if q != "" {
		esc := ldap.EscapeFilter(q)
		filter = fmt.Sprintf(
			"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=*%s*)(displayName=*%s*)(cn=*%s*)))",
			esc, esc, esc,
		)
	}
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		BaseDN:     ou,
		Filter:     filter,
		Attributes: ldapproto.UserAttrs,
	})
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(entries))
	for _, e := range entries {
		out = append(out, entryToUser(e))
	}
	return out, nil
}

// Show returns a single user by sAMAccountName.
func (s *UserService) Show(ctx context.Context, login string) (*User, error) {
	filter := fmt.Sprintf(
		"(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))",
		ldap.EscapeFilter(login),
	)
	e, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{
		Filter:     filter,
		Attributes: ldapproto.UserAttrs,
	})
	if err != nil {
		return nil, err
	}
	u := entryToUser(e)
	return &u, nil
}

func entryToUser(e *ldap.Entry) User {
	enabled := true
	if uac := e.GetAttributeValue(ldapproto.AttrUserAccountCtrl); uac != "" {
		if v, err := strconv.Atoi(uac); err == nil {
			enabled = v&ldapproto.UACAccountDisable == 0
		}
	}
	return User{
		DN:             e.DN,
		SAMAccountName: e.GetAttributeValue(ldapproto.AttrSAMAccountName),
		DisplayName:    e.GetAttributeValue(ldapproto.AttrDisplayName),
		UPN:            e.GetAttributeValue(ldapproto.AttrUserPrincipal),
		Mail:           e.GetAttributeValue(ldapproto.AttrMail),
		Enabled:        enabled,
		Description:    e.GetAttributeValue(ldapproto.AttrDescription),
	}
}
