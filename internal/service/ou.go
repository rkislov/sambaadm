package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// OU is an organizational unit.
type OU struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// CreateOUInput holds parameters for creating an OU.
type CreateOUInput struct {
	Name        string `json:"name"`
	ParentDN    string `json:"parentDN,omitempty"`
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
		Attributes: []string{ldapproto.AttrCN, ldapproto.AttrOU, ldapproto.AttrDescription, "name"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]OU, 0, len(entries))
	for _, e := range entries {
		out = append(out, entryToOU(e))
	}
	return out, nil
}

// Create adds a new organizational unit.
func (s *OUService) Create(ctx context.Context, in CreateOUInput, actor, ip string) (*OU, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	parent := in.ParentDN
	if parent == "" {
		parent = s.ldap.BaseDN()
	}
	dn := BuildDN("OU", name, parent)
	attrs := []ldap.Attribute{
		{Type: ldapproto.AttrObjectClass, Vals: []string{"top", "organizationalUnit"}},
		{Type: ldapproto.AttrOU, Vals: []string{name}},
	}
	if in.Description != "" {
		attrs = append(attrs, ldap.Attribute{Type: ldapproto.AttrDescription, Vals: []string{in.Description}})
	}
	if err := s.ldap.Add(ctx, dn, attrs); err != nil {
		s.audit.Failure(actor, "ou.create", dn, ip, err)
		return nil, err
	}
	s.audit.Success(actor, "ou.create", dn, ip)
	return &OU{DN: dn, Name: name, Description: in.Description}, nil
}

// Delete removes an OU by DN (must be empty on most DCs).
func (s *OUService) Delete(ctx context.Context, dn, actor, ip string) error {
	if err := s.ldap.Delete(ctx, dn); err != nil {
		s.audit.Failure(actor, "ou.delete", dn, ip, err)
		return err
	}
	s.audit.Success(actor, "ou.delete", dn, ip)
	return nil
}

// Move relocates an OU under a new parent.
func (s *OUService) Move(ctx context.Context, dn, toParent, actor, ip string) error {
	rdn := "OU=" + ldap.EscapeDN(cnFromDN(dn))
	if err := s.ldap.ModifyDN(ctx, dn, rdn, true, toParent); err != nil {
		s.audit.Failure(actor, "ou.move", dn, ip, err)
		return err
	}
	s.audit.Success(actor, "ou.move", dn+" -> "+toParent, ip)
	return nil
}

// Tree returns a flat list suitable for tree rendering (name + DN).
func (s *OUService) Tree(ctx context.Context) ([]OU, error) {
	return s.List(ctx)
}

func entryToOU(e *ldap.Entry) OU {
	name := e.GetAttributeValue(ldapproto.AttrOU)
	if name == "" {
		name = e.GetAttributeValue("name")
	}
	return OU{
		DN:          e.DN,
		Name:        name,
		Description: e.GetAttributeValue(ldapproto.AttrDescription),
	}
}
