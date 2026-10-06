package service

import (
	"context"
	"fmt"
	"strings"

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

// CreateGroupInput holds parameters for creating a group.
type CreateGroupInput struct {
	Name        string `json:"name"`
	OU          string `json:"ou,omitempty"`
	Description string `json:"description,omitempty"`
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
		out = append(out, entryToGroup(e))
	}
	return out, nil
}

// Show returns a group by sAMAccountName or CN.
func (s *GroupService) Show(ctx context.Context, name string) (*Group, error) {
	e, err := s.find(ctx, name)
	if err != nil {
		return nil, err
	}
	g := entryToGroup(e)
	return &g, nil
}

// Create adds a new security group.
func (s *GroupService) Create(ctx context.Context, in CreateGroupInput, actor, ip string) (*Group, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	parent := DefaultUsersOU(in.OU, s.ldap.BaseDN())
	dn := BuildDN("CN", name, parent)
	attrs := []ldap.Attribute{
		{Type: ldapproto.AttrObjectClass, Vals: []string{"top", "group"}},
		{Type: ldapproto.AttrCN, Vals: []string{name}},
		{Type: ldapproto.AttrSAMAccountName, Vals: []string{name}},
		{Type: ldapproto.AttrGroupType, Vals: []string{ldapproto.GroupTypeGlobalSecurity}},
	}
	if in.Description != "" {
		attrs = append(attrs, ldap.Attribute{Type: ldapproto.AttrDescription, Vals: []string{in.Description}})
	}
	if err := s.ldap.Add(ctx, dn, attrs); err != nil {
		s.audit.Failure(actor, "group.create", dn, ip, err)
		return nil, err
	}
	s.audit.Success(actor, "group.create", dn, ip)
	return s.Show(ctx, name)
}

// Delete removes a group.
func (s *GroupService) Delete(ctx context.Context, name, actor, ip string) error {
	g, err := s.Show(ctx, name)
	if err != nil {
		return err
	}
	if err := s.ldap.Delete(ctx, g.DN); err != nil {
		s.audit.Failure(actor, "group.delete", g.DN, ip, err)
		return err
	}
	s.audit.Success(actor, "group.delete", g.DN, ip)
	return nil
}

// AddMember adds a member DN to the group.
func (s *GroupService) AddMember(ctx context.Context, group, memberDN, actor, ip string) error {
	g, err := s.Show(ctx, group)
	if err != nil {
		return err
	}
	if err := s.ldap.AddAttrValues(ctx, g.DN, ldapproto.AttrMember, memberDN); err != nil {
		s.audit.Failure(actor, "group.add-member", g.DN, ip, err)
		return err
	}
	s.audit.Success(actor, "group.add-member", g.DN+" + "+memberDN, ip)
	return nil
}

// RemoveMember removes a member DN from the group.
func (s *GroupService) RemoveMember(ctx context.Context, group, memberDN, actor, ip string) error {
	g, err := s.Show(ctx, group)
	if err != nil {
		return err
	}
	if err := s.ldap.DeleteAttrValues(ctx, g.DN, ldapproto.AttrMember, memberDN); err != nil {
		s.audit.Failure(actor, "group.remove-member", g.DN, ip, err)
		return err
	}
	s.audit.Success(actor, "group.remove-member", g.DN+" - "+memberDN, ip)
	return nil
}

// Members lists member DNs of a group.
func (s *GroupService) Members(ctx context.Context, name string) ([]string, error) {
	g, err := s.Show(ctx, name)
	if err != nil {
		return nil, err
	}
	return g.Members, nil
}

func (s *GroupService) find(ctx context.Context, name string) (*ldap.Entry, error) {
	esc := ldap.EscapeFilter(name)
	filter := fmt.Sprintf("(&(objectClass=group)(|(sAMAccountName=%s)(cn=%s)))", esc, esc)
	return s.ldap.SearchOne(ctx, ldapproto.SearchOptions{
		Filter:     filter,
		Attributes: ldapproto.GroupAttrs,
	})
}

func entryToGroup(e *ldap.Entry) Group {
	return Group{
		DN:             e.DN,
		SAMAccountName: e.GetAttributeValue(ldapproto.AttrSAMAccountName),
		Description:    e.GetAttributeValue(ldapproto.AttrDescription),
		Members:        e.GetAttributeValues(ldapproto.AttrMember),
	}
}
