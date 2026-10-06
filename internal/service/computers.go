package service

import (
	"context"
	"fmt"
	"strings"

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
		out = append(out, entryToComputer(e))
	}
	return out, nil
}

// Show returns a computer by sAMAccountName (with or without trailing $).
func (s *ComputerService) Show(ctx context.Context, name string) (*Computer, error) {
	e, err := s.find(ctx, name)
	if err != nil {
		return nil, err
	}
	c := entryToComputer(e)
	return &c, nil
}

// Delete removes a computer account.
func (s *ComputerService) Delete(ctx context.Context, name, actor, ip string) error {
	c, err := s.Show(ctx, name)
	if err != nil {
		return err
	}
	if err := s.ldap.Delete(ctx, c.DN); err != nil {
		s.audit.Failure(actor, "computer.delete", c.DN, ip, err)
		return err
	}
	s.audit.Success(actor, "computer.delete", c.DN, ip)
	return nil
}

// Move relocates a computer under a new OU.
func (s *ComputerService) Move(ctx context.Context, name, toOU, actor, ip string) error {
	c, err := s.Show(ctx, name)
	if err != nil {
		return err
	}
	rdn := "CN=" + ldap.EscapeDN(cnFromDN(c.DN))
	if err := s.ldap.ModifyDN(ctx, c.DN, rdn, true, toOU); err != nil {
		s.audit.Failure(actor, "computer.move", c.DN, ip, err)
		return err
	}
	s.audit.Success(actor, "computer.move", c.DN+" -> "+toOU, ip)
	return nil
}

func (s *ComputerService) find(ctx context.Context, name string) (*ldap.Entry, error) {
	sam := name
	if !strings.HasSuffix(sam, "$") {
		sam += "$"
	}
	esc := ldap.EscapeFilter(sam)
	escName := ldap.EscapeFilter(strings.TrimSuffix(name, "$"))
	filter := fmt.Sprintf("(&(objectClass=computer)(|(sAMAccountName=%s)(cn=%s)))", esc, escName)
	return s.ldap.SearchOne(ctx, ldapproto.SearchOptions{
		Filter:     filter,
		Attributes: ldapproto.ComputerAttrs,
	})
}

func entryToComputer(e *ldap.Entry) Computer {
	return Computer{
		DN:             e.DN,
		SAMAccountName: e.GetAttributeValue(ldapproto.AttrSAMAccountName),
		DNSHostName:    e.GetAttributeValue(ldapproto.AttrDNSHostName),
		OS:             e.GetAttributeValue(ldapproto.AttrOperatingSystem),
		Description:    e.GetAttributeValue(ldapproto.AttrDescription),
	}
}
