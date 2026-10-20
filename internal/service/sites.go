package service

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// Site is an AD site.
type Site struct {
	Name string `json:"name"`
	DN   string `json:"dn"`
}

// Subnet is an AD subnet linked to a site.
type Subnet struct {
	Name string `json:"name"`
	DN   string `json:"dn"`
	Site string `json:"site,omitempty"`
}

// SiteService manages sites.
type SiteService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// SubnetService manages subnets.
type SubnetService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
}

// List returns sites.
func (s *SiteService) List(ctx context.Context) ([]Site, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		BaseDN:     SitesContainerDN(s.ldap.BaseDN()),
		Filter:     "(objectClass=site)",
		Attributes: []string{"cn", "name"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]Site, 0, len(entries))
	for _, e := range entries {
		name := e.GetAttributeValue("cn")
		if name == "" {
			name = e.GetAttributeValue("name")
		}
		out = append(out, Site{Name: name, DN: e.DN})
	}
	return out, nil
}

// Create adds a site under CN=Sites,CN=Configuration.
func (s *SiteService) Create(ctx context.Context, name, actor, ip string) (*Site, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	dn := BuildDN("CN", name, SitesContainerDN(s.ldap.BaseDN()))
	attrs := []ldap.Attribute{
		{Type: ldapproto.AttrObjectClass, Vals: []string{"top", "site"}},
		{Type: ldapproto.AttrCN, Vals: []string{name}},
	}
	if err := s.ldap.Add(ctx, dn, attrs); err != nil {
		s.audit.Failure(actor, "site.create", dn, ip, err)
		return nil, err
	}
	// A usable AD site needs both standard child objects. Roll back a partial
	// create instead of reporting success while hiding a container failure.
	for _, child := range []struct{ name, class string }{{"Servers", "serversContainer"}, {"NTDS Site Settings", "nTDSSiteSettings"}} {
		childDN := BuildDN("CN", child.name, dn)
		if err := s.ldap.Add(ctx, childDN, []ldap.Attribute{{Type: "objectClass", Vals: []string{"top", child.class}}, {Type: "cn", Vals: []string{child.name}}}); err != nil {
			cleanup := s.ldap.Delete(context.Background(), BuildDN("CN", "Servers", dn))
			rollback := s.ldap.Delete(context.Background(), dn)
			s.audit.Failure(actor, "site.create", dn, ip, err)
			return nil, fmt.Errorf("create site child: %w (rollback: %v, %v)", err, cleanup, rollback)
		}
	}

	s.audit.Success(actor, "site.create", dn, ip)
	return &Site{Name: name, DN: dn}, nil
}

// Delete removes a site by name.
func (s *SiteService) Delete(ctx context.Context, name, actor, ip string) error {
	dn := BuildDN("CN", name, SitesContainerDN(s.ldap.BaseDN()))
	// Refuse deletion while controllers, subnets or site links still refer to
	// the site. Never use LDAP subtree delete on a site.
	refs, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: SitesContainerDN(s.ldap.BaseDN()), Filter: "(|(&(objectClass=subnet)(siteObject=" + ldap.EscapeFilter(dn) + "))(&(objectClass=siteLink)(siteList=" + ldap.EscapeFilter(dn) + ")))", Attributes: []string{"cn"}})
	if err != nil {
		return err
	}
	if len(refs) > 0 {
		return topologyBad("site is referenced by subnets or site links")
	}
	scope := ldap.ScopeSingleLevel
	servers := BuildDN("CN", "Servers", dn)
	children, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: servers, Scope: &scope, Filter: "(objectClass=*)", Attributes: []string{"cn"}})
	if err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return err
	}
	if len(children) > 0 {
		return topologyBad("site contains domain controllers or servers")
	}
	top, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: &scope, Filter: "(objectClass=*)", Attributes: []string{"cn"}})
	if err != nil {
		return err
	}
	for _, child := range top {
		n := cnFromDN(child.DN)
		if !strings.EqualFold(n, "Servers") && !strings.EqualFold(n, "NTDS Site Settings") {
			return topologyBad("site contains unmanaged child objects")
		}
	}
	for _, child := range top {
		if err := s.ldap.Delete(ctx, child.DN); err != nil {
			return err
		}
	}
	if err := s.ldap.Delete(ctx, dn); err != nil {
		s.audit.Failure(actor, "site.delete", dn, ip, err)
		return err
	}
	s.audit.Success(actor, "site.delete", dn, ip)
	return nil
}

// List returns subnets.
func (s *SubnetService) List(ctx context.Context) ([]Subnet, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		BaseDN:     SubnetsContainerDN(s.ldap.BaseDN()),
		Filter:     "(objectClass=subnet)",
		Attributes: []string{"cn", "name", "siteObject"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]Subnet, 0, len(entries))
	for _, e := range entries {
		name := e.GetAttributeValue("cn")
		if name == "" {
			name = e.GetAttributeValue("name")
		}
		out = append(out, Subnet{
			Name: name,
			DN:   e.DN,
			Site: e.GetAttributeValue("siteObject"),
		})
	}
	return out, nil
}

// Create adds a subnet linked to a site.
func (s *SubnetService) Create(ctx context.Context, subnet, site, actor, ip string) (*Subnet, error) {
	subnet = strings.TrimSpace(subnet)
	site = strings.TrimSpace(site)
	if subnet == "" || site == "" {
		return nil, fmt.Errorf("subnet and site are required")
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || prefix != prefix.Masked() {
		return nil, topologyBad("a valid CIDR network prefix is required")
	}
	dn := BuildDN("CN", subnet, SubnetsContainerDN(s.ldap.BaseDN()))
	siteDN := site
	if !strings.Contains(strings.ToUpper(site), "CN=") {
		siteDN = BuildDN("CN", site, SitesContainerDN(s.ldap.BaseDN()))
	}
	entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: siteDN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=site)", Attributes: []string{"cn"}})
	if err != nil {
		return nil, err
	}
	siteDN = entry.DN
	attrs := []ldap.Attribute{
		{Type: ldapproto.AttrObjectClass, Vals: []string{"top", "subnet"}},
		{Type: ldapproto.AttrCN, Vals: []string{subnet}},
		{Type: "siteObject", Vals: []string{siteDN}},
	}
	if err := s.ldap.Add(ctx, dn, attrs); err != nil {
		s.audit.Failure(actor, "subnet.create", dn, ip, err)
		return nil, err
	}
	s.audit.Success(actor, "subnet.create", dn, ip)
	return &Subnet{Name: subnet, DN: dn, Site: siteDN}, nil
}

// Delete removes a subnet by name (CIDR).
func (s *SubnetService) Delete(ctx context.Context, subnet, actor, ip string) error {
	dn := BuildDN("CN", subnet, SubnetsContainerDN(s.ldap.BaseDN()))
	if err := s.ldap.Delete(ctx, dn); err != nil {
		s.audit.Failure(actor, "subnet.delete", dn, ip, err)
		return err
	}
	s.audit.Success(actor, "subnet.delete", dn, ip)
	return nil
}
