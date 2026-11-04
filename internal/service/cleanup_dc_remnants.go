package service

import (
	"context"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

func cleanupFinding(o CleanupObject, code string) bool {
	for _, f := range o.Findings {
		if f.Code == code && dnKey(f.DN) == dnKey(o.DN) {
			return true
		}
	}
	return false
}
func cleanupDCRemnant(o CleanupObject) bool {
	return cleanupClass(o, "server") || cleanupClass(o, "computer")
}
func cleanupDisabledDC(o CleanupObject) bool {
	values := o.Attributes["userAccountControl"]
	if len(values) != 1 {
		return false
	}
	flags, e := strconv.ParseUint(string(values[0]), 10, 32)
	return e == nil && flags&2 != 0 && flags&(8192|67108864) != 0
}
func cleanupRemnantAllowed(o CleanupObject, base string) bool {
	dn, e := ldap.ParseDN(o.DN)
	if e != nil {
		return false
	}
	if cleanupClass(o, "server") && (cleanupFinding(o, "server_without_ntds") || cleanupFinding(o, "disabled_dc_metadata") || cleanupFinding(o, "server_computer_reference") || cleanupFinding(o, "server_without_computer")) {
		parent, e := parentDN(o.DN)
		if e != nil || !strings.EqualFold(cnFromDN(parent), "Servers") {
			return false
		}
		sites, _ := ldap.ParseDN(SitesContainerDN(base))
		return sites.AncestorOfFold(dn)
	}
	if cleanupClass(o, "computer") && cleanupDisabledDC(o) && (cleanupFinding(o, "dc_computer_without_server") || cleanupFinding(o, "retired_server_computer")) {
		domain, e := ldap.ParseDN(base)
		if e != nil {
			return false
		}
		config, _ := ldap.ParseDN(ConfigDN(base))
		return domain.AncestorOfFold(dn) && !config.AncestorOfFold(dn)
	}
	return false
}

// A nonresponding DC is never evidence of retirement. These checks require
// absent DSA metadata and disabled trust accounts on every observed replica.
func (s *SiteService) checkDCRemnants(ctx context.Context, p *CleanupPlan) error {
	controllers, e := s.Controllers(ctx)
	if e != nil {
		return e
	}
	selected := map[string]bool{}
	for _, o := range p.Objects {
		selected[dnKey(o.DN)] = true
	}
	for _, o := range p.Objects {
		if !cleanupDCRemnant(o) {
			continue
		}
		if !cleanupRemnantAllowed(o, p.BaseDN) {
			return topologyBad("DC remnant requires absent NTDS metadata and a disabled DC account")
		}
		for _, dc := range controllers {
			if cleanupRetiredController(p, dc) {
				continue
			}
			for _, value := range o.Attributes["dNSHostName"] {
				if string(value) != "" && strings.EqualFold(string(value), dc.DNS) {
					return topologyBad("remnant hostname belongs to a registered DC")
				}
			}
			if dnKey(o.DN) == dnKey(dc.DN) || dnKey(o.DN) == dnKey(dc.Computer) {
				return topologyBad("registered DC metadata cannot be cleaned")
			}
		}
		// Do not silently remove descendants (NTDS, RID, DFSR or unknown objects).
		scope := ldap.ScopeSingleLevel
		children, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: o.DN, Scope: &scope, Filter: "(objectClass=*)", Attributes: []string{"objectClass"}, MaxEntries: 151})
		if err != nil {
			return err
		}
		for _, child := range children {
			if !cleanupHasDN(p, child.DN) {
				return topologyBad("unplanned DC descendant: " + child.DN)
			}
		}
		if cleanupClass(o, "computer") {
			refs, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: SitesContainerDN(p.BaseDN), Filter: "(&(objectClass=server)(serverReference=" + ldap.EscapeFilter(o.DN) + "))", Attributes: []string{"objectGUID"}, MaxEntries: 1000})
			if err != nil {
				return err
			}
			for _, ref := range refs {
				if !selected[dnKey(ref.DN)] {
					return topologyBad("computer is referenced by an unselected server")
				}
			}
		}
	}
	return nil
}
