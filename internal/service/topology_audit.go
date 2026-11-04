package service

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

type TopologyFinding struct {
	Code      string `json:"code"`
	Severity  string `json:"severity"`
	DN        string `json:"dn"`
	Reference string `json:"reference,omitempty"`
	Detail    string `json:"detail"`
	Changed   string `json:"changed,omitempty"`
}
type TopologyAudit struct {
	LDAPServer string            `json:"ldapServer"`
	BaseDN     string            `json:"baseDN"`
	Started    time.Time         `json:"started"`
	Finished   time.Time         `json:"finished"`
	Status     string            `json:"status"`
	Objects    int               `json:"objects"`
	Findings   []TopologyFinding `json:"findings"`
	Warnings   []string          `json:"warnings"`
}

// Audit reads live configuration objects. No tombstone control, deletion or repair
// is used. Absence in this view is evidence to investigate, never proof of disuse.
func (s *SiteService) AuditTopology(ctx context.Context) *TopologyAudit {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	out := &TopologyAudit{LDAPServer: hostnameFromURI(s.ldap.URI()), BaseDN: s.ldap.BaseDN(), Started: time.Now().UTC(), Status: "complete", Findings: []TopologyFinding{}, Warnings: []string{
		"Snapshot of the configured LDAP server, not an atomic or forest-wide inventory. ACL visibility and replication lag can hide objects. Findings require confirmation on another DC before metadata cleanup.",
		"Empty sites and servers without NTDS Settings may be intentional. whenChanged is informational and does not prove inactivity. Offline controllers are not classified as deleted.",
	}}
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: SitesContainerDN(s.ldap.BaseDN()), Filter: "(|(objectClass=site)(objectClass=server)(objectClass=nTDSDSA)(objectClass=nTDSConnection)(objectClass=subnet)(objectClass=siteLink))", Attributes: []string{"objectClass", "serverReference", "fromServer", "siteObject", "siteList", "whenChanged", "dNSHostName"}, MaxEntries: 10000})
	if err != nil {
		out.Status = "partial"
		out.Warnings = append(out.Warnings, "Topology search failed or exceeded its limit; no absence conclusions were made.")
		out.Finished = time.Now().UTC()
		return out
	}
	// Include DC trust accounts left behind after server metadata removal. This
	// search is limited to the current domain; Configuration may span the forest.
	computers, computerErr := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: s.ldap.BaseDN(), Filter: "(&(objectClass=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))", Attributes: []string{"objectClass", "whenChanged"}, MaxEntries: 10000})
	if computerErr != nil {
		out.Status = "partial"
		out.Warnings = append(out.Warnings, "DC computer search failed or exceeded its limit; orphan computer checks are incomplete.")
	} else {
		entries = append(entries, computers...)
	}
	out.Objects = len(entries)
	refs := map[string]string{}
	for _, e := range entries {
		if !hasClass(e, "server") {
			continue
		}
		dn := e.GetAttributeValue("serverReference")
		if dn == "" {
			continue
		}
		key := dnKey(dn)
		if _, ok := refs[key]; ok {
			continue
		}
		if len(refs) >= 256 {
			refs[key] = "unknown"
			continue
		}
		found, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=computer)", Attributes: []string{"1.1"}, MaxEntries: 1})
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			refs[key] = "unknown"
		case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
			refs[key] = "missing"
		case err != nil:
			refs[key] = "unknown"
		case len(found) != 1:
			refs[key] = "unknown"
		default:
			refs[key] = "present"
		}
	}
	out.Findings = analyzeTopology(entries, refs)
	for _, f := range out.Findings {
		if f.Severity == "unknown" {
			out.Status = "partial"
		}
	}
	out.Finished = time.Now().UTC()
	return out
}
func hasClass(e *ldap.Entry, class string) bool {
	for _, c := range e.GetAttributeValues("objectClass") {
		if strings.EqualFold(c, class) {
			return true
		}
	}
	return false
}
func dnKey(dn string) string {
	d, e := ldap.ParseDN(dn)
	if e != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	return strings.ToLower(d.String())
}
func analyzeTopology(entries []*ldap.Entry, refs map[string]string) []TopologyFinding {
	out := []TopologyFinding{}
	byDN := map[string]*ldap.Entry{}
	children := map[string][]*ldap.Entry{}
	serverCounts := map[string]int{}
	referencedComputers := map[string]bool{}
	for _, e := range entries {
		byDN[dnKey(e.DN)] = e
		if hasClass(e, "server") {
			p, _ := parentDN(e.DN)
			site, _ := parentDN(p)
			serverCounts[dnKey(site)]++
			referencedComputers[dnKey(e.GetAttributeValue("serverReference"))] = true
		}
		p, err := parentDN(e.DN)
		if err == nil {
			children[dnKey(p)] = append(children[dnKey(p)], e)
		}
	}
	add := func(e *ldap.Entry, code, severity, ref, detail string) {
		out = append(out, TopologyFinding{code, severity, e.DN, ref, detail, e.GetAttributeValue("whenChanged")})
	}
	check := func(e *ldap.Entry, attr, class string) {
		values := e.GetAttributeValues(attr)
		if len(values) == 0 {
			add(e, "missing_"+attr, "review", "", "Required topology reference is absent or not visible")
			return
		}
		for _, dn := range values {
			target := byDN[dnKey(dn)]
			if target == nil || !hasClass(target, class) {
				add(e, "unresolved_"+attr, "review", dn, "Referenced object is absent from the visible topology or has an unexpected class")
			}
		}
	}
	for _, e := range entries {
		switch {
		case hasClass(e, "nTDSConnection"):
			check(e, "fromServer", "nTDSDSA")
			p, _ := parentDN(e.DN)
			if target := byDN[dnKey(p)]; target == nil || !hasClass(target, "nTDSDSA") {
				add(e, "connection_parent", "review", p, "Connection has no visible NTDS Settings parent")
			}
		case hasClass(e, "nTDSDSA"):
			p, _ := parentDN(e.DN)
			if target := byDN[dnKey(p)]; target == nil || !hasClass(target, "server") {
				add(e, "ntds_parent", "review", p, "NTDS Settings has no visible server parent")
			}
		case hasClass(e, "server"):
			ntds := false
			for _, c := range children[dnKey(e.DN)] {
				if hasClass(c, "nTDSDSA") {
					ntds = true
				}
			}
			if !ntds {
				add(e, "server_without_ntds", "review", "", "Server has no visible NTDS Settings; may be staged or leftover metadata")
			}
			ref := e.GetAttributeValue("serverReference")
			if ref == "" {
				add(e, "server_without_computer", "review", "", "Computer reference is absent or not visible")
			} else if refs[dnKey(ref)] != "present" {
				severity := "unknown"
				if refs[dnKey(ref)] == "missing" {
					severity = "review"
				}
				add(e, "server_computer_reference", severity, ref, "Referenced computer could not be confirmed; check existence, permissions and replication")
			}
		case hasClass(e, "computer"):
			if !referencedComputers[dnKey(e.DN)] {
				add(e, "dc_computer_without_server", "review", "", "DC trust account has no visible serverReference in Configuration; confirm demotion or incomplete provisioning")
			}
		case hasClass(e, "site"):
			if serverCounts[dnKey(e.DN)] == 0 {
				add(e, "site_without_servers", "review", "", "Site has no visible servers; may be a planned regional site")
			}
		case hasClass(e, "subnet"):
			check(e, "siteObject", "site")
		case hasClass(e, "siteLink"):
			check(e, "siteList", "site")
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DN == out[j].DN {
			return out[i].Code < out[j].Code
		}
		return out[i].DN < out[j].DN
	})
	return out
}
