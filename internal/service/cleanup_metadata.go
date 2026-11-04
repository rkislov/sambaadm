package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"net"
	ldapproto "sambaadm/internal/ldap"
	"strings"
	"time"
)

var cleanupLinkAttributes = []string{"msDS-NC-Replica-Locations", "msDS-NC-RO-Replica-Locations", "interSiteTopologyGenerator"}

func cleanupObjectEntry(e *ldap.Entry, code, ref string) CleanupObject {
	attrs := map[string][][]byte{}
	for _, key := range cleanupAttributes {
		if values := e.GetRawAttributeValues(key); len(values) > 0 {
			attrs[key] = values
		}
	}
	return CleanupObject{DN: e.DN, GUID: e.GetRawAttributeValue("objectGUID"), USN: e.GetAttributeValue("uSNChanged"), Attributes: attrs, Findings: []TopologyFinding{{DN: e.DN, Code: code, Reference: ref, Severity: "review"}}}
}
func cleanupHasDN(p *CleanupPlan, dn string) bool {
	for _, o := range p.Objects {
		if dnKey(o.DN) == dnKey(dn) && len(o.Remove) == 0 {
			return true
		}
	}
	return false
}
func cleanupRetiredController(p *CleanupPlan, dc Controller) bool {
	if !cleanupHasDN(p, dc.DN) || !cleanupHasDN(p, dc.NTDS) {
		return false
	}
	for _, o := range p.Objects {
		if dnKey(o.DN) == dnKey(dc.Computer) && cleanupDisabledDC(o) {
			return true
		}
	}
	for _, o := range p.Objects {
		if dnKey(o.DN) == dnKey(dc.DN) {
			if dc.Computer == "" && cleanupFinding(o, "server_without_computer") {
				return true
			}
			for _, f := range o.Findings {
				if f.Code == "server_computer_reference" && f.Severity == "review" && dnKey(f.Reference) == dnKey(dc.Computer) {
					return true
				}
			}
		}
	}
	return false
}
func cleanupDescendantAllowed(o CleanupObject, p *CleanupPlan) bool {
	if !cleanupFinding(o, "retired_dc_child") {
		return false
	}
	d, e := ldap.ParseDN(o.DN)
	if e != nil {
		return false
	}
	classes := []string{"nTDSDSA", "nTDSConnection", "rIDSet", "msDFSR-LocalSettings", "msDFSR-Subscriber", "msDFSR-Subscription"}
	allowed := false
	for _, class := range classes {
		allowed = allowed || cleanupClass(o, class)
	}
	if !allowed {
		return false
	}
	for _, root := range p.Objects {
		if !cleanupDCRemnant(root) || !cleanupRemnantAllowed(root, p.BaseDN) {
			continue
		}
		r, e := ldap.ParseDN(root.DN)
		if e == nil && r.AncestorOfFold(d) {
			return true
		}
	}
	return false
}
func cleanupExtraAllowed(o CleanupObject, p *CleanupPlan) bool {
	if cleanupDescendantAllowed(o, p) {
		return true
	}
	if cleanupFinding(o, "retired_dc_connection") && cleanupClass(o, "nTDSConnection") {
		for _, v := range o.Attributes["fromServer"] {
			if cleanupHasDN(p, string(v)) {
				return true
			}
		}
	}
	if cleanupFinding(o, "retired_dfsr_member") && cleanupClass(o, "msDFSR-Member") {
		for _, v := range o.Attributes["msDFSR-ComputerReference"] {
			if cleanupHasDN(p, string(v)) {
				return true
			}
		}
	}
	if cleanupFinding(o, "retired_dfsr_connection") && cleanupClass(o, "msDFSR-Connection") {
		parent, _ := parentDN(o.DN)
		if cleanupHasDN(p, parent) {
			return true
		}
		for _, value := range append(o.Attributes["fromServer"], o.Attributes["msDFSR-PartnerReference"]...) {
			if cleanupHasDN(p, string(value)) {
				return true
			}
		}
		return false
	}
	if len(o.Remove) > 0 {
		for attr, values := range o.Remove {
			if len(values) == 0 {
				return false
			}
			if attr == "dnsRecord" {
				if !cleanupClass(o, "dnsNode") || !cleanupFinding(o, "retired_dns_records") {
					return false
				}
				continue
			}
			valid := false
			for _, a := range cleanupLinkAttributes {
				valid = valid || attr == a
			}
			if !valid {
				return false
			}
			for _, v := range values {
				if !cleanupHasDN(p, string(v)) {
					return false
				}
			}
		}
		return true
	}
	return false
}
func (s *SiteService) expandRetiredMetadata(ctx context.Context, p *CleanupPlan) error {
	original := append([]CleanupObject(nil), p.Objects...)
	add := func(o CleanupObject) error {
		for _, existing := range p.Objects {
			if dnKey(existing.DN) == dnKey(o.DN) {
				return nil
			}
		}
		if len(p.Objects) >= 150 {
			return topologyBad("expanded cleanup exceeds 150 objects")
		}
		p.Objects = append(p.Objects, o)
		return nil
	}
	for _, root := range original {
		if !cleanupDCRemnant(root) {
			continue
		}
		rows, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: root.DN, Filter: "(objectClass=*)", Attributes: cleanupAttributes, MaxEntries: 151})
		if e != nil {
			return e
		}
		for _, row := range rows {
			if dnKey(row.DN) != dnKey(root.DN) {
				if e = add(cleanupObjectEntry(row, "retired_dc_child", root.DN)); e != nil {
					return e
				}
			}
		}
		if cleanupClass(root, "computer") {
			members, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: p.BaseDN, Filter: "(&(objectClass=msDFSR-Member)(msDFSR-ComputerReference=" + ldap.EscapeFilter(root.DN) + "))", Attributes: cleanupAttributes, MaxEntries: 151})
			if e != nil {
				return e
			}
			for _, member := range members {
				if e = add(cleanupObjectEntry(member, "retired_dfsr_member", root.DN)); e != nil {
					return e
				}
				inbound, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: p.BaseDN, Filter: "(&(objectClass=msDFSR-Connection)(fromServer=" + ldap.EscapeFilter(member.DN) + "))", Attributes: cleanupAttributes, MaxEntries: 151})
				if err != nil {
					return err
				}
				for _, row := range inbound {
					if err = add(cleanupObjectEntry(row, "retired_dfsr_connection", member.DN)); err != nil {
						return err
					}
				}
				children, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: member.DN, Filter: "(objectClass=*)", Attributes: cleanupAttributes, MaxEntries: 151})
				if e != nil {
					return e
				}
				for _, child := range children {
					if e = add(cleanupObjectEntry(child, "retired_dfsr_connection", member.DN)); e != nil {
						return e
					}
				}
			}
		}
	}
	targets := append([]CleanupObject(nil), p.Objects...)
	for _, o := range targets {
		if !cleanupClass(o, "nTDSDSA") {
			continue
		}
		connections, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: ConfigDN(p.BaseDN), Filter: "(&(objectClass=nTDSConnection)(fromServer=" + ldap.EscapeFilter(o.DN) + "))", Attributes: cleanupAttributes, MaxEntries: 151})
		if e != nil {
			return e
		}
		for _, row := range connections {
			if e = add(cleanupObjectEntry(row, "retired_dc_connection", o.DN)); e != nil {
				return e
			}
		}
		for _, attr := range cleanupLinkAttributes {
			entries, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: ConfigDN(p.BaseDN), Filter: "(" + attr + "=" + ldap.EscapeFilter(o.DN) + ")", Attributes: cleanupAttributes, MaxEntries: 151})
			if e != nil {
				return e
			}
			for _, row := range entries {
				if cleanupHasDN(p, row.DN) {
					continue
				}
				found := -1
				for i := range p.Objects {
					if dnKey(p.Objects[i].DN) == dnKey(row.DN) {
						found = i
					}
				}
				if found < 0 {
					if e = add(cleanupObjectEntry(row, "retired_replica_link", o.DN)); e != nil {
						return e
					}
					found = len(p.Objects) - 1
				}
				if p.Objects[found].Remove == nil {
					p.Objects[found].Remove = map[string][][]byte{}
				}
				for _, v := range row.GetRawAttributeValues(attr) {
					if dnKey(string(v)) == dnKey(o.DN) {
						p.Objects[found].Remove[attr] = append(p.Objects[found].Remove[attr], v)
					}
				}
			}
		}
	}
	return s.expandRetiredDNS(ctx, p)
}
func cleanupRemaining(o CleanupObject, attr string) [][]byte {
	values := [][]byte{}
	for _, v := range o.Attributes[attr] {
		remove := false
		for _, r := range o.Remove[attr] {
			remove = remove || bytes.Equal(v, r)
		}
		if !remove {
			values = append(values, v)
		}
	}
	return values
}
func cleanupModify(ctx context.Context, c *ldapproto.Client, o CleanupObject) error {
	if e := checkTopologyRevision(ctx, c, o.DN, o.USN); e != nil {
		return e
	}
	controls, e := assertion(o.USN)
	if e != nil {
		return e
	}
	req := ldap.NewModifyRequest(o.DN, controls)
	for attr, values := range o.Remove {
		raw := []string{}
		for _, v := range values {
			raw = append(raw, string(v))
		}
		req.Delete(attr, raw)
	}
	if len(o.Remove["dnsRecord"]) > 0 && len(cleanupRemaining(o, "dnsRecord")) == 0 {
		req.Replace("dNSTombstoned", []string{"TRUE"})
	}
	return topologyError(c.Modify(ctx, req))
}

func cleanupTargetHost(o CleanupObject) string {
	values := o.Attributes["dNSHostName"]
	if len(values) != 1 {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(string(values[0])), ".")
}

func verifyCleanupModification(ctx context.Context, c *ldapproto.Client, o CleanupObject) error {
	entry, e := c.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: o.DN, Scope: ldapproto.ScopeBase(), Attributes: cleanupAttributes})
	if e != nil {
		return e
	}
	if !bytes.Equal(entry.GetRawAttributeValue("objectGUID"), o.GUID) {
		return ErrTopologyConflict
	}
	for attr := range o.Remove {
		actual := entry.GetRawAttributeValues(attr)
		expected := cleanupRemaining(o, attr)
		if len(actual) != len(expected) {
			return topologyBad("post-cleanup attribute mismatch: " + o.DN + " " + attr)
		}
		for _, v := range expected {
			found := false
			for _, a := range actual {
				found = found || bytes.Equal(v, a)
			}
			if !found {
				return topologyBad("unrelated values changed during cleanup")
			}
		}
	}
	return nil
}

func cleanupPlannedReference(p *CleanupPlan, source, attr, target string) bool {
	for _, o := range p.Objects {
		if dnKey(o.DN) != dnKey(source) {
			continue
		}
		if len(o.Remove) == 0 {
			return true
		}
		for name, values := range o.Remove {
			if !strings.EqualFold(name, attr) {
				continue
			}
			for _, value := range values {
				if dnKey(string(value)) == dnKey(target) {
					return true
				}
			}
		}
	}
	return false
}
func cleanupReferenceNames(schema []*ldap.Entry) []string {
	names := []string{}
	for _, attribute := range schema {
		names = append(names, attribute.GetAttributeValue("lDAPDisplayName"))
	}
	return names
}

// A positive LDAP response always vetoes retirement. NXDOMAIN or unreachable ports
// never authorize deletion by themselves: disabled/missing account, all-replica
// agreement, non-FSMO ownership and explicit retirement confirmation are required.
func checkRetiredOffline(ctx context.Context, host string) error {
	return checkRetiredOfflineIPs(ctx, host, nil)
}
func checkRetiredOfflinePlan(ctx context.Context, host string, p *CleanupPlan) error {
	saved := []string{}
	for _, o := range p.Objects {
		if !cleanupClass(o, "dnsNode") {
			continue
		}
		owner, e := cleanupDNSOwner(o.DN)
		if e != nil {
			return e
		}
		if !strings.EqualFold(owner, host) {
			continue
		}
		for _, raw := range o.Attributes["dnsRecord"] {
			typ, address, e := cleanupDNSRecord(raw)
			if e != nil {
				return e
			}
			if typ == 1 || typ == 28 {
				saved = append(saved, address)
			}
		}
	}
	return checkRetiredOfflineIPs(ctx, host, saved)
}
func checkRetiredOfflineIPs(ctx context.Context, host string, saved []string) error {
	if host == "" {
		return topologyBad("retired controller hostname required")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, e := net.DefaultResolver.LookupHost(ctx, host)
	if e != nil {
		var dns *net.DNSError
		if !errors.As(e, &dns) || !dns.IsNotFound {
			return topologyBad("cannot establish retired controller reachability: " + e.Error())
		}
	}
	for _, ip := range saved {
		found := false
		for _, existing := range addresses {
			found = found || existing == ip
		}
		if !found {
			addresses = append(addresses, ip)
		}
	}
	if len(addresses) > 8 {
		return topologyBad("too many retired controller addresses")
	}
	for _, address := range addresses {
		for _, port := range []string{"389", "636"} {
			conn, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort(address, port))
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
				var wire net.Conn = conn
				if port == "636" {
					// Read-only liveness probe: no credentials or trusted data are exchanged.
					tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
					if tlsConn.HandshakeContext(ctx) != nil {
						conn.Close()
						continue
					}
					wire = tlsConn
				}
				client := ldap.NewConn(wire, port == "636")
				client.Start()
				client.SetTimeout(1500 * time.Millisecond)
				_, probeErr := client.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 1, false, "(objectClass=*)", []string{"dsServiceName"}, nil))
				client.Close()
				var response *ldap.Error
				if probeErr == nil || (errors.As(probeErr, &response) && response.ResultCode < 200) {
					return topologyBad("retired controller still responds to LDAP: " + host)
				}
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
	}
	return nil
}
func cleanupReplicationHealthy(st *ReplStatus, p *CleanupPlan) bool {
	healthy := false
	for _, n := range st.Neighbors {
		if cleanupHasDN(p, n.Partner) {
			continue
		}
		if n.Health != "healthy" {
			return false
		}
		healthy = true
	}
	return healthy
}

func (s *SiteService) revalidateRetiredNTDS(ctx context.Context, p *CleanupPlan, ntds CleanupObject) error {
	serverDN, e := parentDN(ntds.DN)
	if e != nil {
		return e
	}
	for _, server := range p.Objects {
		if dnKey(server.DN) != dnKey(serverDN) {
			continue
		}
		if e = checkTopologyRevision(ctx, s.ldap, server.DN, server.USN); e != nil {
			return e
		}
		for _, ref := range server.Attributes["serverReference"] {
			matched := false
			for _, account := range p.Objects {
				if dnKey(account.DN) == dnKey(string(ref)) {
					matched = true
					if !cleanupDisabledDC(account) {
						return topologyBad("retired account is not disabled")
					}
					if e = checkTopologyRevision(ctx, s.ldap, account.DN, account.USN); e != nil {
						return e
					}
				}
			}
			if !matched {
				_, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: string(ref), Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
				if !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
					return topologyBad("retired account absence could not be revalidated")
				}
			}
		}
		return checkRetiredOfflinePlan(ctx, cleanupTargetHost(server), p)
	}
	return topologyBad("NTDS has no selected retired server")
}

// Remove forward references before their targets so link deletion replicates.
func cleanupOperationRank(o CleanupObject) int {
	if len(o.Remove) > 0 {
		return 0
	}
	return 1
}
