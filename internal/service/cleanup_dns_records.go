package service

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"net"
	ldapproto "sambaadm/internal/ldap"
	"strings"
)

// AD dnsRecord has a 24-byte DNS_RPC_RECORD header, followed by typed data.
// Counted names are not compressed DNS packet names: length, label count,
// counted labels and a terminating zero. Reject malformed supported types.
func cleanupDNSName(data []byte) (string, error) {
	if len(data) < 3 || int(data[0])+2 != len(data) {
		return "", fmt.Errorf("invalid counted DNS name")
	}
	labels := []string{}
	offset := 2
	for i := 0; i < int(data[1]); i++ {
		if offset >= len(data) {
			return "", fmt.Errorf("truncated DNS name")
		}
		n := int(data[offset])
		offset++
		if n == 0 || n > 63 || offset+n >= len(data) {
			return "", fmt.Errorf("invalid DNS label")
		}
		label := string(data[offset : offset+n])
		if strings.ContainsAny(label, ".\x00") {
			return "", fmt.Errorf("invalid DNS label")
		}
		labels = append(labels, label)
		offset += n
	}
	if offset != len(data)-1 || data[offset] != 0 {
		return "", fmt.Errorf("invalid DNS terminator")
	}
	return strings.ToLower(strings.Join(labels, ".")), nil
}
func cleanupDNSRecord(raw []byte) (uint16, string, error) {
	if len(raw) < 24 || int(binary.LittleEndian.Uint16(raw[:2])) != len(raw)-24 {
		return 0, "", fmt.Errorf("invalid AD DNS record")
	}
	typ := binary.LittleEndian.Uint16(raw[2:4])
	data := raw[24:]
	switch typ {
	case 1:
		if len(data) != 4 {
			return typ, "", fmt.Errorf("invalid A record")
		}
		return typ, net.IP(data).String(), nil
	case 28:
		if len(data) != 16 {
			return typ, "", fmt.Errorf("invalid AAAA record")
		}
		return typ, net.IP(data).String(), nil
	case 2, 5, 12:
		name, e := cleanupDNSName(data)
		return typ, name, e
	case 33:
		if len(data) < 6 {
			return typ, "", fmt.Errorf("invalid SRV record")
		}
		name, e := cleanupDNSName(data[6:])
		return typ, name, e
	case 6:
		if len(data) < 23 {
			return typ, "", fmt.Errorf("invalid SOA record")
		}
		end := 20 + int(data[20]) + 2
		if end > len(data) {
			return typ, "", fmt.Errorf("invalid SOA primary")
		}
		primary, e := cleanupDNSName(data[20:end])
		if e != nil {
			return typ, "", e
		}
		if _, e = cleanupDNSName(data[end:]); e != nil {
			return typ, "", e
		}
		return typ, primary, nil
	case 15:
		if len(data) < 2 {
			return typ, "", fmt.Errorf("invalid MX record")
		}
		name, e := cleanupDNSName(data[2:])
		return typ, name, e
	}
	return typ, "", nil
}
func cleanupDNSOwner(dn string) (string, error) {
	d, e := ldap.ParseDN(dn)
	if e != nil || len(d.RDNs) < 2 || len(d.RDNs[0].Attributes) != 1 || len(d.RDNs[1].Attributes) != 1 {
		return "", topologyBad("invalid DNS node DN")
	}
	node, zone := d.RDNs[0].Attributes[0].Value, d.RDNs[1].Attributes[0].Value
	if node == "@" {
		return strings.ToLower(zone), nil
	}
	return strings.ToLower(node + "." + zone), nil
}
func (s *SiteService) expandRetiredDNS(ctx context.Context, p *CleanupPlan) error {
	hosts := map[string]bool{}
	for _, o := range p.Objects {
		if cleanupDCRemnant(o) {
			if host := cleanupTargetHost(o); host != "" {
				hosts[host] = true
			}
		}
	}
	if len(hosts) == 0 {
		return nil
	}
	bases, e := (&DNSService{ldap: s.ldap}).dnsPartitions(ctx)
	if e != nil {
		return e
	}
	apexes := map[string]bool{}
	for _, base := range bases {
		dn, err := ldap.ParseDN(base)
		if err != nil {
			return err
		}
		labels := []string{}
		for _, rdn := range dn.RDNs {
			if len(rdn.Attributes) != 1 || !strings.EqualFold(rdn.Attributes[0].Type, "DC") {
				return topologyBad("unsupported DNS naming context")
			}
			labels = append(labels, rdn.Attributes[0].Value)
		}
		apexes[strings.ToLower(strings.Join(labels, "."))] = true
	}
	nodes := []*ldap.Entry{}
	for _, base := range bases {
		rows, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: base, Filter: "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))", Attributes: cleanupAttributes, MaxEntries: 10000})
		if e != nil {
			return e
		}
		nodes = append(nodes, rows...)
		if len(nodes) > 10000 {
			return topologyBad("DNS cleanup inventory exceeds 10000 nodes")
		}
	}
	addresses := map[string]bool{}
	for _, row := range nodes {
		owner, e := cleanupDNSOwner(row.DN)
		if e != nil {
			return e
		}
		if !hosts[owner] {
			continue
		}
		for _, raw := range row.GetRawAttributeValues("dnsRecord") {
			typ, data, e := cleanupDNSRecord(raw)
			if e != nil {
				return e
			}
			if typ == 1 || typ == 28 {
				addresses[data] = true
			}
		}
	}
	// An address reused by another host cannot be attributed to this DC.
	for _, row := range nodes {
		owner, err := cleanupDNSOwner(row.DN)
		if err != nil {
			return err
		}
		if hosts[owner] || apexes[owner] {
			continue
		}
		for _, raw := range row.GetRawAttributeValues("dnsRecord") {
			typ, data, err := cleanupDNSRecord(raw)
			if err != nil {
				return err
			}
			if (typ == 1 || typ == 28) && addresses[data] {
				return topologyBad("retired DC address is shared by another DNS hostname: " + owner)
			}
		}
	}
	for _, row := range nodes {
		owner, e := cleanupDNSOwner(row.DN)
		if e != nil {
			return e
		}
		object := cleanupObjectEntry(row, "retired_dns_records", owner)
		object.Remove = map[string][][]byte{}
		ns, remainingNS := 0, 0
		for _, raw := range row.GetRawAttributeValues("dnsRecord") {
			typ, data, e := cleanupDNSRecord(raw)
			if e != nil {
				return e
			}
			remove := false
			switch typ {
			case 1, 28:
				remove = hosts[owner] || (apexes[owner] && addresses[data])
			case 6:
				if hosts[data] {
					return topologyBad("SOA primary still names retired DC at " + owner + "; move zone authority first")
				}
			case 2, 5, 12, 15, 33:
				remove = hosts[data]
			default:
				remove = hosts[owner] && typ != 0
			}
			if typ == 2 {
				ns++
				if !remove {
					remainingNS++
				}
			}
			if remove {
				object.Remove["dnsRecord"] = append(object.Remove["dnsRecord"], raw)
			}
		}
		if ns > 0 && remainingNS == 0 {
			return topologyBad("cleanup would remove the last NS record at " + owner)
		}
		if len(object.Remove["dnsRecord"]) > 0 {
			if len(p.Objects) >= 150 {
				return topologyBad("expanded DNS cleanup exceeds 150 objects")
			}
			p.Objects = append(p.Objects, object)
		}
	}
	return nil
}
