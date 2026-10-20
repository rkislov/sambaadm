package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/adremote"
	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// DNSZone is a DNS zone.
type DNSZone struct {
	Name   string `json:"name"`
	DN     string `json:"dn,omitempty"`
	Source string `json:"source,omitempty"` // ldap
}

// DNSRecord is a DNS resource record summary.
type DNSRecord struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Raw  string `json:"raw,omitempty"`
}

// AddDNSRecordInput creates/updates a record.
type AddDNSRecordInput struct {
	Zone string `json:"zone"`
	Name string `json:"name"`
	Type string `json:"type"` // A, AAAA, CNAME, SRV, PTR, TXT, MX, NS, ...
	Data string `json:"data"`
}

// UpdateDNSRecordInput replaces record data.
type UpdateDNSRecordInput struct {
	Zone    string `json:"zone"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	OldData string `json:"oldData"`
	NewData string `json:"newData"`
}

// DNSService manages AD-integrated DNS over native DNS RPC and LDAP.
type DNSService struct {
	ldap   *ldapproto.Client
	audit  *audit.Logger
	remote *adremote.Client
}

// ListZones returns DNS zones through LDAP.
func (s *DNSService) ListZones(ctx context.Context) ([]DNSZone, error) {

	return s.listZonesLDAP(ctx)
}

// CreateZone creates a DNS zone through native protocols.
func (s *DNSService) CreateZone(ctx context.Context, zone, actor, ip string) error {

	zone = strings.TrimSpace(zone)
	if zone == "" {
		return fmt.Errorf("zone is required")
	}
	if err := s.remote.DNSZone(ctx, zone, false); err != nil {
		s.audit.Failure(actor, "dns.zone.create", zone, ip, err)
		return err
	}
	s.audit.Success(actor, "dns.zone.create", zone, ip)
	return nil
}

// DeleteZone deletes a DNS zone through native protocols.
func (s *DNSService) DeleteZone(ctx context.Context, zone, actor, ip string) error {

	if err := s.remote.DNSZone(ctx, zone, true); err != nil {
		s.audit.Failure(actor, "dns.zone.delete", zone, ip, err)
		return err
	}
	s.audit.Success(actor, "dns.zone.delete", zone, ip)
	return nil
}

// QueryRecords queries records in a zone through native DNS RPC.
func (s *DNSService) QueryRecords(ctx context.Context, zone, name, typ string) ([]DNSRecord, error) {

	if name == "" {
		name = "@"
	}
	if typ == "" {
		typ = "ALL"
	}
	records, err := s.remote.DNSQuery(ctx, zone, name, typ)
	if err != nil {
		return nil, err
	}
	out := make([]DNSRecord, 0, len(records))
	for _, r := range records {
		out = append(out, DNSRecord{Name: r.Name, Type: r.Type, Data: r.Data, Raw: r.Raw})
	}
	return out, nil
}

// AddRecord adds a DNS record.
func (s *DNSService) AddRecord(ctx context.Context, in AddDNSRecordInput, actor, ip string) error {

	if err := validateDNSRecord(in.Zone, in.Name, in.Type, in.Data); err != nil {
		return err
	}
	target := fmt.Sprintf("%s/%s %s %s", in.Zone, in.Name, in.Type, in.Data)
	if err := s.remote.DNSUpdate(ctx, in.Zone, in.Name, in.Type, "", in.Data); err != nil {
		s.audit.Failure(actor, "dns.record.add", target, ip, err)
		return err
	}
	s.audit.Success(actor, "dns.record.add", target, ip)
	return nil
}

// UpdateRecord updates a DNS record.
func (s *DNSService) UpdateRecord(ctx context.Context, in UpdateDNSRecordInput, actor, ip string) error {

	if err := validateDNSRecord(in.Zone, in.Name, in.Type, in.NewData); err != nil {
		return err
	}
	if in.OldData == "" {
		return fmt.Errorf("oldData is required")
	}
	target := fmt.Sprintf("%s/%s %s", in.Zone, in.Name, in.Type)
	if err := s.remote.DNSUpdate(ctx, in.Zone, in.Name, in.Type, in.OldData, in.NewData); err != nil {
		s.audit.Failure(actor, "dns.record.update", target, ip, err)
		return err
	}
	s.audit.Success(actor, "dns.record.update", target, ip)
	return nil
}

// DeleteRecord deletes a DNS record.
func (s *DNSService) DeleteRecord(ctx context.Context, in AddDNSRecordInput, actor, ip string) error {

	if err := validateDNSRecord(in.Zone, in.Name, in.Type, in.Data); err != nil {
		return err
	}
	target := fmt.Sprintf("%s/%s %s %s", in.Zone, in.Name, in.Type, in.Data)
	if err := s.remote.DNSUpdate(ctx, in.Zone, in.Name, in.Type, in.Data, ""); err != nil {
		s.audit.Failure(actor, "dns.record.delete", target, ip, err)
		return err
	}
	s.audit.Success(actor, "dns.record.delete", target, ip)
	return nil
}

// dnsPartitions discovers application partitions as AD-integrated zones are not
// descendants of the default naming context.
func (s *DNSService) dnsPartitions(ctx context.Context) ([]string, error) {
	conn, err := s.ldap.Conn(ctx)
	if err != nil {
		return nil, err
	}
	result, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"namingContexts"}, nil))
	if err != nil {
		return nil, err
	}
	bases := []string{s.ldap.BaseDN()}
	seen := map[string]bool{strings.ToLower(s.ldap.BaseDN()): true}
	for _, entry := range result.Entries {
		for _, base := range entry.GetAttributeValues("namingContexts") {
			key := strings.ToLower(base)
			if strings.Contains(key, "dnszones") && !seen[key] {
				bases = append(bases, base)
				seen[key] = true
			}
		}
	}
	return bases, nil
}
func (s *DNSService) listZonesLDAP(ctx context.Context) ([]DNSZone, error) {
	bases, err := s.dnsPartitions(ctx)
	if err != nil {
		return nil, err
	}
	out := []DNSZone{}
	seen := map[string]bool{}
	var failures []error
	for _, base := range bases {
		entries, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: base, Filter: "(objectClass=dnsZone)", Attributes: []string{"name", "dc"}})
		if e != nil {
			failures = append(failures, e)
			continue
		}
		for _, entry := range entries {
			name := entry.GetAttributeValue("name")
			if name == "" {
				name = entry.GetAttributeValue("dc")
			}
			key := strings.ToLower(name)
			if !seen[key] {
				out = append(out, DNSZone{Name: name, DN: entry.DN, Source: "ldap"})
				seen[key] = true
			}
		}
	}
	if len(out) == 0 && len(failures) > 0 {
		return nil, errors.Join(failures...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Nodes lists live names in one zone for lazy navigation in the DNS tree.
func (s *DNSService) Nodes(ctx context.Context, zone string) ([]string, error) {
	zones, err := s.listZonesLDAP(ctx)
	if err != nil {
		return nil, err
	}
	for _, z := range zones {
		if strings.EqualFold(z.Name, zone) {
			entries, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: z.DN, Filter: "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))", Attributes: []string{"name", "dc"}})
			if e != nil {
				return nil, e
			}
			names := []string{}
			for _, entry := range entries {
				name := entry.GetAttributeValue("name")
				if name == "" {
					name = entry.GetAttributeValue("dc")
				}
				if name != "" {
					names = append(names, name)
				}
			}
			sort.Strings(names)
			return names, nil
		}
	}
	return nil, fmt.Errorf("DNS zone %q was not found in readable LDAP partitions", zone)
}

func (s *DNSService) dnsServer() string {
	if host := hostnameFromURI(s.ldap.URI()); host != "" {
		return host
	}
	return "localhost"
}

func validateDNSRecord(zone, name, typ, data string) error {
	if strings.TrimSpace(zone) == "" {
		return fmt.Errorf("zone is required")
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("name is required")
	}
	if strings.TrimSpace(typ) == "" {
		return fmt.Errorf("type is required")
	}
	if strings.TrimSpace(data) == "" {
		return fmt.Errorf("data is required")
	}
	return nil
}
