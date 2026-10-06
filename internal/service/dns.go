package service

import (
	"context"
	"fmt"
	"strings"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/samba"
)

// DNSZone is a DNS zone.
type DNSZone struct {
	Name   string `json:"name"`
	DN     string `json:"dn,omitempty"`
	Source string `json:"source,omitempty"` // ldap | samba-tool
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

// DNSService manages AD-integrated DNS via samba-tool (+ LDAP list fallback).
type DNSService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
	tool  *samba.Runner
}

// ListZones returns DNS zones (samba-tool preferred, LDAP fallback).
func (s *DNSService) ListZones(ctx context.Context) ([]DNSZone, error) {
	if s.tool != nil && s.tool.Available() {
		server := s.dnsServer()
		res, err := s.tool.Run(ctx, "dns", "zonelist", server)
		if err == nil {
			return parseDNSZoneList(res.Stdout), nil
		}
	}
	return s.listZonesLDAP(ctx)
}

// CreateZone creates a DNS zone via samba-tool.
func (s *DNSService) CreateZone(ctx context.Context, zone, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	zone = strings.TrimSpace(zone)
	if zone == "" {
		return fmt.Errorf("zone is required")
	}
	if _, err := s.tool.Run(ctx, "dns", "zonecreate", s.dnsServer(), zone); err != nil {
		s.audit.Failure(actor, "dns.zone.create", zone, ip, err)
		return err
	}
	s.audit.Success(actor, "dns.zone.create", zone, ip)
	return nil
}

// DeleteZone deletes a DNS zone via samba-tool.
func (s *DNSService) DeleteZone(ctx context.Context, zone, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	if _, err := s.tool.Run(ctx, "dns", "zonedelete", s.dnsServer(), zone); err != nil {
		s.audit.Failure(actor, "dns.zone.delete", zone, ip, err)
		return err
	}
	s.audit.Success(actor, "dns.zone.delete", zone, ip)
	return nil
}

// QueryRecords queries records in a zone (samba-tool dns query).
func (s *DNSService) QueryRecords(ctx context.Context, zone, name, typ string) ([]DNSRecord, error) {
	if err := s.requireTool(); err != nil {
		return nil, err
	}
	if name == "" {
		name = "@"
	}
	if typ == "" {
		typ = "ALL"
	}
	res, err := s.tool.Run(ctx, "dns", "query", s.dnsServer(), zone, name, typ)
	if err != nil {
		return nil, err
	}
	return parseDNSQuery(res.Stdout, name, typ), nil
}

// AddRecord adds a DNS record.
func (s *DNSService) AddRecord(ctx context.Context, in AddDNSRecordInput, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	if err := validateDNSRecord(in.Zone, in.Name, in.Type, in.Data); err != nil {
		return err
	}
	target := fmt.Sprintf("%s/%s %s %s", in.Zone, in.Name, in.Type, in.Data)
	args := append([]string{"dns", "add", s.dnsServer(), in.Zone, in.Name, strings.ToUpper(in.Type)},
		splitDNSData(in.Data)...)
	if _, err := s.tool.Run(ctx, args...); err != nil {
		s.audit.Failure(actor, "dns.record.add", target, ip, err)
		return err
	}
	s.audit.Success(actor, "dns.record.add", target, ip)
	return nil
}

// UpdateRecord updates a DNS record.
func (s *DNSService) UpdateRecord(ctx context.Context, in UpdateDNSRecordInput, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	if err := validateDNSRecord(in.Zone, in.Name, in.Type, in.NewData); err != nil {
		return err
	}
	if in.OldData == "" {
		return fmt.Errorf("oldData is required")
	}
	target := fmt.Sprintf("%s/%s %s", in.Zone, in.Name, in.Type)
	args := []string{"dns", "update", s.dnsServer(), in.Zone, in.Name, strings.ToUpper(in.Type)}
	args = append(args, splitDNSData(in.OldData)...)
	args = append(args, splitDNSData(in.NewData)...)
	if _, err := s.tool.Run(ctx, args...); err != nil {
		s.audit.Failure(actor, "dns.record.update", target, ip, err)
		return err
	}
	s.audit.Success(actor, "dns.record.update", target, ip)
	return nil
}

// DeleteRecord deletes a DNS record.
func (s *DNSService) DeleteRecord(ctx context.Context, in AddDNSRecordInput, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	if err := validateDNSRecord(in.Zone, in.Name, in.Type, in.Data); err != nil {
		return err
	}
	target := fmt.Sprintf("%s/%s %s %s", in.Zone, in.Name, in.Type, in.Data)
	args := append([]string{"dns", "delete", s.dnsServer(), in.Zone, in.Name, strings.ToUpper(in.Type)},
		splitDNSData(in.Data)...)
	if _, err := s.tool.Run(ctx, args...); err != nil {
		s.audit.Failure(actor, "dns.record.delete", target, ip, err)
		return err
	}
	s.audit.Success(actor, "dns.record.delete", target, ip)
	return nil
}

func (s *DNSService) listZonesLDAP(ctx context.Context) ([]DNSZone, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		Filter:     "(objectClass=dnsZone)",
		Attributes: []string{"name", "dc"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]DNSZone, 0, len(entries))
	for _, e := range entries {
		name := e.GetAttributeValue("name")
		if name == "" {
			name = e.GetAttributeValue("dc")
		}
		out = append(out, DNSZone{Name: name, DN: e.DN, Source: "ldap"})
	}
	return out, nil
}

func (s *DNSService) dnsServer() string {
	if host := hostnameFromURI(s.ldap.URI()); host != "" {
		return host
	}
	return "localhost"
}

func (s *DNSService) requireTool() error {
	if s.tool == nil || !s.tool.Available() {
		return fmt.Errorf("samba-tool is not available on this host")
	}
	return nil
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

// splitDNSData splits record data for samba-tool (SRV needs multiple args).
func splitDNSData(data string) []string {
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return []string{data}
	}
	return fields
}

func parseDNSZoneList(stdout string) []DNSZone {
	var out []DNSZone
	for _, line := range strings.Split(stdout, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		// Common: "pszZoneName                 : example.com"
		if i := strings.Index(trimmed, ":"); i >= 0 && (strings.Contains(lower, "zonename") || strings.Contains(lower, "psz")) {
			name := strings.TrimSpace(trimmed[i+1:])
			if name != "" {
				out = append(out, DNSZone{Name: name, Source: "samba-tool"})
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	// Fallback: simple one-zone-per-line output
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasSuffix(line, ":") {
			continue
		}
		if strings.Contains(line, " ") && !strings.Contains(line, ".") {
			continue
		}
		out = append(out, DNSZone{Name: line, Source: "samba-tool"})
	}
	return out
}

func parseDNSQuery(stdout, name, typ string) []DNSRecord {
	var out []DNSRecord
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, DNSRecord{Name: name, Type: typ, Raw: line, Data: line})
	}
	if len(out) == 0 && strings.TrimSpace(stdout) != "" {
		out = append(out, DNSRecord{Name: name, Type: typ, Raw: stdout, Data: stdout})
	}
	return out
}
