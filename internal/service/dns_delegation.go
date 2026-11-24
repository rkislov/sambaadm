package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	ldapproto "sambaadm/internal/ldap"
)

type DNSNameServer struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}
type DNSDelegation struct {
	Domain  string          `json:"domain"`
	Child   string          `json:"child"`
	Servers []DNSNameServer `json:"servers"`
}
type DNSDelegationState struct {
	Zone        string          `json:"zone"`
	Revision    string          `json:"revision"`
	Delegations []DNSDelegation `json:"delegations"`
}
type DNSDelegationInput struct {
	Zone             string          `json:"zone"`
	Child            string          `json:"child"`
	Servers          []DNSNameServer `json:"servers"`
	Remove           bool            `json:"remove"`
	Revision         string          `json:"revision"`
	ProposedRevision string          `json:"proposedRevision"`
	Confirm          bool            `json:"confirm"`
}
type DNSRecordChange struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Data   string `json:"data"`
	Remove bool   `json:"remove"`
}
type DNSDelegationPlan struct {
	Revision         string            `json:"revision"`
	ProposedRevision string            `json:"proposedRevision"`
	Domain           string            `json:"domain"`
	Changes          []DNSRecordChange `json:"changes"`
	Warning          string            `json:"warning"`
}
type delegationRecord struct{ Name, Type, Data string }

func normalizeDelegation(in DNSDelegationInput) (DNSDelegationInput, error) {
	var e error
	in.Zone, e = dnsHostName(in.Zone)
	if e != nil {
		return in, e
	}
	in.Child = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(in.Child)), ".")
	in.Child = strings.TrimSuffix(in.Child, "."+in.Zone)
	in.Child, e = dnsHostName(in.Child)
	if e != nil {
		return in, e
	}
	if in.Child == in.Zone {
		return in, fmt.Errorf("нельзя делегировать корень выбранной зоны")
	}
	if in.Remove {
		in.Servers = nil
		return in, nil
	}
	if len(in.Servers) < 1 || len(in.Servers) > 8 {
		return in, fmt.Errorf("укажите от 1 до 8 DNS-серверов")
	}
	seen := map[string]bool{}
	domain := in.Child + "." + in.Zone
	for i, server := range in.Servers {
		name, e := dnsHostName(server.Name)
		if e != nil {
			return in, e
		}
		if seen[name] {
			return in, fmt.Errorf("DNS-сервер указан повторно")
		}
		seen[name] = true
		addresses := []string{}
		ips := map[string]bool{}
		if len(server.Addresses) > 8 {
			return in, fmt.Errorf("не более 8 адресов одного DNS-сервера")
		}
		for _, v := range server.Addresses {
			ip, e := netip.ParseAddr(strings.TrimSpace(v))
			if e != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Zone() != "" {
				return in, fmt.Errorf("недопустимый IP-адрес glue-записи")
			}
			v = ip.Unmap().String()
			if !ips[v] {
				addresses = append(addresses, v)
				ips[v] = true
			}
		}
		inside := name == domain || strings.HasSuffix(name, "."+domain)
		if inside && len(addresses) == 0 {
			return in, fmt.Errorf("для DNS-сервера %s внутри поддомена нужны IP-адреса (glue)", name)
		}
		if !inside && len(addresses) > 0 {
			return in, fmt.Errorf("адресные записи внешнего DNS-сервера %s изменяйте в его собственной зоне", name)
		}
		sort.Strings(addresses)
		in.Servers[i] = DNSNameServer{Name: name, Addresses: addresses}
	}
	sort.Slice(in.Servers, func(i, j int) bool { return in.Servers[i].Name < in.Servers[j].Name })
	return in, nil
}
func (s *DNSService) delegationRecords(ctx context.Context, zone string) ([]delegationRecord, []DNSZone, error) {
	zones, e := s.ListZones(ctx)
	if e != nil {
		return nil, nil, e
	}
	var dn string
	for _, z := range zones {
		if strings.EqualFold(z.Name, zone) {
			dn = z.DN
			break
		}
	}
	if dn == "" {
		return nil, nil, fmt.Errorf("родительская зона не найдена")
	}
	entries, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: dn, Filter: "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))", Attributes: []string{"name", "dnsRecord"}, MaxEntries: 10000})
	if e != nil {
		return nil, nil, e
	}
	records := []delegationRecord{}
	for _, entry := range entries {
		name := strings.ToLower(entry.GetAttributeValue("name"))
		for _, raw := range entry.GetRawAttributeValues("dnsRecord") {
			typ, data, e := cleanupDNSRecord(raw)
			if e != nil {
				return nil, nil, e
			}
			t := fmt.Sprint(typ)
			switch typ {
			case 1:
				t = "A"
			case 28:
				t = "AAAA"
			case 2:
				t = "NS"
			case 5:
				t = "CNAME"
			}
			records = append(records, delegationRecord{name, t, data})
		}
	}
	sort.Slice(records, func(i, j int) bool {
		a, _ := json.Marshal(records[i])
		b, _ := json.Marshal(records[j])
		return string(a) < string(b)
	})
	return records, zones, nil
}
func delegationRevision(records []delegationRecord, zones []DNSZone) string {
	raw, _ := json.Marshal(struct {
		Records []delegationRecord
		Zones   []DNSZone
	}{records, zones})
	return configRevision(raw)
}
func (s *DNSService) Delegations(ctx context.Context, zone string) (*DNSDelegationState, error) {
	zone, e := dnsHostName(zone)
	if e != nil {
		return nil, e
	}
	records, zones, e := s.delegationRecords(ctx, zone)
	if e != nil {
		return nil, e
	}
	out := &DNSDelegationState{Zone: zone, Revision: delegationRevision(records, zones), Delegations: []DNSDelegation{}}
	by := map[string][]DNSNameServer{}
	for _, r := range records {
		if r.Type != "NS" || r.Name == "@" {
			continue
		}
		server := DNSNameServer{Name: r.Data, Addresses: []string{}}
		for _, glue := range records {
			if (r.Data == r.Name+"."+zone || strings.HasSuffix(r.Data, "."+r.Name+"."+zone)) && (glue.Type == "A" || glue.Type == "AAAA") && glue.Name+"."+zone == r.Data {
				server.Addresses = append(server.Addresses, glue.Data)
			}
		}
		by[r.Name] = append(by[r.Name], server)
	}
	for child, servers := range by {
		out.Delegations = append(out.Delegations, DNSDelegation{Domain: child + "." + zone, Child: child, Servers: servers})
	}
	sort.Slice(out.Delegations, func(i, j int) bool { return out.Delegations[i].Domain < out.Delegations[j].Domain })
	return out, nil
}
func delegationPlan(in DNSDelegationInput, records []delegationRecord, zones []DNSZone) (*DNSDelegationPlan, error) {
	in, e := normalizeDelegation(in)
	if e != nil {
		return nil, e
	}
	domain := in.Child + "." + in.Zone
	for _, zone := range zones {
		if strings.EqualFold(zone.Name, domain) {
			return nil, fmt.Errorf("%s уже обслуживается как отдельная AD-зона; сначала разрешите конфликт", domain)
		}
	}
	for _, r := range records {
		if r.Type == "NS" && r.Name != "@" && strings.HasSuffix(in.Child, "."+r.Name) {
			return nil, fmt.Errorf("родитель %s уже делегирован; настройте поддомен на его DNS-сервере", r.Name)
		}
		if r.Name == in.Child && r.Type != "NS" && r.Type != "A" && r.Type != "AAAA" {
			return nil, fmt.Errorf("в имени %s уже есть несовместимые записи", domain)
		}
	}
	desired := map[string]bool{}
	changes := []DNSRecordChange{}
	has := func(name, typ, data string) bool {
		for _, r := range records {
			if r.Name == name && r.Type == typ && strings.EqualFold(strings.TrimSuffix(r.Data, "."), strings.TrimSuffix(data, ".")) {
				return true
			}
		}
		return false
	}
	for _, server := range in.Servers {
		desired[server.Name] = true
		for _, ip := range server.Addresses {
			name := strings.TrimSuffix(server.Name, "."+in.Zone)
			for _, r := range records {
				if r.Name == name && r.Type == "CNAME" {
					return nil, fmt.Errorf("glue-имя %s уже занято CNAME", server.Name)
				}
			}
			typ := "A"
			if strings.Contains(ip, ":") {
				typ = "AAAA"
			}
			if !has(name, typ, ip) {
				changes = append(changes, DNSRecordChange{Name: name, Type: typ, Data: ip})
			}
		}
		if !has(in.Child, "NS", server.Name) {
			changes = append(changes, DNSRecordChange{Name: in.Child, Type: "NS", Data: server.Name})
		}
	}
	for _, r := range records {
		if r.Name == in.Child && r.Type == "NS" && !desired[strings.TrimSuffix(r.Data, ".")] {
			changes = append(changes, DNSRecordChange{Name: in.Child, Type: "NS", Data: r.Data, Remove: true})
		}
	}
	raw, _ := json.Marshal(struct {
		Input   DNSDelegationInput
		Changes []DNSRecordChange
	}{DNSDelegationInput{Zone: in.Zone, Child: in.Child, Servers: in.Servers, Remove: in.Remove}, changes})
	return &DNSDelegationPlan{Revision: delegationRevision(records, zones), ProposedRevision: configRevision(raw), Domain: domain, Changes: changes, Warning: "NS и glue хранятся в AD и реплицируются вместе с зоной. Существующие адресные записи сохраняются; удаление делегирования убирает только NS. Поддомен и его записи должны существовать на целевом DNS-сервере."}, nil
}
func (s *DNSService) PlanDelegation(ctx context.Context, in DNSDelegationInput) (*DNSDelegationPlan, error) {
	in, e := normalizeDelegation(in)
	if e != nil {
		return nil, e
	}
	records, zones, e := s.delegationRecords(ctx, in.Zone)
	if e != nil {
		return nil, e
	}
	return delegationPlan(in, records, zones)
}
func (s *DNSService) ApplyDelegation(ctx context.Context, in DNSDelegationInput, actor, ip string) (out *DNSDelegationState, err error) {
	s.delegationMu.Lock()
	defer s.delegationMu.Unlock()
	defer func() {
		if s.audit != nil {
			if err != nil {
				s.audit.Failure(actor, "dns.delegation", in.Zone+"/"+in.Child, ip, err)
			} else {
				s.audit.Success(actor, "dns.delegation", in.Zone+"/"+in.Child, ip)
			}
		}
	}()
	if !in.Confirm {
		return nil, fmt.Errorf("подтвердите изменение делегирования")
	}
	in, err = normalizeDelegation(in)
	if err != nil {
		return nil, err
	}
	p, e := s.PlanDelegation(ctx, in)
	if e != nil {
		return nil, e
	}
	if in.Revision == "" || in.Revision != p.Revision || in.ProposedRevision != p.ProposedRevision {
		return nil, ErrTopologyConflict
	}
	// DNS RPC updates are individual operations. Stop on failure and report exactly
	// what was completed; never claim an atomic transaction or delete shared glue.
	completed := 0
	for _, c := range p.Changes {
		old, newData := "", c.Data
		if c.Remove {
			old, newData = c.Data, ""
		}
		if e = s.remote.DNSUpdate(ctx, in.Zone, c.Name, c.Type, old, newData); e != nil {
			return nil, fmt.Errorf("изменений выполнено %d из %d; обновите список и повторите предпросмотр: %w", completed, len(p.Changes), e)
		}
		completed++
	}
	return s.Delegations(ctx, in.Zone)
}
