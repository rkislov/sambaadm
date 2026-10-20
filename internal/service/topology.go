package service

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

var ErrTopologyInput = errors.New("invalid topology input")
var ErrTopologyConflict = errors.New("topology changed; reload before saving")

func topologyBad(s string) error { return fmt.Errorf("%w: %s", ErrTopologyInput, s) }
func siteLinkBase(base string) string {
	return "CN=IP,CN=Inter-Site Transports," + SitesContainerDN(base)
}
func parentDN(dn string) (string, error) {
	p, e := ldap.ParseDN(dn)
	if e != nil || len(p.RDNs) < 2 {
		return "", topologyBad("invalid DN")
	}
	return (&ldap.DN{RDNs: p.RDNs[1:]}).String(), nil
}
func assertion(revision string) ([]ldap.Control, error) {
	if _, e := strconv.ParseUint(revision, 10, 64); e != nil {
		return nil, topologyBad("revision required")
	}
	f, _ := ldap.CompileFilter("(uSNChanged=" + revision + ")")
	return []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(f.Bytes()))}, nil
}
func topologyError(e error) error {
	if ldap.IsErrorWithCode(e, 122) {
		return ErrTopologyConflict
	}
	return e
}

// Check before the mutation as well: Samba may short-circuit a no-op modify
// before evaluating the assertion. Keep the server assertion for actual writes.
func checkTopologyRevision(ctx context.Context, c *ldapproto.Client, dn, revision string) error {
	if _, e := assertion(revision); e != nil {
		return e
	}
	entry, e := c.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"uSNChanged"}})
	if e != nil {
		return e
	}
	if entry.GetAttributeValue("uSNChanged") != revision {
		return ErrTopologyConflict
	}
	return nil
}
func topologyModify(ctx context.Context, c *ldapproto.Client, dn, revision string, attrs map[string][]string) error {
	if e := checkTopologyRevision(ctx, c, dn, revision); e != nil {
		return e
	}
	ctrl, e := assertion(revision)
	if e != nil {
		return e
	}
	r := ldap.NewModifyRequest(dn, ctrl)
	for k, v := range attrs {
		r.Replace(k, v)
	}
	return topologyError(c.Modify(ctx, r))
}
func topologyDelete(ctx context.Context, c *ldapproto.Client, dn, revision string) error {
	if e := checkTopologyRevision(ctx, c, dn, revision); e != nil {
		return e
	}
	ctrl, e := assertion(revision)
	if e != nil {
		return e
	}
	conn, e := c.Conn(ctx)
	if e != nil {
		return e
	}
	return topologyError(conn.Del(ldap.NewDelRequest(dn, ctrl)))
}
func findTopology(ctx context.Context, c *ldapproto.Client, class, name string) (*ldap.Entry, error) {
	es, e := c.Search(ctx, ldapproto.SearchOptions{BaseDN: SitesContainerDN(c.BaseDN()), Filter: "(&(objectClass=" + class + ")(cn=" + ldap.EscapeFilter(name) + "))", Attributes: []string{"*"}})
	if e != nil {
		return nil, e
	}
	if len(es) != 1 {
		return nil, topologyBad("object missing or ambiguous: " + name)
	}
	return es[0], nil
}

// Schedule is Sunday first, UTC. Each day is a comma-separated list of
// HH:MM-HH:MM intervals aligned to 15 minutes; empty means unavailable.
func EncodeSchedule(days []string) ([]byte, error) {
	if len(days) != 7 {
		return nil, topologyBad("schedule requires seven UTC days, Sunday first")
	}
	b := make([]byte, 188)
	binary.LittleEndian.PutUint32(b, 188)
	binary.LittleEndian.PutUint32(b[8:], 1)
	binary.LittleEndian.PutUint32(b[16:], 20)
	clock := func(s string) (int, error) {
		var h, m int
		if len(s) != 5 || s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9' || s[3] < '0' || s[3] > '9' || s[4] < '0' || s[4] > '9' || s[2] != ':' {
			return 0, topologyBad("time must be HH:MM")
		}
		h, e := strconv.Atoi(s[:2])
		if e != nil {
			return 0, e
		}
		m, e = strconv.Atoi(s[3:])
		if e != nil || h < 0 || h > 24 || m < 0 || m > 59 || m%15 != 0 || (h == 24 && m != 0) {
			return 0, topologyBad("invalid quarter-hour time")
		}
		return h*4 + m/15, nil
	}
	for day, ranges := range days {
		if strings.TrimSpace(ranges) == "" {
			continue
		}
		for _, span := range strings.Split(ranges, ",") {
			a, z, ok := strings.Cut(strings.TrimSpace(span), "-")
			if !ok {
				return nil, topologyBad("invalid schedule range")
			}
			start, e := clock(a)
			if e != nil {
				return nil, topologyBad(e.Error())
			}
			end, e := clock(z)
			if e != nil || end <= start {
				return nil, topologyBad("invalid schedule interval")
			}
			for q := start; q < end; q++ {
				b[20+day*24+q/4] |= 1 << uint(q%4)
			}
		}
	}
	return b, nil
}
func DecodeSchedule(b []byte) ([]string, bool) {
	if len(b) == 0 {
		return []string{"00:00-24:00", "00:00-24:00", "00:00-24:00", "00:00-24:00", "00:00-24:00", "00:00-24:00", "00:00-24:00"}, true
	}
	if len(b) != 188 || binary.LittleEndian.Uint32(b) != 188 || binary.LittleEndian.Uint32(b[4:]) != 0 || binary.LittleEndian.Uint32(b[8:]) != 1 || binary.LittleEndian.Uint32(b[12:]) != 0 || binary.LittleEndian.Uint32(b[16:]) != 20 {
		return nil, false
	}
	for _, slot := range b[20:] {
		if slot&0xf0 != 0 {
			return nil, false
		}
	}
	out := make([]string, 7)
	clock := func(q int) string { return fmt.Sprintf("%02d:%02d", q/4, (q%4)*15) }
	for d := 0; d < 7; d++ {
		start := -1
		var spans []string
		for q := 0; q <= 96; q++ {
			on := q < 96 && b[20+d*24+q/4]&(1<<uint(q%4)) != 0
			if on && start < 0 {
				start = q
			}
			if !on && start >= 0 {
				spans = append(spans, clock(start)+"-"+clock(q))
				start = -1
			}
		}
		out[d] = strings.Join(spans, ",")
	}
	return out, true
}

type SiteLink struct {
	Name              string   `json:"name"`
	DN                string   `json:"dn"`
	Sites             []string `json:"sites"`
	Cost              int      `json:"cost"`
	Interval          int      `json:"interval"`
	Revision          string   `json:"revision"`
	Schedule          []string `json:"schedule"`
	ScheduleSupported bool     `json:"scheduleSupported"`
	ScheduleEditable  bool     `json:"scheduleEditable"`
	ScheduleWarning   string   `json:"scheduleWarning,omitempty"`
}
type SiteLinkInput struct {
	Name     string   `json:"name"`
	Sites    []string `json:"sites"`
	Cost     int      `json:"cost"`
	Interval int      `json:"interval"`
	Revision string   `json:"revision"`
	Schedule []string `json:"schedule,omitempty"`
}

func (s *SiteService) Links(ctx context.Context) ([]SiteLink, error) {
	es, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: siteLinkBase(s.ldap.BaseDN()), Filter: "(objectClass=siteLink)", Attributes: []string{"cn", "siteList", "cost", "replInterval", "schedule", "uSNChanged"}})
	if e != nil {
		return nil, e
	}
	out := []SiteLink{}
	for _, entry := range es {
		cost, _ := strconv.Atoi(entry.GetAttributeValue("cost"))
		interval, _ := strconv.Atoi(entry.GetAttributeValue("replInterval"))
		days, ok := DecodeSchedule(entry.GetRawAttributeValue("schedule"))
		sites := []string{}
		for _, dn := range entry.GetAttributeValues("siteList") {
			sites = append(sites, cnFromDN(dn))
		}
		out = append(out, SiteLink{entry.GetAttributeValue("cn"), entry.DN, sites, cost, interval, entry.GetAttributeValue("uSNChanged"), days, ok, false, siteLinkScheduleWarning})
	}
	return out, nil
}

const siteLinkScheduleWarning = "Site Link schedule editing is blocked: Samba KCC load_sitelink reads siteList as schedule (verified on 4.17). Use connection schedules; verify a vendor fix before enabling Site Link schedules."

func (s *SiteService) linkAttrs(ctx context.Context, in SiteLinkInput) (map[string][]string, error) {
	if in.Schedule != nil {
		return nil, topologyBad(siteLinkScheduleWarning)
	}
	if in.Cost < 1 || in.Cost > 32767 || in.Interval < 15 || in.Interval > 10080 || in.Interval%15 != 0 {
		return nil, topologyBad("cost 1..32767, interval 15..10080 minutes in multiples of 15 required")
	}
	sites := []string{}
	seen := map[string]bool{}
	for _, name := range in.Sites {
		entry, e := findTopology(ctx, s.ldap, "site", name)
		if e != nil {
			return nil, e
		}
		key := strings.ToLower(entry.DN)
		if !seen[key] {
			sites = append(sites, entry.DN)
			seen[key] = true
		}
	}
	if len(sites) < 1 || (in.Revision == "" && len(sites) < 2) {
		return nil, topologyBad("at least two distinct sites required")
	}
	attrs := map[string][]string{"cost": {strconv.Itoa(in.Cost)}, "replInterval": {strconv.Itoa(in.Interval)}, "siteList": sites}

	return attrs, nil
}
func (s *SiteService) SaveLink(ctx context.Context, name string, in SiteLinkInput, actor, ip string) error {
	attrs, e := s.linkAttrs(ctx, in)
	if e != nil {
		return e
	}
	dn := BuildDN("CN", name, siteLinkBase(s.ldap.BaseDN()))
	op := "sitelink.update"
	if in.Revision == "" {
		op = "sitelink.create"
		if strings.TrimSpace(name) == "" {
			return topologyBad("name required")
		}
		attributes := []ldap.Attribute{{Type: "objectClass", Vals: []string{"top", "siteLink"}}, {Type: "cn", Vals: []string{name}}}
		for k, v := range attrs {
			attributes = append(attributes, ldap.Attribute{Type: k, Vals: v})
		}
		e = s.ldap.Add(ctx, dn, attributes)
	} else {
		e = topologyModify(ctx, s.ldap, dn, in.Revision, attrs)
	}
	if e != nil {
		s.audit.Failure(actor, op, dn, ip, e)
	} else {
		s.audit.Success(actor, op, dn, ip)
	}
	return e
}
func (s *SiteService) LinkSchedule(ctx context.Context, name, revision string, days []string, actor, ip string) error {
	return topologyBad(siteLinkScheduleWarning)
}
func (s *SiteService) DeleteLink(ctx context.Context, name, revision, actor, ip string) error {
	dn := BuildDN("CN", name, siteLinkBase(s.ldap.BaseDN()))
	e := topologyDelete(ctx, s.ldap, dn, revision)
	if e != nil {
		s.audit.Failure(actor, "sitelink.delete", dn, ip, e)
	} else {
		s.audit.Success(actor, "sitelink.delete", dn, ip)
	}
	return e
}

type Controller struct {
	Name     string `json:"name"`
	DNS      string `json:"dns"`
	Site     string `json:"site"`
	DN       string `json:"dn"`
	NTDS     string `json:"ntds"`
	Revision string `json:"revision"`
}

func (s *SiteService) Controllers(ctx context.Context) ([]Controller, error) {
	es, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: SitesContainerDN(s.ldap.BaseDN()), Filter: "(objectClass=nTDSDSA)", Attributes: []string{"cn"}})
	if e != nil {
		return nil, e
	}
	out := []Controller{}
	for _, entry := range es {
		dn, e := parentDN(entry.DN)
		if e != nil {
			return nil, e
		}
		server, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=server)", Attributes: []string{"cn", "dNSHostName", "uSNChanged"}})
		if e != nil {
			return nil, e
		}
		servers, e := parentDN(dn)
		if e != nil {
			return nil, e
		}
		site, e := parentDN(servers)
		if e != nil {
			return nil, e
		}
		out = append(out, Controller{server.GetAttributeValue("cn"), server.GetAttributeValue("dNSHostName"), cnFromDN(site), dn, entry.DN, server.GetAttributeValue("uSNChanged")})
	}
	return out, nil
}
func (s *SiteService) controller(ctx context.Context, name string) (*Controller, error) {
	list, e := s.Controllers(ctx)
	if e != nil {
		return nil, e
	}
	for _, dc := range list {
		if strings.EqualFold(dc.Name, name) || strings.EqualFold(dc.DNS, name) {
			return &dc, nil
		}
	}
	return nil, topologyBad("unknown domain controller")
}
func (s *SiteService) MoveController(ctx context.Context, name, site, revision, actor, ip string) error {
	dc, e := s.controller(ctx, name)
	if e != nil {
		return e
	}
	if dc.Revision != revision {
		return ErrTopologyConflict
	}
	target, e := findTopology(ctx, s.ldap, "site", site)
	if e != nil {
		return e
	}
	rdn, e := rdnFromDN(dc.DN)
	if e != nil {
		return e
	}
	controls, e := assertion(revision)
	if e != nil {
		return e
	}
	conn, e := s.ldap.Conn(ctx)
	if e != nil {
		return e
	}
	req := ldap.NewModifyDNRequest(dc.DN, rdn, true, BuildDN("CN", "Servers", target.DN))
	req.Controls = controls
	e = topologyError(conn.ModifyDN(req))
	if e != nil {
		s.audit.Failure(actor, "dc.move", dc.DN, ip, e)
	} else {
		s.audit.Success(actor, "dc.move", dc.DN+" -> "+site, ip)
	}
	return e
}
func (s *SubnetService) SetSite(ctx context.Context, subnet, site, actor, ip string) error {
	if _, e := netip.ParsePrefix(subnet); e != nil {
		return topologyBad("CIDR required")
	}
	target, e := findTopology(ctx, s.ldap, "site", site)
	if e != nil {
		return e
	}
	dn := BuildDN("CN", subnet, SubnetsContainerDN(s.ldap.BaseDN()))
	e = s.ldap.ReplaceAttr(ctx, dn, "siteObject", target.DN)
	if e != nil {
		s.audit.Failure(actor, "subnet.set-site", dn, ip, e)
	} else {
		s.audit.Success(actor, "subnet.set-site", dn+" -> "+site, ip)
	}
	return e
}

type Connection struct {
	ID                string   `json:"id"`
	DN                string   `json:"dn"`
	Source            string   `json:"source"`
	Destination       string   `json:"destination"`
	Enabled           bool     `json:"enabled"`
	Automatic         bool     `json:"automatic"`
	Revision          string   `json:"revision"`
	Schedule          []string `json:"schedule"`
	ScheduleSupported bool     `json:"scheduleSupported"`
}

func (s *SiteService) Connections(ctx context.Context) ([]Connection, error) {
	es, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: SitesContainerDN(s.ldap.BaseDN()), Filter: "(objectClass=nTDSConnection)", Attributes: []string{"cn", "fromServer", "enabledConnection", "options", "schedule", "uSNChanged"}})
	if e != nil {
		return nil, e
	}
	dcs, e := s.Controllers(ctx)
	if e != nil {
		return nil, e
	}
	names := map[string]string{}
	for _, dc := range dcs {
		names[strings.ToLower(dc.NTDS)] = dc.DNS
	}
	out := []Connection{}
	for _, entry := range es {
		dest, _ := parentDN(entry.DN)
		options, _ := strconv.Atoi(entry.GetAttributeValue("options"))
		days, ok := DecodeSchedule(entry.GetRawAttributeValue("schedule"))
		if len(entry.GetRawAttributeValue("schedule")) == 0 {
			days = make([]string, 7)
		}
		src := entry.GetAttributeValue("fromServer")
		name := func(dn string) string {
			if n := names[strings.ToLower(dn)]; n != "" {
				return n
			}
			return dn
		}
		out = append(out, Connection{entry.GetAttributeValue("cn"), entry.DN, name(src), name(dest), !strings.EqualFold(entry.GetAttributeValue("enabledConnection"), "FALSE"), options&1 != 0, entry.GetAttributeValue("uSNChanged"), days, ok})
	}
	return out, nil
}
func (s *SiteService) CreateConnection(ctx context.Context, source, destination, actor, ip string) error {
	src, e := s.controller(ctx, source)
	if e != nil {
		return e
	}
	dst, e := s.controller(ctx, destination)
	if e != nil {
		return e
	}
	if strings.EqualFold(src.NTDS, dst.NTDS) {
		return topologyBad("source and destination must differ")
	}
	days := []string{"00:00-24:00", "00:00-24:00", "00:00-24:00", "00:00-24:00", "00:00-24:00", "00:00-24:00", "00:00-24:00"}
	schedule, _ := EncodeSchedule(days)
	dn := BuildDN("CN", "manual-"+rand.Text(), dst.NTDS)
	e = s.ldap.Add(ctx, dn, []ldap.Attribute{{Type: "objectClass", Vals: []string{"top", "nTDSConnection"}}, {Type: "fromServer", Vals: []string{src.NTDS}}, {Type: "enabledConnection", Vals: []string{"TRUE"}}, {Type: "options", Vals: []string{"32"}}, {Type: "schedule", Vals: []string{string(schedule)}}})
	if e != nil {
		s.audit.Failure(actor, "connection.create", dn, ip, e)
	} else {
		s.audit.Success(actor, "connection.create", dn, ip)
	}
	return e
}
func (s *SiteService) UpdateConnection(ctx context.Context, id, revision string, enabled *bool, days []string, remove bool, actor, ip string) error {
	entry, e := findTopology(ctx, s.ldap, "nTDSConnection", id)
	if e != nil {
		return e
	}
	if remove {
		e = topologyDelete(ctx, s.ldap, entry.DN, revision)
	} else {
		attrs := map[string][]string{}
		if enabled != nil {
			v := "FALSE"
			if *enabled {
				v = "TRUE"
			}
			attrs["enabledConnection"] = []string{v}
		}
		if days != nil {
			b, err := EncodeSchedule(days)
			if err != nil {
				return err
			}
			attrs["schedule"] = []string{string(b)}
			options, _ := strconv.Atoi(entry.GetAttributeValue("options"))
			attrs["options"] = []string{strconv.Itoa(options | 32)}
		}
		if len(attrs) == 0 {
			return topologyBad("no changes supplied")
		}
		e = topologyModify(ctx, s.ldap, entry.DN, revision, attrs)
	}
	op := "connection.update"
	if remove {
		op = "connection.delete"
	}
	if e != nil {
		s.audit.Failure(actor, op, entry.DN, ip, e)
	} else {
		s.audit.Success(actor, op, entry.DN, ip)
	}
	return e
}
