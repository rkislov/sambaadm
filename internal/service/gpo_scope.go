package service

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

type ScopeLink struct {
	DN       string `json:"dn"`
	Name     string `json:"name"`
	GUID     string `json:"guid"`
	Order    int    `json:"order"`
	Enabled  bool   `json:"enabled"`
	Enforced bool   `json:"enforced"`
	Options  uint32 `json:"options"`
	Missing  bool   `json:"missing"`
	Flags    int    `json:"flags"`
	WMI      string `json:"wmi,omitempty"`
	Source   string `json:"source,omitempty"`
	Reason   string `json:"reason,omitempty"`
}
type GPContainer struct {
	DN       string      `json:"dn"`
	Name     string      `json:"name"`
	Parent   string      `json:"parent"`
	Revision string      `json:"revision"`
	Block    bool        `json:"block"`
	Options  uint32      `json:"options"`
	Links    []ScopeLink `json:"links"`
}
type GPScope struct {
	Containers []GPContainer `json:"containers"`
	Policies   []GPO         `json:"policies"`
}
type ScopeChange struct {
	Container string      `json:"container"`
	Revision  string      `json:"revision"`
	Block     bool        `json:"block"`
	Links     []ScopeLink `json:"links"`
}

func parseScopeLinks(raw string) ([]ScopeLink, error) {
	out := []ScopeLink{}
	for raw != "" {
		if raw[0] != '[' {
			return nil, topologyBad("malformed gPLink")
		}
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return nil, topologyBad("malformed gPLink")
		}
		body := raw[1:end]
		semi := strings.LastIndexByte(body, ';')
		if semi < 7 || !strings.EqualFold(body[:7], "LDAP://") {
			return nil, topologyBad("malformed gPLink")
		}
		dn := body[7:semi]
		if _, e := ldap.ParseDN(dn); e != nil {
			return nil, topologyBad("malformed link DN")
		}
		options, e := strconv.ParseUint(body[semi+1:], 10, 32)
		if e != nil {
			return nil, topologyBad("malformed link options")
		}
		out = append(out, ScopeLink{DN: dn, Options: uint32(options), Enabled: options&1 == 0, Enforced: options&2 != 0})
		raw = raw[end+1:]
	}
	// AD stores links in processing order; the rightmost link has precedence 1.
	for i := range out {
		out[i].Order = len(out) - i
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	return out, nil
}
func dnEqual(a, b string) bool {
	x, e := ldap.ParseDN(a)
	if e != nil {
		return false
	}
	y, e := ldap.ParseDN(b)
	return e == nil && x.EqualFold(y)
}
func (s *GPOService) Scope(ctx context.Context) (*GPScope, error) {
	es, e := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(|(objectClass=domainDNS)(objectClass=organizationalUnit))", Attributes: []string{"name", "gPLink", "gPOptions", "uSNChanged"}})
	if e != nil {
		return nil, e
	}
	ps, e := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(objectClass=groupPolicyContainer)", Attributes: []string{"cn", "displayName", "flags", "gPCWQLFilter"}})
	if e != nil {
		return nil, e
	}
	out := &GPScope{Containers: []GPContainer{}, Policies: []GPO{}}
	for _, p := range ps {
		out.Policies = append(out.Policies, entryToGPO(p))
	}
	for _, entry := range es {
		links, e := parseScopeLinks(entry.GetAttributeValue("gPLink"))
		if e != nil {
			return nil, e
		}
		options := uint64(0)
		if v := entry.GetAttributeValue("gPOptions"); v != "" {
			options, e = strconv.ParseUint(v, 10, 32)
			if e != nil {
				return nil, topologyBad("malformed gPOptions")
			}
		}
		parent, _ := parentDN(entry.DN)
		if dnEqual(entry.DN, s.ldap.BaseDN()) {
			parent = ""
		}
		c := GPContainer{DN: entry.DN, Name: entry.GetAttributeValue("name"), Parent: parent, Revision: entry.GetAttributeValue("uSNChanged"), Options: uint32(options), Block: options&1 != 0, Links: links}
		for i := range c.Links {
			l := &c.Links[i]
			l.Missing = true
			l.Name = l.DN
			for _, p := range ps {
				if dnEqual(l.DN, p.DN) {
					l.Missing = false
					l.Name = p.GetAttributeValue("displayName")
					l.GUID = p.GetAttributeValue("cn")
					l.Flags, e = strconv.Atoi(p.GetAttributeValue("flags"))
					if e != nil {
						l.Flags = -1
					}
					l.WMI = p.GetAttributeValue("gPCWQLFilter")
					break
				}
			}
		}
		out.Containers = append(out.Containers, c)
	}
	sort.Slice(out.Containers, func(i, j int) bool { return out.Containers[i].DN < out.Containers[j].DN })
	return out, nil
}
func (s *GPOService) SaveScope(ctx context.Context, in ScopeChange, actor, ip string) error {
	model, e := s.Scope(ctx)
	if e != nil {
		return e
	}
	var container *GPContainer
	for i := range model.Containers {
		if dnEqual(model.Containers[i].DN, in.Container) {
			container = &model.Containers[i]
			break
		}
	}
	if container == nil {
		return topologyBad("select a domain or OU in this domain")
	}
	if container.Revision != in.Revision {
		return ErrTopologyConflict
	}
	if container.Options & ^uint32(1) != 0 {
		return topologyBad("unknown inheritance options; read only")
	}
	if len(in.Links) > 1024 {
		return topologyBad("too many links")
	}
	for _, old := range container.Links {
		if old.Options & ^uint32(3) != 0 {
			return topologyBad("unknown link options; read only")
		}
	}
	var raw strings.Builder
	for i := len(in.Links) - 1; i >= 0; i-- {
		l := in.Links[i]
		if strings.ContainsAny(l.DN, "[]") {
			return topologyBad("unsupported link DN")
		}
		known := false
		for _, p := range model.Policies {
			if dnEqual(p.DN, l.DN) {
				known = true
				break
			}
		}
		if !known {
			return topologyBad("policy not found; remove unresolved links before saving")
		}
		for j := 0; j < i; j++ {
			if dnEqual(in.Links[j].DN, l.DN) {
				return topologyBad("duplicate policy link")
			}
		}
		options := 0
		if !l.Enabled {
			options |= 1
		}
		if l.Enforced {
			options |= 2
		}
		fmt.Fprintf(&raw, "[LDAP://%s;%d]", l.DN, options)
	}
	options := "0"
	if in.Block {
		options = "1"
	}
	values := []string{raw.String()}
	if raw.Len() == 0 {
		values = nil
	}
	e = topologyModify(ctx, s.ldap, container.DN, in.Revision, map[string][]string{"gPLink": values, "gPOptions": {options}})
	if e != nil {
		s.audit.Failure(actor, "gpo.scope", container.DN, ip, e)
	} else {
		s.audit.Success(actor, "gpo.scope", container.DN, ip)
	}
	return e
}

// ScopeInheritance is a link-level preview, not RSoP: site, token, WMI and
// client-side extension processing are intentionally not claimed as evaluated.
func ScopeInheritance(model *GPScope, dn string) ([]ScopeLink, error) {
	chain := []GPContainer{}
	for dn != "" {
		var found *GPContainer
		for i := range model.Containers {
			if dnEqual(model.Containers[i].DN, dn) {
				found = &model.Containers[i]
				break
			}
		}
		if found == nil {
			return nil, topologyBad("container not found")
		}
		if found.Options & ^uint32(1) != 0 {
			return nil, topologyBad("unknown inheritance options; preview unavailable")
		}
		chain = append(chain, *found)
		dn = found.Parent
		if len(chain) > 256 {
			return nil, topologyBad("invalid container hierarchy")
		}
	}
	normal, enforced, excluded := []ScopeLink{}, []ScopeLink{}, []ScopeLink{}
	blocked := false
	for _, c := range chain {
		localEnforced := []ScopeLink{}
		for _, l := range c.Links {
			l.Source = c.DN
			switch {
			case l.Options & ^uint32(3) != 0:
				l.Reason = "unknown-options"
			case !l.Enabled:
				l.Reason = "disabled"
			case l.Missing:
				l.Reason = "missing"
			case blocked && !l.Enforced:
				l.Reason = "blocked"
			default:
				l.Reason = "candidate"
			}
			if l.Reason != "candidate" {
				excluded = append(excluded, l)
			} else if l.Enforced {
				localEnforced = append(localEnforced, l)
			} else {
				normal = append(normal, l)
			}
		}
		enforced = append(localEnforced, enforced...)
		blocked = blocked || c.Block
	}
	return append(append(enforced, normal...), excluded...), nil
}
