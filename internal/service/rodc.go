package service

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/agent"
	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

const rodcPartialSecrets = 0x04000000
const rodcListLimit = 4096
const rodcAllow = "msDS-RevealOnDemandGroup"
const rodcDeny = "msDS-NeverRevealGroup"

type RODCService struct {
	ldap    *ldapproto.Client
	audit   *audit.Logger
	mu      sync.Mutex
	helpers *agent.Client
}
type RODCPrincipal struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	SID         string `json:"sid,omitempty"`
	Unavailable bool   `json:"unavailable,omitempty"`
}
type RODCState struct {
	Controller       Controller      `json:"controller"`
	Source           string          `json:"source"`
	Revision         string          `json:"revision"`
	Allowed          []RODCPrincipal `json:"allowed"`
	Denied           []RODCPrincipal `json:"denied"`
	Cached           []RODCPrincipal `json:"cached"`
	Authenticated    []RODCPrincipal `json:"authenticated"`
	PreloadAvailable bool            `json:"preloadAvailable"`
	Warnings         []string        `json:"warnings"`
	entry            *ldap.Entry
	guid             []byte
}
type RODCInput struct {
	Operation string   `json:"operation"`
	Principal string   `json:"principal,omitempty"`
	Accounts  []string `json:"accounts,omitempty"`
	Preview   string   `json:"preview,omitempty"`
}
type RODCPreloadAccount struct {
	RODCPrincipal
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	token    []string
}
type RODCPlan struct {
	Operation  string               `json:"operation"`
	Controller string               `json:"controller"`
	Source     string               `json:"source"`
	Principal  *RODCPrincipal       `json:"principal,omitempty"`
	Accounts   []RODCPreloadAccount `json:"accounts"`
	Preview    string               `json:"preview"`
	Warnings   []string             `json:"warnings"`
	state      *RODCState
}
type RODCAccountResult struct {
	DN     string `json:"dn"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}
type RODCResult struct {
	Controller string              `json:"controller"`
	Operation  string              `json:"operation"`
	Accounts   []RODCAccountResult `json:"accounts"`
}

func rodcValues(e *ldap.Entry, name string) ([]string, error) {
	for _, a := range e.Attributes {
		if strings.HasPrefix(strings.ToLower(a.Name), strings.ToLower(name)+";range=") {
			return nil, fmt.Errorf("RODC attribute %s requires ranged retrieval; result is incomplete", name)
		}
	}
	v := e.GetEqualFoldAttributeValues(name)
	if len(v) > rodcListLimit {
		return nil, fmt.Errorf("RODC attribute %s exceeds display limit", name)
	}
	return v, nil
}

// RevealedList is DN-Binary, not a password or a timestamp. Multiple values
// for different secret attributes can refer to the same account.
func rodcRevealedDN(value string) (string, error) {
	p := strings.SplitN(value, ":", 4)
	if len(p) != 4 || p[0] != "B" {
		return "", fmt.Errorf("invalid revealed-list DN-Binary value")
	}
	n, e := strconv.Atoi(p[1])
	if e != nil || n != len(p[2]) || n%2 != 0 {
		return "", fmt.Errorf("invalid revealed-list length")
	}
	for _, r := range p[2] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return "", fmt.Errorf("invalid revealed-list binary value")
		}
	}
	if _, e = ldap.ParseDN(p[3]); e != nil {
		return "", fmt.Errorf("invalid revealed-list DN")
	}
	return p[3], nil
}
func rodcDomainDN(dn, base string) bool {
	d, e := ldap.ParseDN(dn)
	if e != nil {
		return false
	}
	b, e := ldap.ParseDN(base)
	return e == nil && (b.EqualFold(d) || b.AncestorOfFold(d))
}
func (s *RODCService) principal(ctx context.Context, dn string, token bool) (*ldap.Entry, RODCPrincipal, error) {
	if !rodcDomainDN(dn, s.ldap.BaseDN()) {
		return nil, RODCPrincipal{}, topologyBad("principal DN must be in this domain")
	}
	attrs := []string{"objectClass", "sAMAccountName", "objectSid", "objectGUID", "groupType", "userAccountControl", "uSNChanged", "pwdLastSet"}
	if token {
		attrs = append(attrs, "tokenGroups")
	}
	e, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(|(objectClass=user)(objectClass=group))", Attributes: attrs})
	if err != nil {
		return nil, RODCPrincipal{}, err
	}
	p := RODCPrincipal{DN: e.DN, Name: e.GetEqualFoldAttributeValue("sAMAccountName"), SID: sidString(e.GetEqualFoldRawAttributeValue("objectSid"))}
	for _, c := range e.GetEqualFoldAttributeValues("objectClass") {
		switch strings.ToLower(c) {
		case "user":
			if p.Kind == "" {
				p.Kind = "user"
			}
		case "computer":
			p.Kind = "computer"
		case "group":
			p.Kind = "group"
		}
	}
	if p.Kind == "" || p.SID == "" {
		return nil, p, topologyBad("unsupported security principal")
	}
	if p.Kind == "group" {
		n, err := strconv.ParseInt(e.GetEqualFoldAttributeValue("groupType"), 10, 64)
		if err != nil || uint32(n)&0x80000000 == 0 {
			return nil, p, topologyBad("a security group is required")
		}
	}
	return e, p, nil
}
func (s *RODCService) principals(ctx context.Context, values []string, binaryDN bool) ([]RODCPrincipal, error) {
	out := []RODCPrincipal{}
	seen := map[string]bool{}
	for _, dn := range values {
		var e error
		if binaryDN {
			dn, e = rodcRevealedDN(dn)
			if e != nil {
				return nil, e
			}
		}
		parsed, e := ldap.ParseDN(dn)
		if e != nil {
			return nil, e
		}
		key := strings.ToLower(parsed.String())
		if seen[key] {
			continue
		}
		seen[key] = true
		_, p, e := s.principal(ctx, dn, false)
		if e != nil {
			if !ldap.IsErrorWithCode(e, ldap.LDAPResultNoSuchObject) && !errors.Is(e, ErrTopologyInput) {
				return nil, e
			}
			p = RODCPrincipal{DN: dn, Name: cnFromDN(dn), Kind: "unknown", Unavailable: true}
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DN < out[j].DN })
	return out, nil
}
func (s *RODCService) source(ctx context.Context) (string, error) {
	c, e := s.ldap.Conn(ctx)
	if e != nil {
		return "", e
	}
	r, e := c.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"dNSHostName", "dsServiceName"}, nil))
	if e != nil {
		return "", e
	}
	if len(r.Entries) != 1 {
		return "", fmt.Errorf("missing RootDSE")
	}
	dn := r.Entries[0].GetEqualFoldAttributeValue("dsServiceName")
	entry, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=nTDSDSA)", Attributes: []string{"msDS-isRODC"}})
	if e != nil {
		return "", e
	}
	if !strings.EqualFold(entry.GetEqualFoldAttributeValue("msDS-isRODC"), "FALSE") {
		return "", topologyBad("configure ldap.uri on a writable DC for RODC administration")
	}
	host := r.Entries[0].GetEqualFoldAttributeValue("dNSHostName")
	if _, e = consistencyPeerURI("ldaps://unused", host); e != nil {
		return "", e
	}
	return host, nil
}
func (s *RODCService) State(ctx context.Context, name string) (*RODCState, error) {
	if strings.TrimSpace(name) == "" {
		return nil, topologyBad("choose a discovered RODC")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	source, e := s.source(ctx)
	if e != nil {
		return nil, e
	}
	dc, e := (&SiteService{ldap: s.ldap}).controller(ctx, name)
	if e != nil {
		return nil, e
	}
	if !dc.RODC || dc.Computer == "" {
		return nil, topologyBad("selected controller is not an RODC")
	}
	entry, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dc.Computer, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=computer)", Attributes: []string{"userAccountControl", "dNSHostName", "objectGUID", "uSNChanged", rodcAllow, rodcDeny, "msDS-RevealedList", "msDS-RevealedUsers", "msDS-AuthenticatedToAccountlist"}})
	if e != nil {
		return nil, e
	}
	uac, e := strconv.ParseUint(entry.GetEqualFoldAttributeValue("userAccountControl"), 10, 32)
	if e != nil || uac&rodcPartialSecrets == 0 || !strings.EqualFold(entry.GetEqualFoldAttributeValue("dNSHostName"), dc.DNS) {
		return nil, topologyBad("RODC computer identity mismatch")
	}
	ntds, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dc.NTDS, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=nTDSDSA)", Attributes: []string{"objectGUID"}})
	if e != nil {
		return nil, e
	}
	if len(ntds.GetEqualFoldRawAttributeValue("objectGUID")) != 16 {
		return nil, fmt.Errorf("missing RODC DSA identity")
	}
	out := &RODCState{Controller: *dc, Source: source, entry: entry, guid: ntds.GetEqualFoldRawAttributeValue("objectGUID"), Warnings: []string{"PRP removal or denial does not erase passwords already cached. Password reset and client validation are separate operations.", "Cached and authenticated account lists are read from the configured writable DC and can lag replication. The authenticated list has no event times or failed logins; an empty list is not proof that no logins occurred."}}
	for _, set := range []struct {
		attr   string
		binary bool
		dst    *[]RODCPrincipal
	}{{rodcAllow, false, &out.Allowed}, {rodcDeny, false, &out.Denied}, {"msDS-RevealedList", true, &out.Cached}, {"msDS-AuthenticatedToAccountlist", false, &out.Authenticated}} {
		values, e := rodcValues(entry, set.attr)
		if e != nil {
			return nil, e
		}
		if set.attr == "msDS-RevealedList" {
			extra, e := rodcValues(entry, "msDS-RevealedUsers")
			if e != nil {
				return nil, e
			}
			values = append(values, extra...)
		}
		*set.dst, e = s.principals(ctx, values, set.binary)
		if e != nil {
			return nil, e
		}
	}
	out.PreloadAvailable = s.preloadTarget(dc.DNS)
	out.Revision = consistencyHash([]any{dc.NTDS, dc.Computer, dc.DNS, out.guid, source, entry.GetEqualFoldAttributeValue("uSNChanged"), entry.GetEqualFoldRawAttributeValue("objectGUID"), out.Allowed, out.Denied})
	return out, nil
}

func rodcDecision(account RODCPrincipal, groups [][]byte, allowed, denied []RODCPrincipal) (string, string, []string) {
	token := []string{account.SID}
	for _, g := range groups {
		sid := sidString(g)
		if sid == "" {
			return "unknown", "Invalid tokenGroups", nil
		}
		token = append(token, sid)
	}
	sort.Strings(token)
	match := func(list []RODCPrincipal) (bool, bool) {
		unknown := false
		for _, p := range list {
			if p.Unavailable || p.SID == "" {
				unknown = true
			}
			for _, sid := range token {
				if p.SID != "" && p.SID == sid {
					return true, unknown
				}
			}
		}
		return false, unknown
	}
	deny, du := match(denied)
	if deny {
		return "denied", "Matched the deny policy", token
	}
	if du || len(groups) == 0 {
		return "unknown", "Full security token or deny membership is unavailable", token
	}
	allow, au := match(allowed)
	if allow {
		return "allowed", "Matched the allow policy; deny takes precedence", token
	}
	if au {
		return "unknown", "Allow membership is unavailable", token
	}
	return "denied", "No allow policy matches this account", token
}
func validateRODCInput(in RODCInput) error {
	switch in.Operation {
	case "allow", "deny", "remove-allow", "remove-deny":
		if in.Principal == "" || len(in.Accounts) != 0 {
			return topologyBad("policy change requires one principal DN")
		}
	case "preload":
		if in.Principal != "" || len(in.Accounts) == 0 || len(in.Accounts) > 50 {
			return topologyBad("preload requires 1..50 user or computer DNs")
		}
	default:
		return topologyBad("invalid RODC operation")
	}
	return nil
}
func (s *RODCService) Preview(ctx context.Context, name string, in RODCInput) (*RODCPlan, error) {
	if e := validateRODCInput(in); e != nil {
		return nil, e
	}
	state, e := s.State(ctx, name)
	if e != nil {
		return nil, e
	}
	p := &RODCPlan{Operation: in.Operation, Controller: state.Controller.DNS, Source: state.Source, state: state, Accounts: []RODCPreloadAccount{}, Warnings: state.Warnings}
	fingerprints := []any{state.Revision, in.Operation}
	if in.Operation != "preload" {
		entry, principal, e := s.principal(ctx, in.Principal, false)
		if e != nil {
			return nil, e
		}
		p.Principal = &principal
		fingerprints = append(fingerprints, principal, entry.GetEqualFoldAttributeValue("uSNChanged"))
	} else {
		if !state.PreloadAvailable {
			return nil, topologyBad("preload helper is not configured for this RODC")
		}
		seen := map[string]bool{}
		for _, dn := range in.Accounts {
			entry, principal, e := s.principal(ctx, dn, true)
			if e != nil {
				return nil, e
			}
			if principal.Kind == "group" {
				return nil, topologyBad("select individual users or computers for preload; groups are not expanded")
			}
			if seen[strings.ToLower(principal.DN)] {
				return nil, topologyBad("duplicate preload account")
			}
			seen[strings.ToLower(principal.DN)] = true
			decision, reason, token := rodcDecision(principal, entry.GetEqualFoldRawAttributeValues("tokenGroups"), state.Allowed, state.Denied)
			p.Accounts = append(p.Accounts, RODCPreloadAccount{RODCPrincipal: principal, Decision: decision, Reason: reason, token: token})
			fingerprints = append(fingerprints, principal, token, decision, entry.GetEqualFoldAttributeValue("uSNChanged"), entry.GetEqualFoldAttributeValue("pwdLastSet"))
		}
	}
	p.Preview = consistencyHash(fingerprints)
	return p, nil
}
func (s *RODCService) Apply(ctx context.Context, name string, in RODCInput, actor, ip string) (out *RODCResult, err error) {
	if in.Preview == "" {
		return nil, topologyBad("preview required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	defer func() {
		if err != nil {
			s.audit.Failure(actor, "rodc."+in.Operation, name, ip, err)
		} else {
			s.audit.Success(actor, "rodc."+in.Operation, name, ip)
		}
	}()
	p, e := s.Preview(ctx, name, in)
	if e != nil {
		return nil, e
	}
	if p.Preview != in.Preview {
		return nil, ErrTopologyConflict
	}
	out = &RODCResult{Controller: p.Controller, Operation: in.Operation, Accounts: []RODCAccountResult{}}
	if in.Operation == "preload" {
		for _, account := range p.Accounts {
			item := RODCAccountResult{DN: account.DN, Status: "blocked"}
			if account.Decision != "allowed" {
				item.Error = account.Reason
			} else {
				// Re-evaluate PRP and token immediately before each independent request.
				fresh, e := s.Preview(ctx, name, RODCInput{Operation: "preload", Accounts: []string{account.DN}})
				if e != nil {
					item.Status = "failed"
					item.Error = e.Error()
				} else if fresh.Accounts[0].Decision != "allowed" {
					item.Error = fresh.Accounts[0].Reason
				} else {
					e = s.preload(ctx, fresh.state, account.DN)
					if e != nil {
						item.Status = "unconfirmed"
						item.Error = e.Error()
					} else {
						item.Status = "preloaded"
					}
				}
			}
			if item.Status == "preloaded" {
				s.audit.Success(actor, "rodc.preload.account", p.Controller+" "+account.DN, ip)
			} else {
				s.audit.Failure(actor, "rodc.preload.account", p.Controller+" "+account.DN, ip, fmt.Errorf("%s: %s", item.Status, item.Error))
			}
			out.Accounts = append(out.Accounts, item)
		}
		return out, nil
	}
	attr := rodcAllow
	if strings.Contains(in.Operation, "deny") {
		attr = rodcDeny
	}
	assertion, e := ldap.CompileFilter("(&(uSNChanged=" + ldap.EscapeFilter(p.state.entry.GetEqualFoldAttributeValue("uSNChanged")) + ")(userAccountControl:1.2.840.113556.1.4.803:=" + strconv.Itoa(rodcPartialSecrets) + "))")
	if e != nil {
		return nil, e
	}
	req := ldap.NewModifyRequest(p.state.entry.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(assertion.Bytes()))})
	if strings.HasPrefix(in.Operation, "remove-") {
		req.Delete(attr, []string{p.Principal.DN})
	} else {
		req.Add(attr, []string{p.Principal.DN})
	}
	if e = s.ldap.Modify(ctx, req); e != nil {
		if ldap.IsErrorWithCode(e, 122) {
			return nil, ErrTopologyConflict
		}
		return nil, e
	}
	return out, nil
}

func rodcGUIDString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:])
}
