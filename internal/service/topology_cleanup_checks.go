package service

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
	"sort"
	"strconv"
	"strings"
	"time"
)

type CleanupChecksRequest struct {
	CleanupRequest
	Peer string `json:"peer"`
}
type CleanupDependency struct {
	Source     string `json:"source"`
	Attribute  string `json:"attribute"`
	Target     string `json:"target"`
	Controller string `json:"controller"`
}
type CleanupChecks struct {
	plan         *CleanupPlan
	Observed     time.Time           `json:"observed"`
	Peer         string              `json:"peer"`
	Revision     string              `json:"revision"`
	CanApply     bool                `json:"canApply"`
	Checks       []DiagnosticCheck   `json:"checks"`
	Dependencies []CleanupDependency `json:"dependencies"`
}

func comparableCleanupObject(o CleanupObject) []byte {
	attrs := map[string][][]byte{}
	for k, v := range o.Attributes {
		if k == "uSNChanged" || k == "whenChanged" {
			continue
		}
		values := append([][]byte(nil), v...)
		sort.Slice(values, func(i, j int) bool { return bytes.Compare(values[i], values[j]) < 0 })
		attrs[k] = values
	}
	b, _ := json.Marshal(attrs)
	return b
}
func (s *SiteService) CheckCleanup(ctx context.Context, in CleanupChecksRequest) (*CleanupChecks, error) {
	p, e := s.PreviewCleanup(ctx, in.DNs)
	if e != nil {
		return nil, e
	}
	if p.Revision != in.Revision {
		return nil, ErrTopologyConflict
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	out := &CleanupChecks{plan: p, Observed: time.Now().UTC(), Revision: p.Revision, Checks: []DiagnosticCheck{}, Dependencies: []CleanupDependency{}}
	add := func(id, status, detail string) {
		out.Checks = append(out.Checks, DiagnosticCheck{ID: id, Status: status, Detail: detail})
	}
	add("apply", "blocked", "Apply requires a matching verified backup and fresh checks on every supported replica.")
	dns := []string{}
	for _, o := range p.Objects {
		if len(o.Remove) == 0 {
			dns = append(dns, o.DN)
		}
	}
	s.checkCleanupLocal(ctx, dns, out, "")
	peer, e := s.controller(ctx, in.Peer)
	if e != nil {
		return nil, e
	}
	out.Peer = peer.DNS
	if peer.RODC {
		return nil, topologyBad("peer must be a writable DC")
	}
	uri, e := consistencyPeerURI(s.ldap.URI(), peer.DNS)
	if e != nil {
		return nil, e
	}
	other := s.ldap.ServicePeer(uri)
	defer other.Close()
	// Compare actual DSA identities, not host aliases. USNs are DC-local and are not compared.
	rootOpts := ldapproto.SearchOptions{BaseDN: "", Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"dsServiceName"}, MaxEntries: 1}
	// Search's empty BaseDN defaults to the domain; query RootDSE explicitly via the connection.
	identity := func(client *ldapproto.Client) (string, error) {
		conn, err := client.Conn(ctx)
		if err != nil {
			return "", err
		}
		r, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false, rootOpts.Filter, rootOpts.Attributes, nil))
		if err != nil {
			return "", err
		}
		if len(r.Entries) != 1 || r.Entries[0].GetAttributeValue("dsServiceName") == "" {
			return "", topologyBad("DC identity unavailable")
		}
		return r.Entries[0].GetAttributeValue("dsServiceName"), nil
	}
	primary, e := identity(s.ldap)
	if e != nil {
		add("peer", "unknown", e.Error())
		return out, nil
	}
	secondary, e := identity(other)
	if e != nil {
		add("peer", "unknown", e.Error())
		return out, nil
	}
	if dnKey(primary) == dnKey(secondary) {
		add("peer", "blocked", "Selected peer is the same LDAP controller")
		return out, nil
	}
	for _, probe := range []struct {
		client *ldapproto.Client
		dn, id string
	}{{s.ldap, primary, "replication_enabled"}, {other, secondary, "peer_replication_enabled"}} {
		entry, err := probe.client.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: probe.dn, Scope: ldapproto.ScopeBase(), Attributes: []string{"options"}, MaxEntries: 1})
		if err != nil {
			add(probe.id, "unknown", err.Error())
			continue
		}
		flags, err := strconv.ParseUint(entry.GetAttributeValue("options"), 10, 32)
		if err != nil {
			add(probe.id, "unknown", "Replication flags unavailable")
			continue
		}
		if flags&6 != 0 {
			add(probe.id, "blocked", "Inbound or outbound replication is disabled on this DC")
		} else {
			add(probe.id, "ok", "Inbound/outbound replication disable flags are not set; this alone does not prove convergence")
		}
	}
	peerService := &SiteService{ldap: other}
	peerService.checkCleanupLocal(ctx, dns, out, "peer_")
	second, e := peerService.PreviewCleanup(ctx, in.DNs)
	if e != nil {
		add("peer", "unknown", e.Error())
		return out, nil
	}
	difference := "Selected object set differs between controllers"
	matches := len(second.Objects) == len(p.Objects)
	if matches {
		for i, o := range p.Objects {
			if dnKey(o.DN) != dnKey(second.Objects[i].DN) || !bytes.Equal(comparableCleanupObject(o), comparableCleanupObject(second.Objects[i])) {
				matches = false
			}
		}
	}
	if matches {
		add("peer", "ok", "Selected object identities and exported attributes match on another RWDC; local USNs and whenChanged are excluded.")
	} else {
		add("peer", "blocked", difference+"; repeat investigation after replication converges.")
	}
	final, e := s.PreviewCleanup(ctx, in.DNs)
	if e != nil {
		add("primary_recheck", "unknown", e.Error())
	} else if final.Revision != p.Revision {
		return nil, ErrTopologyConflict
	}
	return out, nil
}

// Local dependencies must be examined on each observed replica, not only on the primary.
func (s *SiteService) checkCleanupLocal(ctx context.Context, dns []string, out *CleanupChecks, prefix string) {
	add := func(id, status, detail string) {
		out.Checks = append(out.Checks, DiagnosticCheck{ID: prefix + id, Status: status, Detail: detail})
	}
	dep := func(source, attribute, target string) {
		out.Dependencies = append(out.Dependencies, CleanupDependency{Source: source, Attribute: attribute, Target: target, Controller: hostnameFromURI(s.ldap.URI())})
	}
	controllers, e := s.Controllers(ctx)
	if e != nil {
		add("controllers", "unknown", e.Error())
	} else {
		active := false
		for _, dc := range controllers {
			if out.plan != nil && cleanupRetiredController(out.plan, dc) {
				continue
			}
			for _, dn := range dns {
				if dnKey(dn) == dnKey(dc.DN) || dnKey(dn) == dnKey(dc.NTDS) || dnKey(dn) == dnKey(dc.Computer) {
					active = true
					dep(dc.NTDS, "configured_controller", dn)
				}
			}
		}
		if active {
			add("controllers", "blocked", "Selection contains metadata of a configured DC; demotion must be confirmed separately.")
		} else {
			add("controllers", "ok", "Selection does not directly match visible DC server, NTDS or computer objects. Visibility is limited by LDAP permissions.")
		}
	}
	attrs := []string{"fromServer", "serverReference", "siteObject", "siteList", "fSMORoleOwner"}
	filters := []string{}
	for _, dn := range dns {
		for _, attr := range attrs {
			filters = append(filters, "("+attr+"="+ldap.EscapeFilter(dn)+")")
		}
	}
	complete := true
	referenceCount := len(out.Dependencies)
	for _, base := range []string{ConfigDN(s.ldap.BaseDN()), s.ldap.BaseDN()} {
		entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: base, Filter: "(|" + strings.Join(filters, "") + ")", Attributes: attrs, MaxEntries: 1000})
		if err != nil {
			complete = false
			add("references", "unknown", err.Error())
			continue
		}
		for _, entry := range entries {
			for _, attr := range attrs {
				for _, target := range entry.GetAttributeValues(attr) {
					for _, dn := range dns {
						if dnKey(target) == dnKey(dn) {
							if out.plan != nil && cleanupPlannedReference(out.plan, entry.DN, attr, target) {
								continue
							}
							dep(entry.DN, attr, target)
						}
					}
				}
			}
		}
	}
	if complete {
		status := "ok"
		if len(out.Dependencies) > referenceCount {
			status = "blocked"
		}
		add("references", status, "Read visible fromServer/serverReference/siteObject/siteList/fSMORoleOwner references in current domain and Configuration. This is not an exhaustive forest dependency scan.")
	}
	roles, e := (&DomainService{ldap: s.ldap}).FSMOShow(ctx)
	if e != nil {
		add("fsmo", "unknown", e.Error())
	} else {
		status := "ok"
		for _, role := range roles {
			if role.Owner == "" {
				status = "unknown"
			}
			for _, dn := range dns {
				owner, oe := ldap.ParseDN(role.Owner)
				target, te := ldap.ParseDN(dn)
				if oe == nil && te == nil && (owner.EqualFold(target) || target.AncestorOfFold(owner)) {
					status = "blocked"
					dep(role.Role, "fSMORoleOwner", role.Owner)
				}
			}
		}
		add("fsmo", status, "Visible FSMO owners checked; a selected owner or ancestor blocks removal.")
	}
}
