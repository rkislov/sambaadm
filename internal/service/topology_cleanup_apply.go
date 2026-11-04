package service

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

const backupRestoreKind = "offline-dbcheck-cleanup-second-restore"

type BackupRestoreReceipt struct {
	Kind         string    `json:"kind"`
	ID           string    `json:"id"`
	SHA256       string    `json:"sha256"`
	PlanRevision string    `json:"planRevision"`
	Status       string    `json:"status"`
	Finished     time.Time `json:"finished"`
}
type CleanupApplyRequest struct {
	CleanupBackupRequest
	Confirm               bool `json:"confirm"`
	ConfirmDecommissioned bool `json:"confirmDecommissioned"`
}
type CleanupApplyEvent struct {
	Step   int       `json:"step"`
	DN     string    `json:"dn,omitempty"`
	Status string    `json:"status"`
	Detail string    `json:"detail,omitempty"`
	Time   time.Time `json:"time"`
}
type CleanupApplyResult struct {
	ID     string              `json:"id"`
	Status string              `json:"status"`
	Events []CleanupApplyEvent `json:"events"`
}

func cleanupClass(o CleanupObject, class string) bool {
	for _, v := range o.Attributes["objectClass"] {
		if strings.EqualFold(string(v), class) {
			return true
		}
	}
	return false
}

// Only enumerated leaves and standard children of selected empty sites are
// supported, together with proven leaf remnants of permanently retired DCs.
// Existing DSA objects and arbitrary DC subtrees require a demotion workflow.
func cleanupOrder(p *CleanupPlan) ([]CleanupObject, error) {
	if len(p.Objects) == 0 || len(p.Objects) > 150 {
		return nil, topologyBad("invalid cleanup object count")
	}
	sites := map[string]bool{}
	for _, o := range p.Objects {
		if cleanupClass(o, "site") && len(o.Findings) > 0 {
			sites[dnKey(o.DN)] = true
		}
	}
	base, err := ldap.ParseDN(SitesContainerDN(p.BaseDN))
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, o := range p.Objects {
		if cleanupClass(o, "computer") && !cleanupDisabledDC(o) {
			return nil, topologyBad("remaining DC account must be disabled before cleanup")
		}
		dn, e := ldap.ParseDN(o.DN)
		if e != nil || (!base.AncestorOfFold(dn) && !cleanupRemnantAllowed(o, p.BaseDN) && !cleanupExtraAllowed(o, p)) || len(o.GUID) != 16 || seen[dnKey(o.DN)] {
			return nil, topologyBad("invalid cleanup object identity or location")
		}
		seen[dnKey(o.DN)] = true
		if _, e = assertion(o.USN); e != nil {
			return nil, e
		}
		parent, e := parentDN(o.DN)
		if e != nil {
			return nil, e
		}
		allowed := len(o.Findings) > 0 && (cleanupClass(o, "site") || cleanupClass(o, "siteLink") || cleanupClass(o, "nTDSConnection"))
		if sites[dnKey(parent)] && ((cleanupClass(o, "serversContainer") && strings.EqualFold(cnFromDN(o.DN), "Servers")) || (cleanupClass(o, "nTDSSiteSettings") && strings.EqualFold(cnFromDN(o.DN), "NTDS Site Settings"))) {
			allowed = true
		}
		if cleanupRemnantAllowed(o, p.BaseDN) || cleanupExtraAllowed(o, p) {
			allowed = true
		}
		if !allowed {
			return nil, topologyBad("unsupported cleanup object: " + o.DN)
		}
	}
	ordered := append([]CleanupObject(nil), p.Objects...)
	sort.Slice(ordered, func(i, j int) bool {
		if cleanupOperationRank(ordered[i]) != cleanupOperationRank(ordered[j]) {
			return cleanupOperationRank(ordered[i]) < cleanupOperationRank(ordered[j])
		}
		a, _ := ldap.ParseDN(ordered[i].DN)
		b, _ := ldap.ParseDN(ordered[j].DN)
		if len(a.RDNs) != len(b.RDNs) {
			return len(a.RDNs) > len(b.RDNs)
		}
		return dnKey(ordered[i].DN) < dnKey(ordered[j].DN)
	})
	return ordered, nil
}

// Assert the entire enumerated subtree, including children not present in the
// original audit. New or unrecognised children block deletion.
func (s *SiteService) cleanupChildren(ctx context.Context, p *CleanupPlan) error {
	expected := map[string]bool{}
	for _, o := range p.Objects {
		expected[dnKey(o.DN)] = true
	}
	for _, o := range p.Objects {
		if len(o.Remove) > 0 {
			continue
		}
		scope := ldap.ScopeSingleLevel
		entries, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: o.DN, Scope: &scope, Filter: "(objectClass=*)", Attributes: []string{"objectGUID"}, MaxEntries: 151})
		if e != nil {
			return e
		}
		for _, child := range entries {
			if !expected[dnKey(child.DN)] {
				return topologyBad("unplanned child: " + child.DN)
			}
		}
	}
	return nil
}

func (s *SiteService) ApplyCleanup(ctx context.Context, in CleanupApplyRequest, actor, ip string, repl *ReplService) (*CleanupApplyResult, error) {
	if !in.Confirm || !validBackupID(in.ID) || len(in.Revision) != 64 {
		return nil, topologyBad("explicit confirmation, backup ID and revision required")
	}
	if s.helpers == nil || repl == nil {
		return nil, topologyBad("helper and native replication service required")
	}
	p, e := s.PreviewCleanup(ctx, in.DNs)
	if e != nil {
		return nil, e
	}
	if p.Revision != in.Revision {
		return nil, ErrTopologyConflict
	}
	for _, o := range p.Objects {
		if cleanupDCRemnant(o) && !in.ConfirmDecommissioned {
			return nil, topologyBad("confirm permanent DC decommission before cleaning remnants")
		}
	}
	ordered, e := cleanupOrder(p)
	if e != nil {
		return nil, e
	}
	if e = s.checkDCRemnants(ctx, p); e != nil {
		return nil, e
	}
	if e = s.cleanupReferenceScan(ctx, p); e != nil {
		return nil, e
	}
	if e = s.cleanupChildren(ctx, p); e != nil {
		return nil, e
	}
	backup, e := s.DomainBackupStatus(ctx, in.Controller, in.ID)
	if e != nil {
		return nil, e
	}
	if e = validateCleanupBackup(p, backup); e != nil {
		return nil, e
	}
	domain, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: p.BaseDN, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(domain.GetRawAttributeValue("objectGUID"), backup.DomainGUID) {
		return nil, ErrTopologyConflict
	}
	controllers, e := s.Controllers(ctx)
	if e != nil {
		return nil, e
	}
	if len(controllers) < 2 || len(controllers) > 16 {
		return nil, topologyBad("cleanup requires 2–16 reachable controllers")
	}
	// Resolve the actual DSA identity; localhost and DNS aliases are valid
	// connection addresses but must never be mistaken for distinct controllers.
	conn, e := s.ldap.Conn(ctx)
	if e != nil {
		return nil, e
	}
	root, e := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"dsServiceName"}, nil))
	if e != nil {
		return nil, e
	}
	if len(root.Entries) != 1 {
		return nil, topologyBad("primary DSA identity unavailable")
	}
	primary := ""
	for _, dc := range controllers {
		if dnKey(dc.NTDS) == dnKey(root.Entries[0].GetAttributeValue("dsServiceName")) && !dc.RODC {
			primary = dc.DNS
		}
	}
	if primary == "" {
		return nil, topologyBad("primary writable DC identity not found")
	}

	survivors := []Controller{}
	for _, dc := range controllers {
		if cleanupRetiredController(p, dc) {
			if dc.RODC {
				return nil, topologyBad("retired RODC metadata requires a dedicated KDC-account cleanup workflow")
			}
			if e = checkRetiredOfflinePlan(ctx, dc.DNS, p); e != nil {
				return nil, e
			}
			if strings.EqualFold(dc.DNS, primary) {
				return nil, topologyBad("cannot remove the current LDAP controller")
			}
			continue
		}
		survivors = append(survivors, dc)
	}
	if len(survivors) < 2 {
		return nil, topologyBad("at least two surviving RWDCs required")
	}
	controllers = survivors
	for _, dc := range controllers {
		if dc.RODC {
			return nil, topologyBad("cleanup with RODC replicas is not yet supported")
		}
		if !strings.EqualFold(dc.DNS, primary) {
			checks, err := s.CheckCleanup(ctx, CleanupChecksRequest{CleanupRequest: in.CleanupRequest, Peer: dc.DNS})
			if err != nil {
				return nil, err
			}
			for _, check := range checks.Checks {
				if check.ID != "apply" && check.Status != "ok" {
					return nil, topologyBad(dc.DNS + ": " + check.ID + ": " + check.Detail)
				}
			}
			uri, err := consistencyPeerURI(s.ldap.URI(), dc.DNS)
			if err != nil {
				return nil, err
			}
			peer := s.ldap.ServicePeer(uri)
			err = (&SiteService{ldap: peer}).checkDCRemnants(ctx, p)
			if err == nil {
				err = (&SiteService{ldap: peer}).cleanupChildren(ctx, p)
			}
			if err == nil {
				err = (&SiteService{ldap: peer}).cleanupReferenceScan(ctx, p)
			}
			peer.Close()
			if err != nil {
				return nil, err
			}
		}
		status, err := repl.StatusFor(ctx, dc.DNS)
		if err != nil {
			return nil, err
		}
		if !cleanupReplicationHealthy(status, p) {
			return nil, topologyBad("replication is not healthy on " + dc.DNS)
		}
	}
	// Repeat the primary snapshot after network checks, then atomically consume
	// this backup's application slot through helper before the first LDAP write.
	latest, e := s.PreviewCleanup(ctx, in.DNs)
	if e != nil {
		return nil, e
	}
	if latest.Revision != p.Revision {
		return nil, ErrTopologyConflict
	}
	retirement := ""
	if in.ConfirmDecommissioned {
		retirement = "permanently-decommissioned"
	}
	var reserved map[string]any
	if e = s.helpers.Call(ctx, backup.Controller, "topology.cleanup.reserve", HostOperation{Name: in.ID, Revision: in.Revision, Value: retirement, Actor: actor, IP: ip}, &reserved); e != nil {
		return nil, e
	}
	out := &CleanupApplyResult{ID: in.ID, Status: "applying", Events: []CleanupApplyEvent{}}
	record := func(dn, status, detail string) error {
		event := CleanupApplyEvent{Step: len(out.Events), DN: dn, Status: status, Detail: detail, Time: time.Now().UTC()}
		var saved CleanupApplyEvent
		err := s.helpers.Call(ctx, backup.Controller, "topology.cleanup.event", HostOperation{Name: in.ID, Input: hostInput(event), Actor: actor, IP: ip}, &saved)
		if err == nil {
			out.Events = append(out.Events, event)
		}
		return err
	}
	stop := func(err error) (*CleanupApplyResult, error) {
		out.Status = "stopped"
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		event := CleanupApplyEvent{Step: len(out.Events), Status: "stopped", Detail: err.Error(), Time: time.Now().UTC()}
		var saved CleanupApplyEvent
		if logErr := s.helpers.Call(recovery, backup.Controller, "topology.cleanup.event", HostOperation{Name: in.ID, Input: hostInput(event), Actor: actor, IP: ip}, &saved); logErr == nil {
			out.Events = append(out.Events, event)
		}
		if s.audit != nil {
			s.audit.Failure(actor, "topology.cleanup.apply", in.ID, ip, err)
		}
		// Return the partial result; the caller must not retry an uncertain deletion.
		return out, nil
	}
	for _, o := range ordered {
		if cleanupClass(o, "nTDSDSA") {
			if e = s.revalidateRetiredNTDS(ctx, p, o); e != nil {
				return stop(e)
			}
		}
		before, after := "deleting", "deleted"
		if len(o.Remove) > 0 {
			before, after = "updating", "updated"
		}
		if e = record(o.DN, before, ""); e != nil {
			return stop(e)
		}
		if len(o.Remove) > 0 {
			e = cleanupModify(ctx, s.ldap, o)
		} else {
			e = topologyDelete(ctx, s.ldap, o.DN, o.USN)
		}
		if e != nil {
			return stop(e)
		}
		if e = record(o.DN, after, ""); e != nil {
			return stop(e)
		}
	}
	for _, dc := range controllers {
		if !strings.EqualFold(dc.DNS, primary) {
			for _, nc := range []string{ConfigDN(p.BaseDN), p.BaseDN, "DC=DomainDnsZones," + p.BaseDN, "DC=ForestDnsZones," + p.BaseDN} {
				if e = repl.Sync(ctx, dc.DNS, primary, nc, actor, ip); e != nil {
					return stop(e)
				}
			}
		}
		uri, err := consistencyPeerURI(s.ldap.URI(), dc.DNS)
		if err != nil {
			return stop(err)
		}
		peer := s.ldap.ServicePeer(uri)
		for _, o := range ordered {
			if len(o.Remove) > 0 {
				if err = verifyCleanupModification(ctx, peer, o); err != nil {
					peer.Close()
					return stop(err)
				}
				continue
			}
			_, err = peer.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: o.DN, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
			if !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				peer.Close()
				return stop(fmt.Errorf("deletion not confirmed on %s: %s", dc.DNS, o.DN))
			}
		}
		peer.Close()
	}
	// Refresh local, non-replicated repsFrom/repsTo state after metadata
	// convergence. Do not declare success with dead DSA neighbours still present.
	for _, dc := range controllers {
		if e = repl.KCC(ctx, dc.DNS, actor, ip); e != nil {
			return stop(e)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			status, err := repl.StatusFor(ctx, dc.DNS)
			if err == nil && status.Health == "healthy" {
				break
			}
			if err != nil {
				return stop(err)
			}
			if time.Now().After(deadline) {
				return stop(topologyBad("replication still degraded after KCC on " + dc.DNS))
			}
			select {
			case <-ctx.Done():
				return stop(ctx.Err())
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	if e = record("", "completed", "Cleanup verified on every surviving RWDC; unrelated values preserved"); e != nil {
		return stop(e)
	}
	out.Status = "completed"
	if s.audit != nil {
		s.audit.Success(actor, "topology.cleanup.apply", in.ID, ip)
	}
	return out, nil
}
func validateCleanupBackup(p *CleanupPlan, b *DomainBackupJob) error {
	if b.Status != "backed_up" || !b.RestoreVerified || b.PlanRevision != p.Revision || b.Plan == nil || cleanupRevision(b.Plan) != p.Revision || dnKey(b.BaseDN) != dnKey(p.BaseDN) || b.Finished.IsZero() || time.Since(b.Finished) > 24*time.Hour || b.Finished.After(time.Now().Add(time.Minute)) {
		return topologyBad("matching backup with verified isolated restore, less than 24 hours old, required")
	}
	return nil
}

// Inspect all DN-valued schema attributes in every naming context hosted by
// the replica. Referrals, incomplete permissions or unavailable partitions fail
// closed through LDAP errors. Multi-domain forests require a separate workflow.
func (s *SiteService) cleanupReferenceScan(ctx context.Context, p *CleanupPlan) error {
	domains, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: "CN=Partitions," + ConfigDN(p.BaseDN), Filter: "(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))", Attributes: []string{"nCName"}, MaxEntries: 100})
	if e != nil {
		return e
	}
	if len(domains) != 1 || dnKey(domains[0].GetAttributeValue("nCName")) != dnKey(p.BaseDN) {
		return topologyBad("cleanup currently supports a single-domain forest only")
	}
	schema, e := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: "CN=Schema," + ConfigDN(p.BaseDN), Filter: "(&(objectClass=attributeSchema)(attributeSyntax=2.5.5.1))", Attributes: []string{"lDAPDisplayName", "linkID"}, MaxEntries: 1000})
	if e != nil {
		return e
	}
	// Odd linkIDs are computed backlinks. Their authoritative forward links
	// live on the selected object and disappear with it; do not mutate backlinks.
	forward := schema[:0]
	for _, attr := range schema {
		value := attr.GetAttributeValue("linkID")
		if value != "" {
			id, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return topologyBad("invalid reference schema linkID")
			}
			if id&1 != 0 {
				continue
			}
		}
		forward = append(forward, attr)
	}
	schema = forward
	if len(schema) == 0 {
		return topologyBad("DN reference schema unavailable")
	}
	conn, e := s.ldap.Conn(ctx)
	if e != nil {
		return e
	}
	root, e := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false, "(objectClass=*)", []string{"namingContexts"}, nil))
	if e != nil {
		return e
	}
	if len(root.Entries) != 1 {
		return topologyBad("replica naming contexts unavailable")
	}
	contexts := root.Entries[0].GetAttributeValues("namingContexts")
	if len(contexts) < 3 || len(contexts) > 16 {
		return topologyBad("unexpected replica naming contexts")
	}
	selected := map[string]bool{}
	for _, o := range p.Objects {
		selected[dnKey(o.DN)] = true
	}
	for _, o := range p.Objects {
		if len(o.Remove) > 0 {
			continue
		}
		filters := []string{}
		for _, attr := range schema {
			name := attr.GetAttributeValue("lDAPDisplayName")
			if name == "" {
				return topologyBad("incomplete reference schema")
			}
			// LDAP attribute names are identifiers, not arbitrary filter fragments.
			for _, r := range name {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
					return topologyBad("invalid reference attribute")
				}
			}
			filters = append(filters, "("+name+"="+ldap.EscapeFilter(o.DN)+")")
		}
		for _, nc := range contexts {
			refs, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: nc, Filter: "(|" + strings.Join(filters, "") + ")", Attributes: cleanupReferenceNames(schema), MaxEntries: 1000})
			if err != nil {
				return err
			}
			for _, ref := range refs {
				if selected[dnKey(ref.DN)] && cleanupHasDN(p, ref.DN) {
					continue
				}
				for _, attribute := range ref.Attributes {
					for _, value := range attribute.Values {
						if dnKey(value) == dnKey(o.DN) && !cleanupPlannedReference(p, ref.DN, attribute.Name, value) {
							return topologyBad("reference from " + ref.DN + " to " + o.DN)
						}
					}
				}
			}
		}
	}
	return nil
}
