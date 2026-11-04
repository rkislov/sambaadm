package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/go-ldap/ldap/v3"
	"sort"
	"time"

	ldapproto "sambaadm/internal/ldap"
)

// CleanupPlan is a read-only preparation artifact, never an authorization to delete.
type CleanupPlan struct {
	Format     int             `json:"format"`
	Revision   string          `json:"revision"`
	LDAPServer string          `json:"ldapServer"`
	BaseDN     string          `json:"baseDN"`
	Observed   time.Time       `json:"observed"`
	Objects    []CleanupObject `json:"objects"`
	Blockers   []string        `json:"blockers"`
	CanApply   bool            `json:"canApply"`
}
type CleanupObject struct {
	DN         string              `json:"dn"`
	GUID       []byte              `json:"guid"`
	USN        string              `json:"usn"`
	Attributes map[string][][]byte `json:"attributes"`
	Findings   []TopologyFinding   `json:"findings"`
	Remove     map[string][][]byte `json:"remove,omitempty"`
}
type CleanupRequest struct {
	DNs      []string `json:"dns"`
	Revision string   `json:"revision,omitempty"`
}

// Explicit allowlist excludes secrets and DC-local RID counters (rIDNextRID,
// rIDPreviousAllocationPool), which must not be compared across replicas.
var cleanupAttributes = []string{"objectClass", "objectGUID", "uSNChanged", "whenChanged", "cn", "name", "description", "serverReference", "fromServer", "siteObject", "siteList", "dNSHostName", "options", "enabledConnection", "schedule", "cost", "replInterval", "userAccountControl", "sAMAccountName", "servicePrincipalName", "objectSid", "hasMasterNCs", "msDS-HasMasterNCs", "msDS-HasFullReplicaNCs", "msDS-HasDomainNCs", "msDS-HasInstantiatedNCs", "invocationId", "objectCategory", "msDS-Behavior-Version", "rIDSetReferences", "rIDAllocationPool", "rIDUsedPool", "msDFSR-ComputerReference", "msDFSR-PartnerReference", "msDFSR-MemberReference", "msDFSR-Enabled", "msDFSR-RootPath", "msDFSR-StagingPath", "msDFSR-ContentSetGuid", "msDFSR-ReplicationGroupGuid", "msDS-NC-Replica-Locations", "msDS-NC-RO-Replica-Locations", "interSiteTopologyGenerator", "dnsRecord", "dNSTombstoned", "dc"}

func validateCleanupSelection(dns []string) error {
	if len(dns) == 0 || len(dns) > 50 {
		return topologyBad("select between 1 and 50 findings")
	}
	seen := map[string]bool{}
	for _, dn := range dns {
		if len(dn) > 4096 {
			return topologyBad("DN too long")
		}
		if _, err := parentDN(dn); err != nil {
			return err
		}
		key := dnKey(dn)
		if seen[key] {
			return topologyBad("duplicate DN")
		}
		seen[key] = true
	}
	return nil
}
func cleanupRevision(p *CleanupPlan) string {
	// Observation times do not affect identity; source, findings and raw attributes do.
	b, _ := json.Marshal(struct {
		Server, Base string
		Objects      []CleanupObject
		Blockers     []string
	}{p.LDAPServer, p.BaseDN, p.Objects, p.Blockers})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s *SiteService) PreviewCleanup(ctx context.Context, dns []string) (*CleanupPlan, error) {
	if err := validateCleanupSelection(dns); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	audit := s.AuditTopology(ctx)
	if audit.Status != "complete" {
		return nil, topologyBad("incomplete audit; cleanup preparation blocked")
	}
	findings := map[string][]TopologyFinding{}
	for _, f := range audit.Findings {
		findings[dnKey(f.DN)] = append(findings[dnKey(f.DN)], f)
	}
	p := &CleanupPlan{Format: 1, LDAPServer: audit.LDAPServer, BaseDN: audit.BaseDN, Observed: time.Now().UTC(), Objects: []CleanupObject{}, Blockers: []string{
		"Application requires a verified backup and fresh checks; retired DC remnants require separate confirmation. NTDS/RID/DFSR and DNS changes must be explicitly enumerated and verified on surviving controllers.",
		"Confirmation on another RWDC, dependency/FSMO/replication checks and decommission history are required.",
		"This selective snapshot excludes secrets, ACLs and unselected objects; it is not a restorable domain backup.",
		"A supported domain backup and a successful isolated cleanup/restore rehearsal are required.",
	}}
	for _, dn := range dns {
		fs := findings[dnKey(dn)]
		if len(fs) == 0 {
			return nil, topologyBad("selected object is not a current finding")
		}
		e, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: cleanupAttributes, MaxEntries: 1})
		if err != nil {
			return nil, err
		}
		guid := e.GetRawAttributeValue("objectGUID")
		usn := e.GetAttributeValue("uSNChanged")
		if len(guid) != 16 || usn == "" {
			return nil, topologyBad("object identity or revision unavailable")
		}
		if _, err := assertion(usn); err != nil {
			return nil, err
		}
		attrs := map[string][][]byte{}
		for _, name := range cleanupAttributes {
			if v := e.GetRawAttributeValues(name); len(v) > 0 {
				attrs[name] = v
			}
		}
		p.Objects = append(p.Objects, CleanupObject{DN: e.DN, GUID: guid, USN: usn, Attributes: attrs, Findings: fs})
	}
	// A server without DSA metadata may still reference its retired account.
	// Include that exact account in the reviewable plan; never follow arbitrary
	// descendants or infer retirement from network failure.
	initial := append([]CleanupObject(nil), p.Objects...)
	for _, o := range initial {
		if !cleanupClass(o, "server") || (!cleanupFinding(o, "server_without_ntds") && !cleanupFinding(o, "disabled_dc_metadata") && !cleanupFinding(o, "server_computer_reference") && !cleanupFinding(o, "server_without_computer")) {
			continue
		}
		for _, raw := range o.Attributes["serverReference"] {
			dn := string(raw)
			present := false
			for _, existing := range p.Objects {
				if dnKey(existing.DN) == dnKey(dn) {
					present = true
				}
			}
			if present {
				continue
			}
			entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=computer)", Attributes: cleanupAttributes, MaxEntries: 1})
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				continue
			}
			if err != nil {
				return nil, err
			}
			attrs := map[string][][]byte{}
			for _, name := range cleanupAttributes {
				if values := entry.GetRawAttributeValues(name); len(values) > 0 {
					attrs[name] = values
				}
			}
			p.Objects = append(p.Objects, CleanupObject{DN: entry.DN, GUID: entry.GetRawAttributeValue("objectGUID"), USN: entry.GetAttributeValue("uSNChanged"), Attributes: attrs, Findings: []TopologyFinding{{DN: entry.DN, Code: "retired_server_computer", Severity: "review", Reference: o.DN, Detail: "Account referenced by selected server without NTDS; must be disabled and retirement confirmed"}}})
		}
	}
	// Include only standard direct children of a selected site. They are visible
	// in the preview and bound into its revision; no subtree-delete control is used.
	selected := append([]CleanupObject(nil), p.Objects...)
	for _, o := range selected {
		if !cleanupClass(o, "site") {
			continue
		}
		scope := 1
		children, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: o.DN, Scope: &scope, Filter: "(objectClass=*)", Attributes: cleanupAttributes, MaxEntries: 100})
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			attrs := map[string][][]byte{}
			for _, name := range cleanupAttributes {
				if v := child.GetRawAttributeValues(name); len(v) > 0 {
					attrs[name] = v
				}
			}
			p.Objects = append(p.Objects, CleanupObject{DN: child.DN, GUID: child.GetRawAttributeValue("objectGUID"), USN: child.GetAttributeValue("uSNChanged"), Attributes: attrs})
		}
	}
	if err := s.expandRetiredMetadata(ctx, p); err != nil {
		return nil, err
	}
	sort.Slice(p.Objects, func(i, j int) bool { return dnKey(p.Objects[i].DN) < dnKey(p.Objects[j].DN) })
	p.Revision = cleanupRevision(p)
	return p, nil
}
func (s *SiteService) ArchiveCleanup(ctx context.Context, in CleanupRequest, actor, ip string) (*CleanupReceipt, error) {
	if len(in.Revision) != 64 {
		return nil, topologyBad("preview revision required")
	}
	p, err := s.PreviewCleanup(ctx, in.DNs)
	if err != nil {
		return nil, err
	}
	if p.Revision != in.Revision {
		return nil, ErrTopologyConflict
	}
	if s.helpers == nil {
		return nil, topologyBad("helper is not configured")
	}
	var receipt CleanupReceipt
	err = s.helpers.Call(ctx, s.helpers.Config.HostNode, "topology.snapshot.store", HostOperation{Input: hostInput(p), Actor: actor, IP: ip}, &receipt)
	if err != nil {
		return nil, err
	}
	// Read-back through the transport verifies the persisted bytes, not just write success.
	var saved CleanupPlan
	err = s.helpers.Call(ctx, s.helpers.Config.HostNode, "topology.snapshot.load", HostOperation{Name: receipt.ID, Revision: receipt.SHA256}, &saved)
	if err != nil {
		return nil, err
	}
	if saved.Revision != p.Revision || cleanupRevision(&saved) != p.Revision {
		return nil, ErrTopologyConflict
	}
	if s.audit != nil {
		s.audit.Success(actor, "topology.snapshot", receipt.ID+" "+receipt.SHA256, ip)
	}
	receipt.Verified = true
	return &receipt, nil
}
