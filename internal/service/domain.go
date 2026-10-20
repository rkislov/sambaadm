package service

import (
	"context"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"strings"

	"sambaadm/internal/adremote"
	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// DomainInfo holds basic domain metadata.
type DomainInfo struct {
	DNSRoot     string `json:"dnsRoot,omitempty"`
	NetBIOS     string `json:"netbios,omitempty"`
	DomainSID   string `json:"domainSid,omitempty"`
	FunctionLvl string `json:"functionLevel,omitempty"`
	BaseDN      string `json:"baseDN"`
}

// FSMORole is a single FSMO role holder.
type FSMORole struct {
	Role   string `json:"role"`
	Owner  string `json:"owner,omitempty"`
	Source string `json:"source,omitempty"` // ldap
}

// DomainLevel describes domain/forest functional levels.
type DomainLevel struct {
	Raw    string `json:"raw,omitempty"`
	Domain string `json:"domain,omitempty"`
	Forest string `json:"forest,omitempty"`
}

// DomainService exposes domain / FSMO operations.
type DomainService struct {
	remote *adremote.Client
	ldap   *ldapproto.Client
	audit  *audit.Logger
}

// Info returns basic domain information.
func (s *DomainService) Info(ctx context.Context) (*DomainInfo, error) {
	info := &DomainInfo{BaseDN: s.ldap.BaseDN()}
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		BaseDN:     s.ldap.BaseDN(),
		Filter:     "(objectClass=domainDNS)",
		Scope:      ldapproto.ScopeBase(),
		Attributes: []string{"dc", "name", "objectSid", "msDS-Behavior-Version"},
		PageSize:   1,
	})
	if err != nil {
		return nil, err
	}
	if len(entries) != 1 {
		return nil, fmt.Errorf("domain not found")
	}
	e := entries[0]
	info.FunctionLvl = e.GetAttributeValue("msDS-Behavior-Version")
	var sid dtyp.SID
	if err := sid.DecodeBinary(e.GetRawAttributeValue("objectSid")); err != nil {
		return nil, err
	}
	info.DomainSID = sid.String()
	refs, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: "CN=Partitions," + ConfigDN(s.ldap.BaseDN()), Filter: "(&(objectClass=crossRef)(nCName=" + ldap.EscapeFilter(s.ldap.BaseDN()) + "))", Attributes: []string{"dnsRoot", "nETBIOSName"}})
	if err != nil {
		return nil, err
	}
	if len(refs) != 1 {
		return nil, fmt.Errorf("domain partition metadata unavailable")
	}
	info.NetBIOS = refs[0].GetAttributeValue("nETBIOSName")
	info.DNSRoot = refs[0].GetAttributeValue("dnsRoot")
	return info, nil
}

// FSMOShow returns FSMO role owners. Uses LDAP.
func (s *DomainService) FSMOShow(ctx context.Context) ([]FSMORole, error) {
	return s.fsmoFromLDAP(ctx)
}

// FSMOTransfer transfers a role through native protocols.
func (s *DomainService) FSMOTransfer(ctx context.Context, role, actor, ip string) error {
	return s.changeFSMO(ctx, role, actor, ip, false)
}

// FSMOSeize seizes a role through native protocols (last resort).
func (s *DomainService) FSMOSeize(ctx context.Context, role, actor, ip string) error {
	return s.changeFSMO(ctx, role, actor, ip, true)
}

// LevelShow returns domain/forest functional level through LDAP.
func (s *DomainService) LevelShow(ctx context.Context) (*DomainLevel, error) {
	return s.levelNative(ctx)
}

// LevelRaise raises domain and/or forest level through native protocols.
func (s *DomainService) LevelRaise(ctx context.Context, domainLevel, forestLevel, actor, ip string) error {
	return s.raiseNative(ctx, domainLevel, forestLevel, actor, ip)
}

func (s *DomainService) fsmoFromLDAP(ctx context.Context) ([]FSMORole, error) {
	base := s.ldap.BaseDN()
	cfg := ConfigDN(base)
	roles := []struct {
		name string
		dn   string
	}{
		{"SchemaMaster", SchemaDN(base)},
		{"DomainNamingMaster", "CN=Partitions," + cfg},
		{"PDC", base},
		{"RIDMaster", "CN=RID Manager$,CN=System," + base},
		{"InfrastructureMaster", "CN=Infrastructure," + base},
		{"DomainDnsZonesMaster", "CN=Infrastructure,DC=DomainDnsZones," + base},
		{"ForestDnsZonesMaster", "CN=Infrastructure,DC=ForestDnsZones," + base},
	}
	out := make([]FSMORole, 0, len(roles))
	for _, r := range roles {
		entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
			BaseDN:     r.dn,
			Filter:     "(objectClass=*)",
			Scope:      ldapproto.ScopeBase(),
			Attributes: []string{"fSMORoleOwner"},
			PageSize:   1,
		})
		if err != nil {
			return nil, err
		}
		if len(entries) != 1 {
			return nil, fmt.Errorf("missing role object %s", r.dn)
		}
		owner := entries[0].GetAttributeValue("fSMORoleOwner")
		out = append(out, FSMORole{Role: r.name, Owner: owner, Source: "ldap"})
	}
	return out, nil
}

func normalizeFSMORole(role string) string {
	r := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(role)), "role")
	switch r {
	case "schema", "schemamaster", "schema_master":
		return "schema"
	case "naming", "domainnaming", "domain_naming", "domainnamingmaster", "namingmaster":
		return "naming"
	case "pdc", "pdcemulator", "pdc_emulator", "pdcemulationmaster":
		return "pdc"
	case "rid", "ridmaster", "rid_master", "ridallocationmaster":
		return "rid"
	case "infrastructure", "im", "infrastructuremaster":
		return "infrastructure"
	case "domaindnszonesmaster":
		return "domaindns"
	case "forestdnszonesmaster":
		return "forestdns"
	case "all":
		return "all"
	default:
		return r
	}
}
