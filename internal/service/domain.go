package service

import (
	"context"
	"fmt"
	"strings"

	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/samba"
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
	Source string `json:"source,omitempty"` // ldap | samba-tool
}

// DomainLevel describes domain/forest functional levels.
type DomainLevel struct {
	Raw    string `json:"raw,omitempty"`
	Domain string `json:"domain,omitempty"`
	Forest string `json:"forest,omitempty"`
}

// DomainService exposes domain / FSMO operations.
type DomainService struct {
	ldap  *ldapproto.Client
	audit *audit.Logger
	tool  *samba.Runner
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
	if err == nil && len(entries) > 0 {
		e := entries[0]
		info.NetBIOS = e.GetAttributeValue("dc")
		info.DNSRoot = e.GetAttributeValue("name")
		info.FunctionLvl = e.GetAttributeValue("msDS-Behavior-Version")
	}
	return info, nil
}

// FSMOShow returns FSMO role owners. Prefers samba-tool; falls back to LDAP.
func (s *DomainService) FSMOShow(ctx context.Context) ([]FSMORole, error) {
	if s.tool != nil && s.tool.Available() {
		res, err := s.tool.Run(ctx, "fsmo", "show")
		if err == nil {
			return parseFSMOShow(res.Stdout), nil
		}
	}
	return s.fsmoFromLDAP(ctx)
}

// FSMOTransfer transfers a role via samba-tool.
func (s *DomainService) FSMOTransfer(ctx context.Context, role, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	role = normalizeFSMORole(role)
	if _, err := s.tool.Run(ctx, "fsmo", "transfer", "--role="+role); err != nil {
		s.audit.Failure(actor, "fsmo.transfer", role, ip, err)
		return err
	}
	s.audit.Success(actor, "fsmo.transfer", role, ip)
	return nil
}

// FSMOSeize seizes a role via samba-tool (last resort).
func (s *DomainService) FSMOSeize(ctx context.Context, role, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	role = normalizeFSMORole(role)
	if _, err := s.tool.Run(ctx, "fsmo", "seize", "--role="+role); err != nil {
		s.audit.Failure(actor, "fsmo.seize", role, ip, err)
		return err
	}
	s.audit.Success(actor, "fsmo.seize", role, ip)
	return nil
}

// LevelShow returns domain/forest functional level (samba-tool preferred).
func (s *DomainService) LevelShow(ctx context.Context) (*DomainLevel, error) {
	if s.tool != nil && s.tool.Available() {
		res, err := s.tool.Run(ctx, "domain", "level", "show")
		if err == nil {
			return parseDomainLevel(res.Stdout), nil
		}
	}
	info, err := s.Info(ctx)
	if err != nil {
		return nil, err
	}
	return &DomainLevel{Domain: info.FunctionLvl, Raw: "msDS-Behavior-Version=" + info.FunctionLvl}, nil
}

// LevelRaise raises domain and/or forest level via samba-tool.
func (s *DomainService) LevelRaise(ctx context.Context, domainLevel, forestLevel, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	args := []string{"domain", "level", "raise"}
	if domainLevel != "" {
		args = append(args, "--domain-level="+domainLevel)
	}
	if forestLevel != "" {
		args = append(args, "--forest-level="+forestLevel)
	}
	if len(args) == 3 {
		return fmt.Errorf("specify --domain-level and/or --forest-level")
	}
	target := strings.Join(args[3:], " ")
	if _, err := s.tool.Run(ctx, args...); err != nil {
		s.audit.Failure(actor, "domain.level.raise", target, ip, err)
		return err
	}
	s.audit.Success(actor, "domain.level.raise", target, ip)
	return nil
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
		owner := ""
		if err == nil && len(entries) > 0 {
			owner = entries[0].GetAttributeValue("fSMORoleOwner")
		}
		out = append(out, FSMORole{Role: r.name, Owner: owner, Source: "ldap"})
	}
	return out, nil
}

func (s *DomainService) requireTool() error {
	if s.tool == nil || !s.tool.Available() {
		return fmt.Errorf("samba-tool is not available on this host")
	}
	return nil
}

func parseFSMOShow(stdout string) []FSMORole {
	var out []FSMORole
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Typical: "SchemaMasterRole owner: CN=NTDS Settings,..."
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			out = append(out, FSMORole{Role: line, Source: "samba-tool"})
			continue
		}
		role := strings.TrimSpace(parts[0])
		role = strings.TrimSuffix(role, " owner")
		role = strings.TrimSuffix(role, " Role")
		out = append(out, FSMORole{
			Role:   strings.TrimSpace(role),
			Owner:  strings.TrimSpace(parts[1]),
			Source: "samba-tool",
		})
	}
	return out
}

func parseDomainLevel(stdout string) *DomainLevel {
	lvl := &DomainLevel{Raw: stdout}
	for _, line := range strings.Split(stdout, "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "domain") && strings.Contains(l, "level") {
			if i := strings.LastIndex(line, ":"); i >= 0 {
				lvl.Domain = strings.TrimSpace(line[i+1:])
			}
		}
		if strings.Contains(l, "forest") && strings.Contains(l, "level") {
			if i := strings.LastIndex(line, ":"); i >= 0 {
				lvl.Forest = strings.TrimSpace(line[i+1:])
			}
		}
	}
	return lvl
}

func normalizeFSMORole(role string) string {
	r := strings.ToLower(strings.TrimSpace(role))
	switch r {
	case "schema", "schemamaster", "schema_master":
		return "schema"
	case "naming", "domainnaming", "domain_naming", "domainnamingmaster":
		return "naming"
	case "pdc", "pdcemulator", "pdc_emulator":
		return "pdc"
	case "rid", "ridmaster", "rid_master":
		return "rid"
	case "infrastructure", "im", "infrastructuremaster":
		return "infrastructure"
	case "all":
		return "all"
	default:
		return r
	}
}
