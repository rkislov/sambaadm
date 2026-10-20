package service

import (
	"context"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"net"
	ldapproto "sambaadm/internal/ldap"
	"strconv"
	"strings"
)

func (s *DomainService) roleDN(role string) (string, error) {
	base := s.ldap.BaseDN()
	roles := map[string]string{"schema": SchemaDN(base), "naming": "CN=Partitions," + ConfigDN(base), "pdc": base, "rid": "CN=RID Manager$,CN=System," + base, "infrastructure": "CN=Infrastructure," + base, "domaindns": "CN=Infrastructure,DC=DomainDnsZones," + base, "forestdns": "CN=Infrastructure,DC=ForestDnsZones," + base}
	if dn := roles[normalizeFSMORole(role)]; dn != "" {
		return dn, nil
	}
	return "", fmt.Errorf("unknown FSMO role")
}
func (s *DomainService) changeFSMO(ctx context.Context, role, actor, ip string, seize bool) error {
	role = normalizeFSMORole(role)
	if role == "all" {
		for _, r := range []string{"schema", "naming", "pdc", "rid", "infrastructure", "domaindns", "forestdns"} {
			if err := s.changeFSMO(ctx, r, actor, ip, seize); err != nil {
				return fmt.Errorf("role %s: %w", r, err)
			}
		}
		return nil
	}
	dn, err := s.roleDN(role)
	if err != nil {
		return err
	}
	conn, err := s.ldap.Conn(ctx)
	if err != nil {
		return err
	}
	root, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{"dsServiceName"}, nil))
	if err != nil {
		return err
	}
	if len(root.Entries) != 1 {
		return fmt.Errorf("missing RootDSE")
	}
	target := root.Entries[0].GetAttributeValue("dsServiceName")
	if target == "" {
		return fmt.Errorf("missing target DSA")
	}
	entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"fSMORoleOwner", "uSNChanged"}})
	if err != nil {
		return err
	}
	if strings.EqualFold(entry.GetAttributeValue("fSMORoleOwner"), target) {
		return nil
	}
	attr := map[string]string{"schema": "becomeSchemaMaster", "naming": "becomeDomainMaster", "pdc": "becomePdc", "rid": "becomeRidMaster", "infrastructure": "becomeInfrastructureMaster"}[role]
	if attr == "" && !seize {
		return s.transferDNSRole(ctx, dn, entry.GetAttributeValue("fSMORoleOwner"), target, role, actor, ip)
	}
	value := "1"
	if role == "pdc" {
		domain, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: s.ldap.BaseDN(), Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"objectSid"}})
		if e != nil {
			return e
		}
		value = string(domain.GetRawAttributeValue("objectSid"))
	}
	if attr != "" {
		req := ldap.NewModifyRequest("", nil)
		req.Replace(attr, []string{value})
		err = conn.Modify(req)
	}
	if seize && (err != nil || attr == "") {
		if role == "rid" {
			serverDN, e := parentDN(target)
			if e != nil {
				return e
			}
			server, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: serverDN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=server)", Attributes: []string{"serverReference"}})
			if e != nil {
				return e
			}
			computerDN := server.GetAttributeValue("serverReference")
			if computerDN == "" {
				return fmt.Errorf("target DC computer reference missing")
			}
			computer, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: computerDN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=computer)", Attributes: []string{"rIDSetReferences"}})
			if e != nil {
				return e
			}
			if computer.GetAttributeValue("rIDSetReferences") == "" {
				return fmt.Errorf("RID seizure requires an initialized RID set on the target DC")
			}
		}
		err = topologyModify(ctx, s.ldap, dn, entry.GetAttributeValue("uSNChanged"), map[string][]string{"fSMORoleOwner": {target}})
	}
	action := "fsmo.transfer"
	if seize {
		action = "fsmo.seize"
	}
	if err != nil {
		s.audit.Failure(actor, action, role, ip, err)
		return err
	}
	s.audit.Success(actor, action, role, ip)
	return nil
}
func (s *DomainService) levelNative(ctx context.Context) (*DomainLevel, error) {
	read := func(dn string) (string, error) {
		entry, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"msDS-Behavior-Version"}})
		if e != nil {
			return "", e
		}
		return entry.GetAttributeValue("msDS-Behavior-Version"), nil
	}
	domain, e := read(s.ldap.BaseDN())
	if e != nil {
		return nil, e
	}
	forest, e := read("CN=Partitions," + ConfigDN(s.ldap.BaseDN()))
	if e != nil {
		return nil, e
	}
	return &DomainLevel{Domain: domain, Forest: forest, Raw: "LDAP msDS-Behavior-Version: domain=" + domain + " forest=" + forest}, nil
}
func (s *DomainService) raiseNative(ctx context.Context, domain, forest, actor, ip string) error {
	levels := map[string]int{"2000": 0, "2003": 2, "2008": 3, "2008_R2": 4, "2012": 5, "2012_R2": 6, "2016": 7}
	if domain == "" && forest == "" {
		return fmt.Errorf("specify domain and/or forest level")
	}
	current, err := s.levelNative(ctx)
	if err != nil {
		return err
	}
	oldDomain, err := strconv.Atoi(current.Domain)
	if err != nil {
		return err
	}
	oldForest, err := strconv.Atoi(current.Forest)
	if err != nil {
		return err
	}
	wantedDomain, wantedForest := oldDomain, oldForest
	if domain != "" {
		v, ok := levels[strings.ToUpper(domain)]
		if !ok {
			return fmt.Errorf("unsupported domain level")
		}
		wantedDomain = v
	}
	if forest != "" {
		v, ok := levels[strings.ToUpper(forest)]
		if !ok {
			return fmt.Errorf("unsupported forest level")
		}
		wantedForest = v
	}
	if wantedDomain < oldDomain || wantedForest < oldForest {
		return fmt.Errorf("functional level cannot be lowered")
	}
	dcs, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: ConfigDN(s.ldap.BaseDN()), Filter: "(objectClass=nTDSDSA)", Attributes: []string{"msDS-Behavior-Version"}})
	if err != nil {
		return err
	}
	if len(dcs) == 0 {
		return fmt.Errorf("no DCs found")
	}
	for _, dc := range dcs {
		v, e := strconv.Atoi(dc.GetAttributeValue("msDS-Behavior-Version"))
		if e != nil || v < wantedDomain {
			return fmt.Errorf("DC %s does not support requested level", dc.DN)
		}
	}
	if wantedForest > wantedDomain {
		return fmt.Errorf("forest level exceeds domain level")
	}
	// The directory server validates forest-wide prerequisites, permissions and schema.
	for _, item := range []struct {
		dn        string
		old, next int
	}{{s.ldap.BaseDN(), oldDomain, wantedDomain}, {"CN=Partitions," + ConfigDN(s.ldap.BaseDN()), oldForest, wantedForest}} {
		if item.old == item.next {
			continue
		}
		req := ldap.NewModifyRequest(item.dn, nil)
		req.Replace("msDS-Behavior-Version", []string{strconv.Itoa(item.next)})
		if err := s.ldap.Modify(ctx, req); err != nil {
			s.audit.Failure(actor, "domain.level.raise", item.dn, ip, err)
			return err
		}
	}
	s.audit.Success(actor, "domain.level.raise", domain+"/"+forest, ip)
	return nil
}

func (s *DomainService) transferDNSRole(ctx context.Context, dn, owner, target, role, actor, ip string) error {
	if owner == "" {
		return fmt.Errorf("role has no owner; explicit seizure required")
	}
	serverDN, err := parentDN(owner)
	if err != nil {
		return err
	}
	server, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: serverDN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=server)", Attributes: []string{"dNSHostName"}})
	if err != nil {
		return err
	}
	host := server.GetAttributeValue("dNSHostName")
	if host == "" {
		return fmt.Errorf("role owner DNS name unavailable")
	}
	peer := s.ldap.ServicePeer("ldaps://" + net.JoinHostPort(host, "636"))
	defer peer.Close()
	req := ldap.NewModifyRequest(dn, nil)
	req.Delete("fSMORoleOwner", []string{owner})
	req.Add("fSMORoleOwner", []string{target})
	if err = peer.Modify(ctx, req); err != nil {
		s.audit.Failure(actor, "fsmo.transfer", role, ip, err)
		return err
	}
	repl := &ReplService{ldap: s.ldap, audit: s.audit, remote: s.remote}
	if err := repl.Sync(ctx, hostnameFromURI(s.ldap.URI()), host, strings.TrimPrefix(dn, "CN=Infrastructure,"), actor, ip); err != nil {
		return fmt.Errorf("role owner changed; replication to new owner failed: %w", err)
	}
	s.audit.Success(actor, "fsmo.transfer", role, ip)
	return nil
}
