package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

func (s *GPOService) policyEntry(ctx context.Context, policy string) (*ldap.Entry, error) {
	guid, err := s.resolveGUID(ctx, policy)
	if err != nil {
		return nil, err
	}
	return s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: "CN=" + ldap.EscapeDN(braceGUID(guid)) + ",CN=Policies,CN=System," + s.ldap.BaseDN(), Scope: ldapproto.ScopeBase(), Filter: "(objectClass=groupPolicyContainer)", Attributes: []string{"displayName", "name", "gPCFileSysPath", "versionNumber", "flags", "gPCFunctionalityVersion"}})
}

// Retain order and options of every unrelated link; reject malformed attributes
// rather than discarding entries we cannot interpret.
func editGPLink(raw, target string, remove bool) (string, error) {
	var out strings.Builder
	found := false
	rest := raw
	for rest != "" {
		if !strings.HasPrefix(rest, "[") {
			return "", fmt.Errorf("invalid gPLink attribute")
		}
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return "", fmt.Errorf("invalid gPLink attribute")
		}
		token := rest[:end+1]
		body := token[1 : len(token)-1]
		semi := strings.LastIndexByte(body, ';')
		if semi < 7 || len(body) < 7 || !strings.EqualFold(body[:7], "LDAP://") {
			return "", fmt.Errorf("invalid gPLink entry")
		}
		if _, err := strconv.ParseUint(body[semi+1:], 10, 32); err != nil {
			return "", fmt.Errorf("invalid gPLink options")
		}
		dn, err := ldap.ParseDN(body[7:semi])
		if err != nil {
			return "", err
		}
		want, err := ldap.ParseDN(target)
		if err != nil {
			return "", err
		}
		if dn.EqualFold(want) {
			found = true
			if !remove {
				out.WriteString(token)
			}
		} else {
			out.WriteString(token)
		}
		rest = rest[end+1:]
	}
	if !remove && !found {
		return "[LDAP://" + target + ";0]" + out.String(), nil
	}
	return out.String(), nil
}

func (s *GPOService) changeLink(ctx context.Context, containerDN, policy, actor, ip string, remove bool) error {
	entry, err := s.policyEntry(ctx, policy)
	if err != nil {
		return err
	}
	container, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: containerDN, Scope: ldapproto.ScopeBase(), Filter: "(|(objectClass=organizationalUnit)(objectClass=domainDNS)(objectClass=site))", Attributes: []string{"gPLink", "uSNChanged"}})
	if err != nil {
		return err
	}
	value, err := editGPLink(container.GetAttributeValue("gPLink"), entry.DN, remove)
	if err != nil {
		return err
	}
	action := "gpo.link"
	if remove {
		action = "gpo.unlink"
	}
	if value != container.GetAttributeValue("gPLink") {
		values := []string{value}
		if value == "" {
			values = nil
		}
		err = topologyModify(ctx, s.ldap, container.DN, container.GetAttributeValue("uSNChanged"), map[string][]string{"gPLink": values})
	}
	if err != nil {
		s.audit.Failure(actor, action, containerDN, ip, err)
		return err
	}
	s.audit.Success(actor, action, containerDN+" <- "+entry.DN, ip)
	return nil
}
