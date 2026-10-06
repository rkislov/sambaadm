package web

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/auth"
	ldapproto "sambaadm/internal/ldap"
)

// resolveLoginIdentity looks up DN and memberOf for an authenticated user
// and maps groups to an RBAC role.
func (s *Server) resolveLoginIdentity(ctx context.Context, username string) (dn string, role auth.Role, err error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return "", auth.RoleReadonly, fmt.Errorf("empty username")
	}

	esc := ldap.EscapeFilter(username)
	filter := fmt.Sprintf(
		"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=%s)(userPrincipalName=%s)))",
		esc, esc,
	)
	// Bare login without @ — also try UPN with domain from base DN.
	if !strings.Contains(username, "@") {
		if domain := dnsFromBaseDN(s.ldap.BaseDN()); domain != "" {
			upn := ldap.EscapeFilter(username + "@" + domain)
			filter = fmt.Sprintf(
				"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=%s)(userPrincipalName=%s)))",
				esc, upn,
			)
		}
	}

	entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{
		Filter:     filter,
		Attributes: []string{ldapproto.AttrSAMAccountName, ldapproto.AttrMemberOf, ldapproto.AttrDN},
	})
	if err != nil {
		// Bind succeeded but directory lookup failed — fall back safely.
		return username, s.rbac.Resolve(nil), fmt.Errorf("identity lookup: %w", err)
	}
	role = s.rbac.Resolve(entry.GetAttributeValues(ldapproto.AttrMemberOf))
	return entry.DN, role, nil
}

func dnsFromBaseDN(base string) string {
	var parts []string
	for _, p := range strings.Split(base, ",") {
		p = strings.TrimSpace(p)
		if len(p) >= 3 && strings.EqualFold(p[:3], "DC=") {
			parts = append(parts, p[3:])
		}
	}
	return strings.Join(parts, ".")
}
