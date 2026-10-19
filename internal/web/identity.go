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
func (s *Server) resolveLoginIdentity(ctx context.Context, client *ldapproto.Client, username string) (dn string, role auth.Role, err error) {
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
		if domain := dnsFromBaseDN(client.BaseDN()); domain != "" {
			upn := ldap.EscapeFilter(username + "@" + domain)
			filter = fmt.Sprintf(
				"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=%s)(userPrincipalName=%s)))",
				esc, upn,
			)
		}
	}

	opts := ldapproto.SearchOptions{
		Filter:     filter,
		Attributes: []string{ldapproto.AttrSAMAccountName, ldapproto.AttrMemberOf, ldapproto.AttrDN},
	}
	entry, err := client.SearchOne(ctx, opts)
	// AD accepts a domain UPN for built-in accounts without a stored UPN.
	// Only use this fallback for the configured domain after an empty search.
	if local, domain, ok := strings.Cut(username, "@"); ok && local != "" &&
		strings.EqualFold(domain, dnsFromBaseDN(client.BaseDN())) && ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		opts.Filter = fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(local))
		entry, err = client.SearchOne(ctx, opts)
	}
	if err != nil {
		return "", auth.RoleReadonly, fmt.Errorf("identity lookup: %w", err)
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
