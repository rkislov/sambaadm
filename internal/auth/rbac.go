package auth

import (
	"strings"

	"sambaadm/internal/config"
)

// RBAC resolves a user's role from group membership DNs.
type RBAC struct {
	adminDNs    []string
	helpdeskDNs []string
}

// NewRBAC builds an RBAC resolver from config role group DNs.
func NewRBAC(roles config.RolesConfig) *RBAC {
	return &RBAC{
		adminDNs:    normalizeDNs(roles.Admins),
		helpdeskDNs: normalizeDNs(roles.Helpdesk),
	}
}

// Configured reports whether any role groups are defined.
func (r *RBAC) Configured() bool {
	return r != nil && (len(r.adminDNs) > 0 || len(r.helpdeskDNs) > 0)
}

// Resolve returns the highest role matching memberOf groups.
// Default is readonly when authenticated but not in elevated groups.
func (r *RBAC) Resolve(memberOf []string) Role {
	if r == nil || !r.Configured() {
		return RoleAdmin
	}
	normalized := normalizeDNs(memberOf)
	for _, g := range normalized {
		for _, admin := range r.adminDNs {
			if g == admin {
				return RoleAdmin
			}
		}
	}
	for _, g := range normalized {
		for _, hd := range r.helpdeskDNs {
			if g == hd {
				return RoleHelpdesk
			}
		}
	}
	return RoleReadonly
}

// CanRead is true for any authenticated role.
func CanRead(role Role) bool {
	return role == RoleReadonly || role == RoleHelpdesk || role == RoleAdmin
}

// CanHelpdesk covers password reset / unlock.
func CanHelpdesk(role Role) bool {
	return role == RoleHelpdesk || role == RoleAdmin
}

// CanAdmin covers full mutating operations.
func CanAdmin(role Role) bool {
	return role == RoleAdmin
}

func normalizeDNs(dns []string) []string {
	out := make([]string, 0, len(dns))
	for _, dn := range dns {
		out = append(out, strings.ToLower(strings.TrimSpace(dn)))
	}
	return out
}
