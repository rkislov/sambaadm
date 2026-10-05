package service

import (
	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

// Services aggregates domain services shared by CLI and HTTP.
type Services struct {
	Users     *UserService
	Groups    *GroupService
	Computers *ComputerService
	OU        *OUService
	Trusts    *TrustService
	Domain    *DomainService
	Repl      *ReplService
	DNS       *DNSService
	GPO       *GPOService
	Audit     *audit.Logger
}

// New builds the service layer on top of an LDAP client.
func New(ldap *ldapproto.Client, auditLog *audit.Logger) *Services {
	return &Services{
		Users:     &UserService{ldap: ldap, audit: auditLog},
		Groups:    &GroupService{ldap: ldap, audit: auditLog},
		Computers: &ComputerService{ldap: ldap, audit: auditLog},
		OU:        &OUService{ldap: ldap, audit: auditLog},
		Trusts:    &TrustService{ldap: ldap, audit: auditLog},
		Domain:    &DomainService{ldap: ldap, audit: auditLog},
		Repl:      &ReplService{ldap: ldap, audit: auditLog},
		DNS:       &DNSService{ldap: ldap, audit: auditLog},
		GPO:       &GPOService{ldap: ldap, audit: auditLog},
		Audit:     auditLog,
	}
}
