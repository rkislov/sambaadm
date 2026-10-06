package service

import (
	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/samba"
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
	Sites     *SiteService
	Subnets   *SubnetService
	DNS       *DNSService
	GPO       *GPOService
	Audit     *audit.Logger
	Tool      *samba.Runner
}

// Options configures service construction.
type Options struct {
	SambaTool string // path/name of samba-tool; empty = default
}

// New builds the service layer on top of an LDAP client.
func New(ldap *ldapproto.Client, auditLog *audit.Logger) *Services {
	return NewWithOptions(ldap, auditLog, Options{})
}

// NewWithOptions builds services with optional samba-tool path.
func NewWithOptions(ldap *ldapproto.Client, auditLog *audit.Logger, opts Options) *Services {
	tool := samba.NewRunner(opts.SambaTool)
	return &Services{
		Users:     &UserService{ldap: ldap, audit: auditLog},
		Groups:    &GroupService{ldap: ldap, audit: auditLog},
		Computers: &ComputerService{ldap: ldap, audit: auditLog},
		OU:        &OUService{ldap: ldap, audit: auditLog},
		Trusts:    &TrustService{ldap: ldap, audit: auditLog, tool: tool},
		Domain:    &DomainService{ldap: ldap, audit: auditLog, tool: tool},
		Repl:      &ReplService{ldap: ldap, audit: auditLog, tool: tool},
		Sites:     &SiteService{ldap: ldap, audit: auditLog},
		Subnets:   &SubnetService{ldap: ldap, audit: auditLog},
		DNS:       &DNSService{ldap: ldap, audit: auditLog},
		GPO:       &GPOService{ldap: ldap, audit: auditLog},
		Audit:     auditLog,
		Tool:      tool,
	}
}
