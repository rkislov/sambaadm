package service

import (
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
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
	Shares    *ShareService
	Printers  *PrinterService
	FSACL     *FSACLService
	Audit     *audit.Logger
	Tool      *samba.Runner
}

// ServiceOptions configures optional dependencies.
type ServiceOptions struct {
	SambaTool string
	GPO       config.GPOConfig
	Samba     config.SambaConfig
}

// New builds the service layer on top of an LDAP client.
func New(ldap *ldapproto.Client, auditLog *audit.Logger) *Services {
	return NewWithOptions(ldap, auditLog, ServiceOptions{})
}

// NewWithOptions builds services with optional samba-tool path and GPO sync settings.
func NewWithOptions(ldap *ldapproto.Client, auditLog *audit.Logger, opts ServiceOptions) *Services {
	tool := samba.NewRunner(opts.SambaTool)
	shares := newShareService(auditLog, opts.Samba)
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
		DNS:       &DNSService{ldap: ldap, audit: auditLog, tool: tool},
		GPO: &GPOService{
			ldap: ldap, audit: auditLog, tool: tool,
			gpoCfg: opts.GPO,
			jobs:   newJobStore(),
		},
		Shares:   shares,
		Printers: newPrinterService(auditLog, shares),
		FSACL:    newFSACLService(auditLog, shares),
		Audit:    auditLog,
		Tool:     tool,
	}
}
