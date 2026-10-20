package service

import (
	"sambaadm/internal/adremote"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
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
	Sites     *SiteService
	Subnets   *SubnetService
	DNS       *DNSService
	GPO       *GPOService
	Shares    *ShareService
	Printers  *PrinterService
	FSACL     *FSACLService
	Audit     *audit.Logger
}

// ServiceOptions configures optional dependencies.
type ServiceOptions struct {
	Username string
	Password func() string
	GPO      config.GPOConfig
	Samba    config.SambaConfig
}

// New builds the service layer on top of an LDAP client.
func New(ldap *ldapproto.Client, auditLog *audit.Logger) *Services {
	return NewWithOptions(ldap, auditLog, ServiceOptions{})
}

// NewWithOptions builds services with service credentials and GPO sync settings.
func NewWithOptions(ldap *ldapproto.Client, auditLog *audit.Logger, opts ServiceOptions) *Services {
	remoteHost := hostnameFromURI(ldap.URI())
	if remoteHost == "" {
		remoteHost = "localhost"
	}
	shares := newShareService(auditLog, opts.Samba)
	return &Services{
		Users:     &UserService{ldap: ldap, audit: auditLog},
		Groups:    &GroupService{ldap: ldap, audit: auditLog},
		Computers: &ComputerService{ldap: ldap, audit: auditLog},
		OU:        &OUService{ldap: ldap, audit: auditLog},
		Trusts:    &TrustService{ldap: ldap, audit: auditLog, remote: &adremote.Client{SMBPort: opts.GPO.SMBPort, Host: remoteHost, User: opts.Username, Password: opts.Password}},
		Domain:    &DomainService{ldap: ldap, audit: auditLog, remote: &adremote.Client{SMBPort: opts.GPO.SMBPort, Host: remoteHost, User: opts.Username, Password: opts.Password}},
		Repl:      &ReplService{ldap: ldap, audit: auditLog, remote: &adremote.Client{SMBPort: opts.GPO.SMBPort, Host: remoteHost, User: opts.Username, Password: opts.Password}},
		Sites:     &SiteService{ldap: ldap, audit: auditLog},
		Subnets:   &SubnetService{ldap: ldap, audit: auditLog},
		DNS:       &DNSService{ldap: ldap, audit: auditLog, remote: &adremote.Client{SMBPort: opts.GPO.SMBPort, Host: remoteHost, User: opts.Username, Password: opts.Password}},
		GPO: &GPOService{
			ldap: ldap, audit: auditLog, remote: &adremote.Client{SMBPort: opts.GPO.SMBPort, Host: remoteHost, User: opts.Username, Password: opts.Password},
			gpoCfg: opts.GPO,
			jobs:   newJobStore(),
		},
		Shares:   shares,
		Printers: newPrinterService(auditLog, shares),
		FSACL:    newFSACLService(auditLog, shares),
		Audit:    auditLog,
	}
}
