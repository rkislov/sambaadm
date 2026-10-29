package service

import (
	"context"
	"fmt"
	"os"
	"strings"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/adremote"
	ldapproto "sambaadm/internal/ldap"
)

func (s *DiagnosticService) diagnosticRemote() *adremote.Client {
	host := hostnameFromURI(s.cfg.LDAP.URI)
	if host == "" {
		host = "localhost"
	}
	return &adremote.Client{Host: host, SMBPort: s.cfg.GPO.SMBPort, User: s.cfg.LDAP.Bind.User, Password: s.cfg.BindPassword}
}
func (s *DiagnosticService) checkDRSPermissions(ctx context.Context) (string, string, string) {
	if s.cfg.LDAP.Bind.User == "" || s.cfg.BindPassword() == "" {
		return "skipped", "DRS service credentials are not configured", "Configure ldap.bind.user and its password environment variable."
	}
	remote := s.diagnosticRemote()
	neighbors, err := remote.Neighbors(ctx)
	if err != nil {
		return "error", fmt.Sprintf("DRS read on %s as %s failed: %v", remote.Host, remote.User, err), "Check RPC connectivity and this service account's DRS permissions. Browser login does not change this identity. KCC and replication writes were not attempted."
	}
	return "ok", fmt.Sprintf("DRS replication information readable on %s as %s (%d neighbors)", remote.Host, remote.User, len(neighbors)), "Confirms GetReplicationInfo access only. KCC, synchronization rights and replication health are separate checks."
}
func (s *DiagnosticService) withDiagnosticPolicy(ctx context.Context, gpo string, fn func(*ldapproto.Client, *ldap.Entry, string) error) error {
	client := ldapproto.NewServiceClient(s.cfg.LDAP, s.cfg.BindPassword)
	defer client.Close()
	if err := client.Connect(ctx); err != nil {
		return err
	}
	svc := &GPOService{ldap: client}
	entry, err := svc.policyEntry(ctx, gpo)
	if err != nil {
		return err
	}
	base, err := svc.policyPath(ctx, entry)
	if err != nil {
		return err
	}
	return fn(client, entry, base)
}

func (s *DiagnosticService) checkLDAPPolicyPermissions(ctx context.Context, gpo string) (string, string, string) {
	if gpo == "" {
		return "skipped", "No GPO selected for LDAP effective permissions", "Select a GPO to check its versionNumber and extension attributes without modifying it."
	}
	var attrs []string
	err := s.withDiagnosticPolicy(ctx, gpo, func(client *ldapproto.Client, entry *ldap.Entry, _ string) error {
		e, err := client.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: entry.DN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=groupPolicyContainer)", Attributes: []string{"allowedAttributesEffective"}})
		if err == nil {
			attrs = e.GetEqualFoldAttributeValues("allowedAttributesEffective")
		}
		return err
	})
	if err != nil {
		return "error", err.Error(), "Check the service bind, GPO read rights and server support for allowedAttributesEffective."
	}
	if len(attrs) == 0 {
		return "warning", "The server returned no allowedAttributesEffective values", "Write permissions could not be confirmed; no LDAP modify was attempted."
	}
	missing := []string{}
	for _, want := range []string{"versionNumber", "gPCMachineExtensionNames", "gPCUserExtensionNames"} {
		found := false
		for _, attr := range attrs {
			if strings.EqualFold(want, attr) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, want)
		}
	}
	if len(missing) > 0 {
		return "error", "Service account cannot modify GPO attributes: " + strings.Join(missing, ", "), "Delegate the required write-property rights for this GPO. This check does not grant permissions."
	}
	return "ok", "Server reports effective write-property permission for versionNumber and both extension attributes", "No LDAP modify was performed. Creation, deletion, security descriptor changes and successful future writes are not guaranteed."
}

func (s *DiagnosticService) checkSYSVOLPolicyPermissions(ctx context.Context, gpo string) (string, string, string) {
	if gpo == "" {
		return "skipped", "No GPO selected for SYSVOL write-open check", "Select a GPO. The existing GPT.INI is opened without truncation; no data is written."
	}
	err := s.withDiagnosticPolicy(ctx, gpo, func(_ *ldapproto.Client, _ *ldap.Entry, base string) error {
		return s.diagnosticRemote().SYSVOL(ctx, s.cfg.GPO.SMBPort, func(sh *smb2.Share) error {
			root := &smbPolicyStore{share: sh, base: strings.ReplaceAll(base, `\`, "/")}
			gpt, err := policyChild(root, ".", "GPT.INI", false)
			if err != nil {
				return err
			}
			if _, err := readPolicyFile(root, gpt); err != nil {
				return err
			}
			f, err := root.OpenFile(gpt, os.O_RDWR, 0)
			if err != nil {
				return err
			}
			return f.Close()
		})
	})
	if err != nil {
		return "error", err.Error(), "Check SMB permissions on this GPO and GPT.INI, including both the share and file ACLs. No file was created or written."
	}
	return "ok", "Existing GPT.INI is readable and opens with read/write access as the service account", "No data was written. Directory create/delete rights, other script file ACLs and atomic rename permissions remain untested."
}
