package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"sambaadm/internal/adremote"
	ldapproto "sambaadm/internal/ldap"
)

func (s *GPOService) domainDNS(ctx context.Context) (string, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: "CN=Partitions," + ConfigDN(s.ldap.BaseDN()), Filter: "(&(objectClass=crossRef)(nCName=" + ldap.EscapeFilter(s.ldap.BaseDN()) + "))", Attributes: []string{"dnsRoot"}})
	if err != nil {
		return "", err
	}
	if len(entries) != 1 || entries[0].GetAttributeValue("dnsRoot") == "" {
		return "", fmt.Errorf("domain DNS name unavailable")
	}
	return entries[0].GetAttributeValue("dnsRoot"), nil
}
func (s *GPOService) createNative(ctx context.Context, name, actor, ip string) (result string, err error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("display name is required")
	}
	policies, err := s.listLDAP(ctx)
	if err != nil {
		return "", err
	}
	for _, p := range policies {
		if strings.EqualFold(p.DisplayName, name) {
			return "", fmt.Errorf("GPO name already exists")
		}
	}
	realm, err := s.domainDNS(ctx)
	if err != nil {
		return "", err
	}
	guid := "{" + strings.ToUpper(uuid.NewString()) + "}"
	dn := "CN=" + guid + ",CN=Policies,CN=System," + s.ldap.BaseDN()
	remotePath := realm + "\\Policies\\" + guid
	created := []string{}
	defer func() {
		if err != nil {
			for i := len(created) - 1; i >= 0; i-- {
				if e := s.ldap.Delete(context.Background(), created[i]); e != nil {
					err = errors.Join(err, fmt.Errorf("rollback %s: %w", created[i], e))
				}
			}
			s.audit.Failure(actor, "gpo.create", name, ip, err)
		}
	}()
	err = s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(share *smb2.Share) (failure error) {
		add := ldap.NewAddRequest(dn, nil)
		add.Attribute("objectClass", []string{"groupPolicyContainer"})
		if e := s.ldap.Add(ctx, add.DN, add.Attributes); e != nil {
			return e
		}
		created = append(created, dn)
		for _, part := range []string{"Machine", "User"} {
			child := "CN=" + part + "," + dn
			req := ldap.NewAddRequest(child, nil)
			req.Attribute("objectClass", []string{"container"})
			if e := s.ldap.Add(ctx, req.DN, req.Attributes); e != nil {
				return e
			}
			created = append(created, child)
		}
		entry, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"nTSecurityDescriptor"}})
		if e != nil {
			return e
		}
		acl, e := adremote.PolicyFileACL(entry.GetRawAttributeValue("nTSecurityDescriptor"))
		if e != nil {
			return e
		}
		if e = share.Mkdir(remotePath, 0755); e != nil {
			return e
		}
		defer func() {
			if failure != nil {
				failure = errors.Join(failure, share.RemoveAll(remotePath))
			}
		}()
		if e = share.SetSecurityInfoRaw(remotePath, smb2.OwnerSecurityInformation|smb2.GroupSecurityInformation|smb2.DACLSecurityInformation|0x80000000, acl); e != nil {
			return e
		}
		for _, part := range []string{"Machine", "User"} {
			if e = share.Mkdir(remotePath+"\\"+part, 0755); e != nil {
				return e
			}
		}
		if e = share.WriteFile(remotePath+"\\GPT.INI", []byte("[General]\r\nVersion=0\r\n"), 0644); e != nil {
			return e
		}
		req := ldap.NewModifyRequest(dn, nil)
		for k, v := range map[string]string{"displayName": name, "gPCFileSysPath": "\\\\" + realm + "\\SYSVOL\\" + remotePath, "versionNumber": "0", "gPCFunctionalityVersion": "2", "flags": "0"} {
			req.Replace(k, []string{v})
		}
		return s.ldap.Modify(ctx, req)
	})
	if err != nil {
		return "", err
	}
	s.audit.Success(actor, "gpo.create", guid, ip)
	return fmt.Sprintf("GPO '%s' created as %s", name, guid), nil
}

func (s *GPOService) policyPath(ctx context.Context, entry *ldap.Entry) (string, error) {
	realm, err := s.domainDNS(ctx)
	if err != nil {
		return "", err
	}
	guid := entry.GetAttributeValue("name")
	if !looksLikeGUID(guid) {
		return "", fmt.Errorf("invalid GPO GUID")
	}
	expected := realm + "\\Policies\\" + guid
	unc := entry.GetAttributeValue("gPCFileSysPath")
	parts := strings.Split(strings.TrimPrefix(unc, "\\\\"), "\\")
	if len(parts) != 5 || !strings.EqualFold(parts[1], "SYSVOL") || !strings.EqualFold(strings.Join(parts[2:], "\\"), expected) {
		return "", fmt.Errorf("unexpected GPO SYSVOL path")
	}
	return expected, nil
}
func (s *GPOService) deleteNative(ctx context.Context, policy, actor, ip string) error {
	entry, err := s.policyEntry(ctx, policy)
	if err != nil {
		return err
	}
	refs, err := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(gPLink=*" + ldap.EscapeFilter(entry.DN) + "*)", Attributes: []string{"gPLink"}})
	if err != nil {
		return err
	}
	sites, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: SitesContainerDN(s.ldap.BaseDN()), Filter: "(gPLink=*" + ldap.EscapeFilter(entry.DN) + "*)", Attributes: []string{"gPLink"}})
	if err != nil {
		return err
	}
	if len(refs)+len(sites) > 0 {
		return fmt.Errorf("unlink GPO from all containers before deleting")
	}
	remotePath, err := s.policyPath(ctx, entry)
	if err != nil {
		return err
	}
	children, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: entry.DN, Filter: "(objectClass=*)", Attributes: []string{"cn"}})
	if err != nil {
		return err
	}
	sort.Slice(children, func(i, j int) bool { return len(children[i].DN) > len(children[j].DN) })
	err = s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(share *smb2.Share) error {
		// Keep files until directory deletion succeeds. An interrupted deletion is
		// reported; remaining SYSVOL files retain their original ACL for recovery.
		for _, child := range children {
			if e := s.ldap.Delete(ctx, child.DN); e != nil {
				return e
			}
		}
		if e := share.RemoveAll(remotePath); e != nil {
			return fmt.Errorf("GPO deleted from LDAP; SYSVOL cleanup required at %s: %w", remotePath, e)
		}
		return nil
	})
	if err != nil {
		s.audit.Failure(actor, "gpo.delete", entry.DN, ip, err)
		return err
	}
	s.audit.Success(actor, "gpo.delete", entry.DN, ip)
	return nil
}
