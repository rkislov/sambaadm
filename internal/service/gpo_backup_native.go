package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/adremote"
	ldapproto "sambaadm/internal/ldap"
)

type policyBackup struct {
	Format      int                 `json:"format"`
	Domain      string              `json:"domain"`
	Attributes  map[string][]string `json:"attributes"`
	Files       map[string][]byte   `json:"files"`
	Permissions map[string][]byte   `json:"permissions"`
	ACL         []byte              `json:"acl"`
}

var backupAttrs = []string{"displayName", "versionNumber", "flags", "gPCMachineExtensionNames", "gPCUserExtensionNames"}

func (s *GPOService) backupNative(ctx context.Context, policy, path, actor, ip string) error {
	if path == "" {
		return fmt.Errorf("backup path required")
	}
	entry, err := s.policyEntry(ctx, policy)
	if err != nil {
		return err
	}
	remotePath, err := s.policyPath(ctx, entry)
	if err != nil {
		return err
	}
	meta, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: entry.DN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: backupAttrs})
	if err != nil {
		return err
	}
	realm, err := s.domainDNS(ctx)
	if err != nil {
		return err
	}
	backup := policyBackup{Format: 1, Domain: realm, Attributes: map[string][]string{}, Files: map[string][]byte{}, Permissions: map[string][]byte{}}
	for _, a := range backupAttrs {
		backup.Attributes[a] = meta.GetAttributeValues(a)
	}
	err = s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(share *smb2.Share) error {
		var e error
		backup.ACL, e = share.SecurityInfoRaw(remotePath, smb2.OwnerSecurityInformation|smb2.GroupSecurityInformation|smb2.DACLSecurityInformation)
		if e != nil {
			return e
		}
		total := int64(0)
		var walk func(string) error
		walk = func(rel string) error {
			entries, e := share.ReadDir(remotePath + "\\" + strings.ReplaceAll(rel, "/", "\\"))
			if e != nil {
				return e
			}
			for _, f := range entries {
				if strings.ContainsAny(f.Name(), "/\\") || f.Name() == "." || f.Name() == ".." || f.Mode()&os.ModeSymlink != 0 {
					return fmt.Errorf("unsupported SYSVOL entry")
				}
				child := f.Name()
				if rel != "" {
					child = rel + "/" + child
				}
				if len(backup.Permissions) >= 10000 {
					return fmt.Errorf("policy entry limit exceeded")
				}
				acl, e := share.SecurityInfoRaw(remotePath+"\\"+strings.ReplaceAll(child, "/", "\\"), smb2.OwnerSecurityInformation|smb2.GroupSecurityInformation|smb2.DACLSecurityInformation)
				if e != nil {
					return e
				}
				backup.Permissions[child] = acl
				if f.IsDir() {
					if strings.Count(child, "/") > 32 {
						return fmt.Errorf("policy nesting too deep")
					}
					if e := walk(child); e != nil {
						return e
					}
					continue
				}
				total += f.Size()
				if total > 64<<20 || len(backup.Files) >= 10000 {
					return fmt.Errorf("policy backup exceeds size limit")
				}
				data, e := share.ReadFile(remotePath + "\\" + strings.ReplaceAll(child, "/", "\\"))
				if e != nil {
					return e
				}
				backup.Files[child] = data
			}
			return nil
		}
		return walk("")
	})
	if err != nil {
		return err
	}
	after, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: entry.DN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: backupAttrs})
	if err != nil {
		return err
	}
	if after.GetAttributeValue("versionNumber") != meta.GetAttributeValue("versionNumber") {
		return fmt.Errorf("GPO changed during backup; retry")
	}
	dest := filepath.Join(path, "policy", entry.GetAttributeValue("name"))
	if err = os.MkdirAll(dest, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dest, "sambaadm-backup.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	s.audit.Success(actor, "gpo.backup", entry.DN+" -> "+dest, ip)
	return nil
}
func (s *GPOService) restoreNative(ctx context.Context, name, path, actor, ip string) error {
	f, err := os.Open(filepath.Join(path, "sambaadm-backup.json"))
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 100<<20 {
		return fmt.Errorf("backup too large")
	}
	var b policyBackup
	if err = json.NewDecoder(f).Decode(&b); err != nil {
		return err
	}
	if b.Format != 1 {
		return fmt.Errorf("unsupported backup format")
	}
	realm, err := s.domainDNS(ctx)
	if err != nil {
		return err
	}
	if !strings.EqualFold(realm, b.Domain) {
		return fmt.Errorf("backup belongs to another domain")
	}
	paths := map[string]bool{}
	for p := range b.Files {
		paths[p] = true
	}
	for p := range b.Permissions {
		paths[p] = true
	}
	for path := range paths {
		if path == "" || strings.Contains(path, "\\") || strings.HasPrefix(path, "/") || strings.Contains(path, ":") {
			return fmt.Errorf("invalid backup path")
		}
		for _, part := range strings.Split(path, "/") {
			if part == "" || part == "." || part == ".." {
				return fmt.Errorf("invalid backup path")
			}
		}
	}
	if _, ok := b.Files["GPT.INI"]; !ok {
		return fmt.Errorf("backup missing GPT.INI")
	}
	if _, err = s.createNative(ctx, name, actor, ip); err != nil {
		return err
	}
	entry, err := s.policyEntry(ctx, name)
	if err != nil {
		return err
	}
	remotePath, err := s.policyPath(ctx, entry)
	if err != nil {
		return err
	}
	err = s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(share *smb2.Share) error {
		for name, data := range b.Files {
			full := remotePath + "\\" + strings.ReplaceAll(name, "/", "\\")
			i := strings.LastIndex(full, "\\")
			if e := share.MkdirAll(full[:i], 0755); e != nil {
				return e
			}
			if e := share.WriteFile(full, data, 0644); e != nil {
				return e
			}
		}
		if len(b.ACL) > 0 {
			if e := share.SetSecurityInfoRaw(remotePath, smb2.OwnerSecurityInformation|smb2.GroupSecurityInformation|smb2.DACLSecurityInformation|0x80000000, adremote.SecurityBytes(b.ACL)); e != nil {
				return e
			}
		}
		if e := applySnapshotPermissions(share, remotePath, b); e != nil {
			return e
		}

		req := ldap.NewModifyRequest(entry.DN, nil)
		for _, key := range backupAttrs {
			if key != "displayName" {
				req.Replace(key, b.Attributes[key])
			}
		}
		return s.ldap.Modify(ctx, req)
	})
	if err != nil {
		return fmt.Errorf("restore incomplete; new unlinked GPO %s retained for recovery: %w", entry.DN, err)
	}
	s.audit.Success(actor, "gpo.restore", entry.DN, ip)
	return nil
}

func applySnapshotPermissions(share *smb2.Share, root string, b policyBackup) error {
	paths := make([]string, 0, len(b.Permissions))
	for p := range b.Permissions {
		paths = append(paths, p)
	}
	sort.Slice(paths, func(i, j int) bool { return strings.Count(paths[i], "/") < strings.Count(paths[j], "/") })
	for _, p := range paths {
		full := root + "\\" + strings.ReplaceAll(p, "/", "\\")
		if _, isFile := b.Files[p]; !isFile {
			if err := share.MkdirAll(full, 0755); err != nil {
				return err
			}
		}
		if err := share.SetSecurityInfoRaw(full, smb2.OwnerSecurityInformation|smb2.GroupSecurityInformation|smb2.DACLSecurityInformation|0x80000000, adremote.SecurityBytes(b.Permissions[p])); err != nil {
			return err
		}
	}
	return nil
}
