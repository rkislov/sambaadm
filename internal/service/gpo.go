package service

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/adremote"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
)

// GPO is a Group Policy Object summary.
type GPO struct {
	DisplayName string `json:"displayName"`
	GUID        string `json:"guid,omitempty"`
	DN          string `json:"dn,omitempty"`
	Source      string `json:"source,omitempty"`
}

// GPOService manages GPOs over LDAP and SMB.
type GPOService struct {
	editorMu sync.Mutex
	remote   *adremote.Client
	ldap     *ldapproto.Client
	audit    *audit.Logger
	gpoCfg   config.GPOConfig
	jobs     *jobStore
}

// List returns GPOs through LDAP.
func (s *GPOService) List(ctx context.Context) ([]GPO, error) {

	return s.listLDAP(ctx)
}

// Show returns details for a GPO (GUID or display name) through native protocols.
func (s *GPOService) Show(ctx context.Context, gpo string) (string, error) {
	entry, err := s.policyEntry(ctx, gpo)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	fmt.Fprintf(&out, "dn: %s\n", entry.DN)
	for _, attr := range entry.Attributes {
		fmt.Fprintf(&out, "%s: %s\n", attr.Name, strings.Join(attr.Values, ", "))
	}
	return out.String(), nil
}

// Create creates a GPO with the given display name.
func (s *GPOService) Create(ctx context.Context, displayName, actor, ip string) (string, error) {
	return s.createNative(ctx, displayName, actor, ip)
}

// Delete deletes a GPO by GUID or name.
func (s *GPOService) Delete(ctx context.Context, gpo, actor, ip string) error {
	return s.deleteNative(ctx, gpo, actor, ip)
}

// Link links a GPO to a container DN.
func (s *GPOService) Link(ctx context.Context, containerDN, gpo, actor, ip string) error {
	return s.changeLink(ctx, containerDN, gpo, actor, ip, false)
}

// Unlink removes a GPO link from a container DN.
func (s *GPOService) Unlink(ctx context.Context, containerDN, gpo, actor, ip string) error {
	return s.changeLink(ctx, containerDN, gpo, actor, ip, true)
}

// GetLinks returns GPO links on a container.
func (s *GPOService) GetLinks(ctx context.Context, containerDN string) (string, error) {
	entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: containerDN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"gPLink"}})
	if err != nil {
		return "", err
	}
	return entry.GetAttributeValue("gPLink"), nil
}

// Backup backs up a GPO to a directory path.
func (s *GPOService) Backup(ctx context.Context, gpo, path, actor, ip string) error {
	return s.backupNative(ctx, gpo, path, actor, ip)
}

// Restore creates a new GPO with displayName from a policy/<GUID> backup directory.
func (s *GPOService) Restore(ctx context.Context, displayName, path, actor, ip string) error {
	return s.restoreNative(ctx, displayName, path, actor, ip)
}

func (s *GPOService) listLDAP(ctx context.Context) ([]GPO, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{
		Filter:     "(objectClass=groupPolicyContainer)",
		Attributes: []string{"displayName", "cn", "name"},
	})
	if err != nil {
		return nil, err
	}
	out := make([]GPO, 0, len(entries))
	for _, e := range entries {
		out = append(out, entryToGPO(e))
	}
	return out, nil
}

func entryToGPO(e *ldap.Entry) GPO {
	return GPO{
		DisplayName: e.GetAttributeValue("displayName"),
		GUID:        e.GetAttributeValue("cn"),
		DN:          e.DN,
		Source:      "ldap",
	}
}
