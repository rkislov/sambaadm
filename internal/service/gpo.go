package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/samba"
)

// GPO is a Group Policy Object summary.
type GPO struct {
	DisplayName string `json:"displayName"`
	GUID        string `json:"guid,omitempty"`
	DN          string `json:"dn,omitempty"`
	Source      string `json:"source,omitempty"`
}

// GPOService manages GPOs (LDAP list + samba-tool mutations).
type GPOService struct {
	ldap   *ldapproto.Client
	audit  *audit.Logger
	tool   *samba.Runner
	gpoCfg config.GPOConfig
	jobs   *jobStore
}

// List returns GPOs (samba-tool listall preferred, LDAP fallback).
func (s *GPOService) List(ctx context.Context) ([]GPO, error) {
	if s.tool != nil && s.tool.Available() {
		res, err := s.tool.Run(ctx, "gpo", "listall")
		if err == nil {
			if parsed := parseGPOListAll(res.Stdout); len(parsed) > 0 {
				return parsed, nil
			}
		}
	}
	return s.listLDAP(ctx)
}

// Show returns details for a GPO (GUID or display name) via samba-tool.
func (s *GPOService) Show(ctx context.Context, gpo string) (string, error) {
	if err := s.requireTool(); err != nil {
		return "", err
	}
	res, err := s.tool.Run(ctx, "gpo", "show", gpo)
	if err != nil {
		return "", err
	}
	return res.Stdout, nil
}

// Create creates a GPO with the given display name.
func (s *GPOService) Create(ctx context.Context, displayName, actor, ip string) (string, error) {
	if err := s.requireTool(); err != nil {
		return "", err
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" {
		return "", fmt.Errorf("display name is required")
	}
	res, err := s.tool.Run(ctx, "gpo", "create", displayName)
	if err != nil {
		s.audit.Failure(actor, "gpo.create", displayName, ip, err)
		return "", err
	}
	s.audit.Success(actor, "gpo.create", displayName, ip)
	return res.Stdout, nil
}

// Delete deletes a GPO by GUID or name.
func (s *GPOService) Delete(ctx context.Context, gpo, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	if _, err := s.tool.Run(ctx, "gpo", "delete", gpo); err != nil {
		s.audit.Failure(actor, "gpo.delete", gpo, ip, err)
		return err
	}
	s.audit.Success(actor, "gpo.delete", gpo, ip)
	return nil
}

// Link links a GPO to a container DN.
func (s *GPOService) Link(ctx context.Context, containerDN, gpo, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	target := containerDN + " <- " + gpo
	if _, err := s.tool.Run(ctx, "gpo", "setlink", containerDN, gpo); err != nil {
		s.audit.Failure(actor, "gpo.link", target, ip, err)
		return err
	}
	s.audit.Success(actor, "gpo.link", target, ip)
	return nil
}

// Unlink removes a GPO link from a container DN.
func (s *GPOService) Unlink(ctx context.Context, containerDN, gpo, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	target := containerDN + " -/ " + gpo
	if _, err := s.tool.Run(ctx, "gpo", "dellink", containerDN, gpo); err != nil {
		s.audit.Failure(actor, "gpo.unlink", target, ip, err)
		return err
	}
	s.audit.Success(actor, "gpo.unlink", target, ip)
	return nil
}

// GetLinks returns GPO links on a container.
func (s *GPOService) GetLinks(ctx context.Context, containerDN string) (string, error) {
	if err := s.requireTool(); err != nil {
		return "", err
	}
	res, err := s.tool.Run(ctx, "gpo", "getlink", containerDN)
	if err != nil {
		return "", err
	}
	return res.Stdout, nil
}

// Backup backs up a GPO to a directory path.
func (s *GPOService) Backup(ctx context.Context, gpo, path, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	if path == "" {
		return fmt.Errorf("backup path is required")
	}
	target := gpo + " -> " + path
	if _, err := s.tool.Run(ctx, "gpo", "backup", gpo, path); err != nil {
		s.audit.Failure(actor, "gpo.backup", target, ip, err)
		return err
	}
	s.audit.Success(actor, "gpo.backup", target, ip)
	return nil
}

// Restore restores a GPO from a backup path.
func (s *GPOService) Restore(ctx context.Context, gpo, path, actor, ip string) error {
	if err := s.requireTool(); err != nil {
		return err
	}
	if path == "" {
		return fmt.Errorf("restore path is required")
	}
	target := path + " -> " + gpo
	// samba-tool gpo restore <gpo> <path> (versions differ; try restore then create)
	if _, err := s.tool.Run(ctx, "gpo", "restore", gpo, path); err != nil {
		s.audit.Failure(actor, "gpo.restore", target, ip, err)
		return err
	}
	s.audit.Success(actor, "gpo.restore", target, ip)
	return nil
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

func (s *GPOService) requireTool() error {
	if s.tool == nil || !s.tool.Available() {
		return fmt.Errorf("samba-tool is not available on this host")
	}
	return nil
}

func entryToGPO(e *ldap.Entry) GPO {
	return GPO{
		DisplayName: e.GetAttributeValue("displayName"),
		GUID:        e.GetAttributeValue("cn"),
		DN:          e.DN,
		Source:      "ldap",
	}
}

func parseGPOListAll(stdout string) []GPO {
	var out []GPO
	var cur GPO
	flush := func() {
		if cur.GUID != "" || cur.DisplayName != "" {
			cur.Source = "samba-tool"
			out = append(out, cur)
			cur = GPO{}
		}
	}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		lower := strings.ToLower(line)
		if i := strings.Index(line, ":"); i >= 0 {
			key := strings.ReplaceAll(strings.TrimSpace(lower[:i]), " ", "")
			val := strings.TrimSpace(line[i+1:])
			switch {
			case strings.Contains(key, "displayname"), key == "name":
				if cur.DisplayName != "" && cur.GUID != "" {
					flush()
				}
				cur.DisplayName = val
			case strings.Contains(key, "guid"), key == "gpo":
				if cur.GUID != "" && cur.DisplayName != "" {
					flush()
				}
				cur.GUID = val
			case strings.Contains(key, "dn"), strings.Contains(key, "path"):
				cur.DN = val
			}
			continue
		}
	}
	flush()
	return out
}
