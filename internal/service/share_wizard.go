package service

import (
	"context"
	protocol "github.com/go-ldap/ldap/v3"
	"os/exec"
	"os/user"
	"runtime"
	"sambaadm/internal/ldap"
	"strconv"
	"strings"
	"time"
)

type ShareWizardInput struct {
	Name    string   `json:"name"`
	Path    string   `json:"path"`
	Comment string   `json:"comment"`
	Profile string   `json:"profile"`
	Groups  []string `json:"groups"`
}
type ShareWizardPlan struct {
	Input    CreateShareInput `json:"input"`
	Domain   string           `json:"domain"`
	Groups   []string         `json:"groups"`
	Ready    bool             `json:"ready"`
	Warnings []string         `json:"warnings"`
}

func (s *Services) PlanShare(ctx context.Context, in ShareWizardInput) (*ShareWizardPlan, error) {
	return s.planShare(ctx, in, lookupHostGroup)
}
func (s *Services) planShare(ctx context.Context, in ShareWizardInput, resolve func(context.Context, string) (string, error)) (*ShareWizardPlan, error) {
	if strings.ContainsAny(in.Path+in.Comment, "\r\n") {
		return nil, topologyBad("multiline path or comment")
	}
	if e := validateShareName(in.Name); e != nil {
		return nil, e
	}
	if in.Profile != "team" && in.Profile != "read" {
		return nil, topologyBad("select team or read profile")
	}
	if len(in.Groups) == 0 || len(in.Groups) > 32 {
		return nil, topologyBad("select 1–32 domain groups")
	}
	domain, e := s.Domain.Info(ctx)
	if e != nil {
		return nil, e
	}
	if domain.NetBIOS == "" || strings.ContainsAny(domain.NetBIOS, "\"\\,;\r\n") {
		return nil, topologyBad("unsupported domain name")
	}
	plan := &ShareWizardPlan{Domain: domain.NetBIOS, Ready: true, Groups: []string{}, Warnings: []string{}}
	names, acls := []string{}, []string{}
	seen := map[string]bool{}
	for _, dn := range in.Groups {
		if seen[strings.ToLower(dn)] {
			return nil, topologyBad("duplicate group")
		}
		seen[strings.ToLower(dn)] = true
		// Resolve only a group from this domain, never trust a supplied smb.conf token.
		parsed, e := parseDomainGroupDN(dn, s.GPO.ldap.BaseDN())
		if e != nil {
			return nil, e
		}
		entry, e := s.GPO.ldap.SearchOne(ctx, ldap.SearchOptions{BaseDN: parsed, Scope: ldap.ScopeBase(), Filter: "(objectClass=group)", Attributes: []string{"sAMAccountName", "groupType"}})
		if e != nil {
			return nil, e
		}
		gt, e := strconv.ParseInt(entry.GetAttributeValue("groupType"), 10, 64)
		if e != nil || uint32(gt)&0x80000000 == 0 {
			return nil, topologyBad("distribution groups cannot grant file access")
		}
		name := entry.GetAttributeValue("sAMAccountName")
		if name == "" || strings.ContainsAny(name, "\"\\,;:#%\r\n[]") {
			return nil, topologyBad("group name cannot be represented safely")
		}
		qualified := domain.NetBIOS + "\\" + name
		plan.Groups = append(plan.Groups, qualified)
		names = append(names, "@\""+qualified+"\"")
		gid, e := resolve(ctx, qualified)
		if e != nil {
			plan.Ready = false
			plan.Warnings = append(plan.Warnings, "Local identity lookup failed: "+qualified+". Check domain membership and winbind/NSS.")
			continue
		}
		if _, e := strconv.ParseUint(gid, 10, 32); e != nil {
			return nil, topologyBad("invalid local GID")
		}
		perm := "rwx"
		if in.Profile == "read" {
			perm = "r-x"
		}
		acls = append(acls, "g:"+gid+":"+perm)
	}
	ro, guest, browse, inherit, create, reload := true, false, true, true, true, true
	plan.Input = CreateShareInput{Name: in.Name, Path: in.Path, Comment: in.Comment, Preset: PresetCustom, ReadOnly: &ro, GuestOK: &guest, Browseable: &browse, InheritACLs: &inherit, MapACLInherit: &inherit, CreateDir: &create, Reload: &reload, Mode: "0770", CreateMask: "0660", DirectoryMask: "0770", ValidUsers: strings.Join(names, ", ")}
	if in.Profile == "team" {
		plan.Input.WriteList = plan.Input.ValidUsers
	}
	if plan.Ready {
		acls = append(acls, "m::rwx", "o::---")
		plan.Input.ACL = strings.Join(acls, ",")
		plan.Input.DefaultACL = plan.Input.ACL
	}
	if in.Path != "" {
		if e := s.Shares.validatePath(in.Path); e != nil {
			return nil, e
		}
	}
	return plan, nil
}

func parseDomainGroupDN(dn, base string) (string, error) {
	a, e := protocol.ParseDN(dn)
	b, _ := protocol.ParseDN(base)
	if e != nil || !b.AncestorOfFold(a) {
		return "", topologyBad("select a group in the configured domain")
	}
	return dn, nil
}

// Static Linux builds cannot resolve winbind NSS groups through os/user.
// getent invokes the host NSS stack; the group name is a literal argv value.
func lookupHostGroup(ctx context.Context, name string) (string, error) {
	if runtime.GOOS == "linux" {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		out, e := exec.CommandContext(ctx, "getent", "group", name).Output()
		if e != nil {
			return "", e
		}
		parts := strings.Split(strings.TrimSpace(string(out)), ":")
		if len(parts) != 4 {
			return "", topologyBad("invalid getent group response")
		}
		return parts[2], nil
	}
	group, e := user.LookupGroup(name)
	if e != nil {
		return "", e
	}
	return group.Gid, nil
}
