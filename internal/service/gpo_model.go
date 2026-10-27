package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/policy"
)

// GPModelInput describes a hypothetical scenario. Filter outcomes are assumptions,
// never claimed to be an access check or a WMI evaluation on the client.
type GPModelInput struct {
	User              string            `json:"user"`
	Computer          string            `json:"computer"`
	UserOU            string            `json:"userOU"`
	ComputerOU        string            `json:"computerOU"`
	Loopback          string            `json:"loopback"`
	Security          string            `json:"security"`
	WMI               string            `json:"wmi"`
	SecurityOverrides map[string]string `json:"securityOverrides,omitempty"`
	WMIOverrides      map[string]string `json:"wmiOverrides,omitempty"`
}
type GPModelContribution struct {
	Source  ScopeLink `json:"source"`
	Type    uint32    `json:"type"`
	Value   string    `json:"value"`
	Deleted bool      `json:"deleted"`
}

type GPModelValue struct {
	Key           string                `json:"key"`
	Name          string                `json:"name"`
	Type          uint32                `json:"type"`
	Data          []byte                `json:"data"`
	Value         string                `json:"value"`
	Deleted       bool                  `json:"deleted"`
	Winner        ScopeLink             `json:"winner"`
	Precedence    []ScopeLink           `json:"precedence"`
	Conflict      bool                  `json:"conflict"`
	Contributions []GPModelContribution `json:"contributions"`
}
type GPModelSetting struct {
	ALTSetting
	Sources   []ScopeLink    `json:"sources"`
	Conflicts []GPModelValue `json:"conflicts"`
}
type GPModelSection struct {
	Scope      string           `json:"scope"`
	Container  string           `json:"container"`
	Links      []ScopeLink      `json:"links"`
	Values     []GPModelValue   `json:"values"`
	Settings   []GPModelSetting `json:"settings"`
	Incomplete bool             `json:"incomplete"`
	Warnings   []string         `json:"warnings"`
}
type GPModelReport struct {
	GeneratedAt    time.Time        `json:"generatedAt"`
	Scenario       GPModelInput     `json:"scenario"`
	Controller     string           `json:"controller"`
	TemplateSource string           `json:"templateSource"`
	Sections       []GPModelSection `json:"sections"`
	Limitations    []string         `json:"limitations"`
}

func validateModelInput(in GPModelInput) error {
	if in.User == "" && in.Computer == "" {
		return topologyBad("select a user/computer or their domain/OU")
	}
	if (in.UserOU != "" && in.User == "") || (in.ComputerOU != "" && in.Computer == "") {
		return topologyBad("OU override requires a target")
	}
	if in.Loopback != "none" && in.Loopback != "merge" && in.Loopback != "replace" {
		return topologyBad("loopback must be none, merge or replace")
	}
	if in.Loopback != "none" && (in.User == "" || in.Computer == "") {
		return topologyBad("loopback requires both user and computer targets")
	}
	for _, v := range []string{in.Security, in.WMI} {
		if v != "unknown" && v != "allow" && v != "deny" {
			return topologyBad("filter outcome must be unknown, allow or deny")
		}
	}
	for _, m := range []map[string]string{in.SecurityOverrides, in.WMIOverrides} {
		if len(m) > 1024 {
			return topologyBad("too many filter overrides")
		}
		seen := map[string]bool{}
		for k, v := range m {
			if !looksLikeGUID(k) || (v != "unknown" && v != "allow" && v != "deny") {
				return topologyBad("invalid GPO filter override")
			}
			key := strings.ToLower(braceGUID(k))
			if seen[key] {
				return topologyBad("duplicate GPO filter override")
			}
			seen[key] = true
		}
	}
	return nil
}
func modelOutcome(fallback string, overrides map[string]string, guid string) string {
	for k, v := range overrides {
		if strings.EqualFold(braceGUID(k), braceGUID(guid)) {
			return v
		}
	}
	return fallback
}
func (s *GPOService) modelContainer(ctx context.Context, model *GPScope, target, override, scope string) (string, error) {
	if target == "" {
		return "", nil
	}
	dn, e := ldap.ParseDN(target)
	base, be := ldap.ParseDN(s.ldap.BaseDN())
	if e != nil || be != nil || (!base.EqualFold(dn) && !base.AncestorOfFold(dn)) {
		return "", topologyBad("target must be in this domain")
	}
	container := ""
	for _, c := range model.Containers {
		if dnEqual(c.DN, target) {
			container = c.DN
			break
		}
	}
	if container == "" {
		filter := "(&(objectClass=user)(!(objectClass=computer)))"
		if scope == "Machine" {
			filter = "(objectClass=computer)"
		}
		entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: target, Scope: ldapproto.ScopeBase(), Filter: filter, Attributes: []string{"objectClass"}})
		if err != nil {
			return "", err
		}
		parent, err := parentDN(entry.DN)
		if err != nil {
			return "", err
		}
		// CN=Users and CN=Computers do not carry GPO links; walk to a domain/OU.
		for parent != "" && container == "" {
			for _, c := range model.Containers {
				if dnEqual(c.DN, parent) {
					container = c.DN
					break
				}
			}
			parent, _ = parentDN(parent)
		}
	}
	if override != "" {
		container = ""
		for _, c := range model.Containers {
			if dnEqual(c.DN, override) {
				container = c.DN
				break
			}
		}
	}
	if container == "" {
		return "", topologyBad("select a domain or OU from this domain")
	}
	return container, nil
}
func modelLinks(model *GPScope, container, computer, scope string, in GPModelInput) ([]ScopeLink, error) {
	links, err := ScopeInheritance(model, container)
	if err != nil {
		return nil, err
	}
	if scope == "User" && in.Loopback != "none" {
		computerLinks, e := ScopeInheritance(model, computer)
		if e != nil {
			return nil, e
		}
		if in.Loopback == "replace" {
			links = computerLinks
		} else {
			links = append(computerLinks, links...)
		}
	}
	for i := range links {
		l := &links[i]
		if l.Reason != "candidate" {
			continue
		}
		mask := 2
		if scope == "User" {
			mask = 1
		}
		switch {
		case l.Flags & ^3 != 0:
			l.Reason = "unknown-flags"
		case l.Flags&mask != 0:
			l.Reason = "section-disabled"
		case modelOutcome(in.Security, in.SecurityOverrides, l.GUID) == "deny":
			l.Reason = "security-denied"
		case modelOutcome(in.Security, in.SecurityOverrides, l.GUID) == "unknown":
			l.Reason = "security-unknown"
		case l.WMI != "" && modelOutcome(in.WMI, in.WMIOverrides, l.GUID) == "deny":
			l.Reason = "wmi-false"
		case l.WMI != "" && modelOutcome(in.WMI, in.WMIOverrides, l.GUID) == "unknown":
			l.Reason = "wmi-unknown"
		default:
			l.Reason = "applied"
		}
	}
	return links, nil
}

// Model reads LDAP/SYSVOL only. It does not save GPOs, move objects or run gpupdate.
func (s *GPOService) Model(ctx context.Context, in GPModelInput) (*GPModelReport, error) {
	if err := validateModelInput(in); err != nil {
		return nil, err
	}
	model, err := s.Scope(ctx)
	if err != nil {
		return nil, err
	}
	user, err := s.modelContainer(ctx, model, in.User, in.UserOU, "User")
	if err != nil {
		return nil, err
	}
	computer, err := s.modelContainer(ctx, model, in.Computer, in.ComputerOU, "Machine")
	if err != nil {
		return nil, err
	}
	report := &GPModelReport{GeneratedAt: time.Now().UTC(), Scenario: in, Sections: []GPModelSection{}, Limitations: []string{
		"Simulation of domain/OU Registry.pol and supported ALT ADMX settings; verify actual application on the ALT/Windows client.",
		"Security (including GPO/SYSVOL read access) and WMI outcomes are explicit scenario assumptions; unknown outcomes make the section incomplete.",
		"Site policies, local policies, scripts, preferences, security templates, slow-link behavior and other client extensions are not evaluated.",
		"Loopback is selected explicitly; compatibility and loopback support depend on the client's policy engine. LDAP/SYSVOL may change during the read.",
	}}
	for _, item := range []struct{ scope, container string }{{"Machine", computer}, {"User", user}} {
		if item.container == "" {
			continue
		}
		links, e := modelLinks(model, item.container, computer, item.scope, in)
		if e != nil {
			return nil, e
		}
		report.Sections = append(report.Sections, GPModelSection{Scope: item.scope, Container: item.container, Links: links, Values: []GPModelValue{}, Settings: []GPModelSetting{}, Warnings: []string{}})
	}
	if !s.gpoCfg.EditorEnabled || s.remote == nil {
		return nil, ErrEditorUnavailable
	}
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	err = s.remote.SYSVOL(ctx, s.gpoCfg.SMBPort, func(share *smb2.Share) error {
		dns, e := s.domainDNS(ctx)
		if e != nil {
			return e
		}
		defs, source, e := s.editorDefinitions(share, dns)
		if e != nil {
			return e
		}
		report.TemplateSource = source
		report.Controller = s.remote.Host
		for i := range report.Sections {
			section := &report.Sections[i]
			records := map[string][]policy.Record{}
			for j := range section.Links {
				l := &section.Links[j]
				if l.Reason != "applied" {
					if l.Reason == "security-unknown" || l.Reason == "wmi-unknown" || l.Reason == "unknown-options" || l.Reason == "unknown-flags" || l.Reason == "missing" {
						section.Incomplete = true
					}
					continue
				}
				id := strings.ToLower(l.GUID)
				if _, ok := records[id]; ok {
					continue
				}
				snap, e := s.editorSnapshot(ctx, l.GUID, share, false, section.Scope)
				if e != nil {
					l.Reason = "read-error"
					section.Incomplete = true
					section.Warnings = append(section.Warnings, fmt.Sprintf("%s: %v", l.Name, e))
					continue
				}
				records[id] = snap.records
			}
			mergeModelSection(section, records, defs)
		}
		return nil
	})
	return report, err
}
func modelRecordID(r policy.Record) string {
	name := r.Name
	if strings.HasPrefix(strings.ToLower(name), "**del.") {
		name = name[6:]
	}
	return strings.ToLower(r.Key + "\x00" + name)
}
func modelValueText(r policy.Record) string {
	switch r.Type {
	case 1, 2, 7:
		if len(r.Data)%2 == 0 {
			chars := make([]uint16, len(r.Data)/2)
			for i := range chars {
				chars[i] = binary.LittleEndian.Uint16(r.Data[2*i:])
			}
			return strings.TrimRight(strings.ReplaceAll(string(utf16.Decode(chars)), "\x00", "\n"), "\n")
		}
	case 4:
		if len(r.Data) == 4 {
			return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(r.Data)), 10)
		}
	case 11:
		if len(r.Data) == 8 {
			return strconv.FormatUint(binary.LittleEndian.Uint64(r.Data), 10)
		}
	}
	return "0x" + hex.EncodeToString(r.Data)
}
func mergeModelSection(section *GPModelSection, byGPO map[string][]policy.Record, defs []policy.Definition) {
	// Links are highest precedence first. A deletion and a value share an identity.
	effective := map[string]policy.Record{}
	values := map[string]*GPModelValue{}
	seen := map[string]bool{}
	for _, l := range section.Links {
		if l.Reason != "applied" {
			continue
		}
		guid := strings.ToLower(l.GUID)
		if seen[guid] {
			continue
		}
		seen[guid] = true
		records := byGPO[guid]
		localSeen := map[string]bool{}
		// Within a Registry.pol the last record for a value takes precedence.
		for i := len(records) - 1; i >= 0; i-- {
			r := records[i]
			lower := strings.ToLower(r.Name)
			if strings.HasPrefix(lower, "**") && !strings.HasPrefix(lower, "**del.") {
				section.Incomplete = true
				section.Warnings = append(section.Warnings, fmt.Sprintf("%s: unsupported registry directive %s\\%s", l.Name, r.Key, r.Name))
				continue
			}
			if strings.HasPrefix(lower, "**del.") && (r.Type != 1 || len(r.Data) < 2 || len(r.Data)%2 != 0 || (modelValueText(r) != " " && modelValueText(r) != "")) {
				section.Incomplete = true
				section.Warnings = append(section.Warnings, fmt.Sprintf("%s: malformed registry deletion %s\\%s", l.Name, r.Key, r.Name))
				continue
			}
			id := modelRecordID(r)
			if localSeen[id] {
				continue
			}
			localSeen[id] = true
			contribution := GPModelContribution{Source: l, Type: r.Type, Value: modelValueText(r), Deleted: strings.HasPrefix(lower, "**del.")}
			if v, ok := values[id]; ok {
				v.Precedence = append(v.Precedence, l)
				v.Contributions = append(v.Contributions, contribution)
				winner := effective[id]
				if v.Deleted != contribution.Deleted || (!v.Deleted && (winner.Type != r.Type || !bytes.Equal(winner.Data, r.Data))) {
					v.Conflict = true
				}
				continue
			}
			effective[id] = r
			name := r.Name
			deleted := strings.HasPrefix(lower, "**del.")
			if deleted {
				name = name[6:]
			}
			values[id] = &GPModelValue{Key: r.Key, Name: name, Type: r.Type, Data: r.Data, Value: modelValueText(r), Deleted: deleted, Winner: l, Precedence: []ScopeLink{l}, Contributions: []GPModelContribution{contribution}}
		}
	}
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	merged := make([]policy.Record, 0, len(ids))
	for _, id := range ids {
		section.Values = append(section.Values, *values[id])
		merged = append(merged, effective[id])
	}
	for _, d := range defs {
		if d.Scope != section.Scope {
			continue
		}
		state, settings := policy.SettingState(d, merged)
		if state == "not-configured" {
			continue
		}
		sources := []ScopeLink{}
		conflicts := []GPModelValue{}
		used := map[string]bool{}
		for _, id := range ids {
			if policy.SettingOwnsRecord(d, effective[id]) {
				if values[id].Conflict {
					conflicts = append(conflicts, *values[id])
				}
				l := values[id].Winner
				key := strings.ToLower(l.GUID)
				if !used[key] {
					sources = append(sources, l)
					used[key] = true
				}
			}
		}
		if len(sources) == 0 {
			continue
		}
		section.Settings = append(section.Settings, GPModelSetting{ALTSetting: ALTSetting{Definition: d, State: state, Values: settings}, Sources: sources, Conflicts: conflicts})
	}
}
