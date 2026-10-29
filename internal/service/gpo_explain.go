package service

import (
	"context"
	"strings"
	"time"
)

// GPExplainInput uses actual targets/locations, without hypothetical filter outcomes.
type GPExplainInput struct {
	User     string `json:"user"`
	Computer string `json:"computer"`
}
type GPExplainCheck struct {
	Code   string `json:"code"`
	State  string `json:"state"` // pass, fail, unknown
	Detail string `json:"detail,omitempty"`
}
type GPExplainLink struct {
	ScopeLink
	Status          string           `json:"status"` // excluded, conditional
	Priority        int              `json:"priority,omitempty"`
	ProcessingOrder int              `json:"processingOrder,omitempty"`
	Checks          []GPExplainCheck `json:"checks"`
}
type GPExplainSection struct {
	Scope     string          `json:"scope"`
	Target    string          `json:"target"`
	Container string          `json:"container"`
	Path      []GPContainer   `json:"path"`
	Links     []GPExplainLink `json:"links"`
}
type GPExplainReport struct {
	GeneratedAt time.Time          `json:"generatedAt"`
	Sections    []GPExplainSection `json:"sections"`
	Limitations []string           `json:"limitations"`
}

// Explain only reads LDAP. A conditional link is not proof of client application.
func (s *GPOService) Explain(ctx context.Context, in GPExplainInput) (*GPExplainReport, error) {
	if in.User == "" && in.Computer == "" {
		return nil, topologyBad("select a user or computer")
	}
	model, err := s.Scope(ctx)
	if err != nil {
		return nil, err
	}
	report := &GPExplainReport{GeneratedAt: time.Now().UTC(), Sections: []GPExplainSection{}, Limitations: []string{
		"ldap-only", "security-token-and-sysvol-not-evaluated", "wmi-not-evaluated", "site-local-loopback-not-evaluated", "client-execution-not-confirmed", "non-atomic-directory-snapshot",
	}}
	for _, target := range []struct{ scope, dn string }{{"Machine", in.Computer}, {"User", in.User}} {
		if target.dn == "" {
			continue
		}
		container, err := s.modelContainer(ctx, model, target.dn, "", target.scope)
		if err != nil {
			return nil, err
		}
		section, err := explainScope(model, container, target.scope)
		if err != nil {
			return nil, err
		}
		section.Target = target.dn
		report.Sections = append(report.Sections, *section)
	}
	return report, nil
}

func explainScope(model *GPScope, container, scope string) (*GPExplainSection, error) {
	links, err := ScopeInheritance(model, container)
	if err != nil {
		return nil, err
	}
	section := &GPExplainSection{Scope: scope, Container: container, Path: []GPContainer{}, Links: []GPExplainLink{}}
	// ScopeInheritance has already validated the hierarchy and bounded its depth.
	for dn := container; dn != ""; {
		for _, c := range model.Containers {
			if dnEqual(dn, c.DN) {
				section.Path = append([]GPContainer{c}, section.Path...)
				dn = c.Parent
				break
			}
		}
	}
	seen := map[string]bool{}
	priority := 0
	for _, l := range links {
		row := GPExplainLink{ScopeLink: l, Status: "conditional", Checks: []GPExplainCheck{}}
		check := func(code, state, detail string) { row.Checks = append(row.Checks, GPExplainCheck{code, state, detail}) }
		if l.Options & ^uint32(3) != 0 {
			check("link-options", "unknown", "")
		} else {
			check("link-options", "pass", "")
		}
		if l.Enabled {
			check("link-enabled", "pass", "")
		} else {
			check("link-enabled", "fail", "")
		}
		if l.Missing {
			check("policy-exists", "unknown", l.DN)
		} else {
			check("policy-exists", "pass", l.DN)
		}
		blocker := ""
		below := false
		for _, c := range section.Path {
			if below && c.Block {
				blocker = c.DN
			}
			if dnEqual(c.DN, l.Source) {
				below = true
			}
		}
		if blocker != "" && !l.Enforced {
			check("inheritance", "fail", blocker)
		} else if l.Enforced {
			check("enforced", "pass", l.Source)
		} else {
			check("inheritance", "pass", l.Source)
		}
		mask := 2
		if scope == "User" {
			mask = 1
		}
		if l.Missing || l.Flags & ^3 != 0 {
			check("section-enabled", "unknown", scope)
		} else if l.Flags&mask != 0 {
			check("section-enabled", "fail", scope)
		} else {
			check("section-enabled", "pass", scope)
		}
		// Report every condition, even when an earlier condition already excludes it.
		check("security", "unknown", "")
		check("sysvol", "unknown", "")
		if l.WMI != "" {
			check("wmi", "unknown", l.WMI)
		} else if !l.Missing {
			check("no-wmi-filter", "pass", "")
		}
		for _, c := range row.Checks {
			if c.State == "fail" {
				row.Status = "excluded"
				break
			}
		}
		if row.Status != "excluded" {
			key := strings.ToLower(l.GUID)
			// Unresolved links cannot safely be deduplicated or assigned a priority.
			if l.Reason == "candidate" && l.Flags & ^3 == 0 {
				if seen[key] {
					row.Status = "excluded"
					check("higher-priority-link", "fail", l.GUID)
				} else {
					seen[key] = true
					priority++
					row.Priority = priority
				}
			}
		}
		section.Links = append(section.Links, row)
	}
	for i := range section.Links {
		if section.Links[i].Priority > 0 {
			section.Links[i].ProcessingOrder = priority - section.Links[i].Priority + 1
		}
	}
	return section, nil
}
