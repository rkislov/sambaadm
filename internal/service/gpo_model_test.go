package service

import (
	"encoding/json"
	"strings"
	"testing"

	"sambaadm/internal/policy"
)

const modelHigh = "{00000000-0000-0000-0000-000000000001}"
const modelLow = "{00000000-0000-0000-0000-000000000002}"

func modelTestSection() GPModelSection {
	return GPModelSection{Scope: "Machine", Links: []ScopeLink{{GUID: modelHigh, Name: "OU policy", Source: "OU=Workstations,DC=test", Order: 1, Reason: "applied"}, {GUID: modelLow, Name: "Domain policy", Source: "DC=test", Order: 2, Reason: "applied"}}}
}
func modelDWORD(name string, v byte) policy.Record {
	return policy.Record{Key: policy.SystemdKey, Name: name, Type: 4, Data: []byte{v, 0, 0, 0}}
}
func TestModelALTConflictsAndIdenticalValues(t *testing.T) {
	section := modelTestSection()
	definitions := []policy.Definition{
		{ID: "chrony", Label: "Time synchronization", Scope: "Machine", Key: policy.SystemdKey, Value: "chronyd.service"},
		{ID: "sshd", Scope: "Machine", Key: policy.SystemdKey, Value: "sshd.service"},
		{ID: "unconfigured", Scope: "Machine", Key: policy.SystemdKey, Value: "missing.service"},
		{ID: "unsupported-unconfigured", Scope: "Machine", Key: "Other", Value: "Missing", Unsupported: "unsupported template"},
	}
	mergeModelSection(&section, map[string][]policy.Record{
		modelHigh: {modelDWORD("chronyd.service", 0), modelDWORD("sshd.service", 1)},
		modelLow:  {modelDWORD("CHRONYD.SERVICE", 1), modelDWORD("sshd.service", 1)},
	}, definitions)
	if section.Incomplete || len(section.Settings) != 2 || len(section.Values) != 2 {
		t.Fatalf("%+v", section)
	}
	chrony := section.Settings[0]
	if chrony.State != "disabled" || len(chrony.Conflicts) != 1 || chrony.Sources[0].GUID != modelHigh {
		t.Fatalf("ALT winner: %+v", chrony)
	}
	conflict := chrony.Conflicts[0]
	if !conflict.Conflict || conflict.Winner.GUID != modelHigh || len(conflict.Contributions) != 2 || conflict.Contributions[0].Value != "0" || conflict.Contributions[1].Value != "1" {
		t.Fatalf("conflict: %+v", conflict)
	}
	if len(section.Settings[1].Conflicts) != 0 {
		t.Fatal("identical values were marked as a conflict")
	}
}
func TestModelDeletionOverridesAndDuplicateLinks(t *testing.T) {
	section := modelTestSection()
	section.Links = append(section.Links, section.Links[0])
	deletion := policy.Record{Key: policy.SystemdKey, Name: "**del.chronyd.service", Type: 1, Data: []byte{' ', 0, 0, 0}}
	mergeModelSection(&section, map[string][]policy.Record{modelHigh: {modelDWORD("chronyd.service", 1), deletion}, modelLow: {modelDWORD("chronyd.service", 1)}}, []policy.Definition{{ID: "chrony", Scope: "Machine", Key: policy.SystemdKey, Value: "chronyd.service"}})
	if len(section.Values) != 1 || !section.Values[0].Deleted || !section.Values[0].Conflict || len(section.Values[0].Contributions) != 2 || section.Settings[0].State != "disabled" {
		t.Fatalf("%+v", section)
	}
}
func TestModelALTMultipleFieldsMergeByRegistryValue(t *testing.T) {
	defs, err := policy.ParseADMX("BaseALTEditorTest.admx", []byte(typedEditorADMX), nil)
	if err != nil || len(defs) != 2 {
		t.Fatalf("%+v %v", defs, err)
	}
	var def policy.Definition
	for _, d := range defs {
		if d.Scope == "Machine" {
			def = d
		}
	}
	records, err := policy.ApplySetting(def, nil, "enabled", map[string]json.RawMessage{"text": json.RawMessage(`"domain text"`), "number": json.RawMessage(`"5"`), "mode": json.RawMessage(`"1"`), "lock": json.RawMessage(`true`), "packages": json.RawMessage(`["curl","vim"]`)})
	if err != nil {
		t.Fatal(err)
	}
	high := policy.Record{Key: `Software\BaseALT\EditorTest`, Name: "Count", Type: 4, Data: []byte{9, 0, 0, 0}}
	section := modelTestSection()
	mergeModelSection(&section, map[string][]policy.Record{modelHigh: {high}, modelLow: records}, defs)
	if len(section.Settings) != 1 {
		t.Fatalf("%+v", section)
	}
	got := section.Settings[0]
	if got.State != "enabled" || got.Values["text"] != "domain text" || len(got.Sources) != 2 || len(got.Conflicts) != 1 {
		t.Fatalf("%+v", got)
	}
	if got.Conflicts[0].Value != "9" {
		t.Fatal(got.Conflicts)
	}
}
func TestModelUnsupportedDirectiveMakesReportIncomplete(t *testing.T) {
	section := modelTestSection()
	mergeModelSection(&section, map[string][]policy.Record{modelHigh: {{Key: "Software", Name: "**DeleteValues", Type: 1}}}, nil)
	if !section.Incomplete || len(section.Warnings) != 1 || len(section.Values) != 0 {
		t.Fatalf("%+v", section)
	}
}
func TestModelLinksFilteringAndLoopback(t *testing.T) {
	model := &GPScope{Containers: []GPContainer{
		{DN: "DC=test", Links: []ScopeLink{{GUID: modelLow, Name: "domain", Enabled: true}}},
		{DN: "OU=Users,DC=test", Parent: "DC=test", Links: []ScopeLink{{GUID: modelHigh, Name: "user", Enabled: true, Flags: 1}}},
		{DN: "OU=PC,DC=test", Parent: "DC=test", Block: true, Links: []ScopeLink{{GUID: modelHigh, Name: "computer", Enabled: true, WMI: "filter"}}},
	}}
	in := GPModelInput{User: "OU=Users,DC=test", Computer: "OU=PC,DC=test", Security: "allow", WMI: "allow", Loopback: "none"}
	links, e := modelLinks(model, in.User, in.Computer, "User", in)
	if e != nil || links[0].Reason != "section-disabled" || links[1].Reason != "applied" {
		t.Fatalf("%+v %v", links, e)
	}
	in.Loopback = "merge"
	links, e = modelLinks(model, in.User, in.Computer, "User", in)
	if e != nil || links[0].Name != "computer" || links[0].Reason != "applied" || links[1].Reason != "blocked" || links[2].Name != "user" {
		t.Fatalf("%+v %v", links, e)
	}
	in.Loopback = "replace"
	in.WMI = "unknown"
	links, e = modelLinks(model, in.User, in.Computer, "User", in)
	if e != nil || len(links) != 2 || links[0].Reason != "wmi-unknown" {
		t.Fatalf("%+v %v", links, e)
	}
	in.WMIOverrides = map[string]string{strings.Trim(modelHigh, "{}"): "deny"}
	links, _ = modelLinks(model, in.User, in.Computer, "User", in)
	if links[0].Reason != "wmi-false" {
		t.Fatal(links)
	}
	in.SecurityOverrides = map[string]string{modelHigh: "deny"}
	links, _ = modelLinks(model, in.User, in.Computer, "User", in)
	if links[0].Reason != "security-denied" {
		t.Fatal(links)
	}
	in.Security = "unknown"
	in.SecurityOverrides = nil
	links, _ = modelLinks(model, in.User, in.Computer, "Machine", in)
	if links[0].Reason != "security-unknown" || links[1].Reason != "security-unknown" {
		t.Fatal(links)
	}

}
func TestModelInputValidation(t *testing.T) {
	valid := GPModelInput{Computer: "DC=test", Loopback: "none", Security: "unknown", WMI: "unknown"}
	if e := validateModelInput(valid); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*GPModelInput){
		func(in *GPModelInput) { in.Computer = "" }, func(in *GPModelInput) { in.Loopback = "replace" }, func(in *GPModelInput) { in.Security = "ignore" }, func(in *GPModelInput) { in.UserOU = "DC=test" }, func(in *GPModelInput) { in.WMIOverrides = map[string]string{"invalid": "allow"} },
	} {
		in := valid
		mutate(&in)
		if validateModelInput(in) == nil {
			t.Fatal("accepted invalid scenario", in)
		}
	}
}

func TestModelEnforcedAncestorWinsALTConflict(t *testing.T) {
	model := &GPScope{Containers: []GPContainer{
		{DN: "DC=test", Links: []ScopeLink{{GUID: modelHigh, Name: "Enforced domain", Enabled: true, Enforced: true}}},
		{DN: "OU=PC,DC=test", Parent: "DC=test", Block: true, Links: []ScopeLink{{GUID: modelLow, Name: "Local OU", Enabled: true}}},
	}}
	in := GPModelInput{Computer: "OU=PC,DC=test", Loopback: "none", Security: "allow", WMI: "unknown"}
	links, err := modelLinks(model, in.Computer, "", "Machine", in)
	if err != nil {
		t.Fatal(err)
	}
	section := GPModelSection{Scope: "Machine", Links: links}
	mergeModelSection(&section, map[string][]policy.Record{modelHigh: {modelDWORD("chronyd.service", 1)}, modelLow: {modelDWORD("chronyd.service", 0)}}, []policy.Definition{{ID: "chrony", Scope: "Machine", Key: policy.SystemdKey, Value: "chronyd.service"}})
	if len(section.Settings) != 1 || section.Settings[0].State != "enabled" || len(section.Settings[0].Conflicts) != 1 || !section.Values[0].Winner.Enforced {
		t.Fatalf("%+v", section)
	}
}
func TestModelMalformedDeletionAndDuplicateOverrides(t *testing.T) {
	section := modelTestSection()
	mergeModelSection(&section, map[string][]policy.Record{modelHigh: {{Key: policy.SystemdKey, Name: "**del.chronyd.service", Type: 4, Data: []byte{1, 0, 0, 0}}}, modelLow: {modelDWORD("chronyd.service", 1)}}, nil)
	if !section.Incomplete || len(section.Values) != 1 || section.Values[0].Deleted || section.Values[0].Winner.GUID != modelLow {
		t.Fatalf("%+v", section)
	}
	in := GPModelInput{Computer: "DC=test", Loopback: "none", Security: "unknown", WMI: "unknown", SecurityOverrides: map[string]string{modelHigh: "allow", strings.Trim(modelHigh, "{}"): "deny"}}
	if validateModelInput(in) == nil {
		t.Fatal("accepted ambiguous overrides")
	}
}
