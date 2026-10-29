package service

import "testing"

func TestExplainInheritanceAndAllConditions(t *testing.T) {
	model := &GPScope{Containers: []GPContainer{
		{DN: "DC=test", Links: []ScopeLink{
			{GUID: modelHigh, Name: "enforced", Enabled: true, Enforced: true},
			{GUID: modelLow, Name: "blocked", Enabled: true, WMI: "WMI-reference"},
		}},
		{DN: "OU=PC,DC=test", Parent: "DC=test", Block: true, Links: []ScopeLink{
			{GUID: "local", Name: "local", Enabled: true},
			{GUID: "off", Name: "off", Enabled: true, Flags: 2},
			{GUID: "disabled", Name: "disabled", Enabled: false},
		}},
	}}
	section, err := explainScope(model, "OU=PC,DC=test", "Machine")
	if err != nil {
		t.Fatal(err)
	}
	if len(section.Path) != 2 || section.Path[0].DN != "DC=test" || len(section.Links) != 5 {
		t.Fatalf("%+v", section)
	}
	rows := map[string]GPExplainLink{}
	for _, l := range section.Links {
		rows[l.Name] = l
	}
	if rows["enforced"].Priority != 1 || rows["enforced"].ProcessingOrder != 2 || rows["local"].Priority != 2 || rows["local"].ProcessingOrder != 1 {
		t.Fatal(rows)
	}
	for _, name := range []string{"blocked", "off", "disabled"} {
		if rows[name].Status != "excluded" || rows[name].Priority != 0 {
			t.Fatal(rows[name])
		}
	}
	foundBlock, foundWMI, foundSecurity := false, false, false
	for _, c := range rows["blocked"].Checks {
		if c.Code == "inheritance" {
			foundBlock = c.State == "fail" && c.Detail == "OU=PC,DC=test"
		}
		if c.Code == "wmi" {
			foundWMI = c.State == "unknown" && c.Detail == "WMI-reference"
		}
		if c.Code == "security" {
			foundSecurity = c.State == "unknown"
		}
	}
	if !foundBlock || !foundWMI || !foundSecurity {
		t.Fatal(rows["blocked"])
	}
	// Machine-disabled must not exclude the User section.
	section, err = explainScope(model, "OU=PC,DC=test", "User")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range section.Links {
		if l.Name == "off" && l.Status != "conditional" {
			t.Fatal(l)
		}
	}
}
func TestExplainUncertaintyAndRepeatedPolicy(t *testing.T) {
	model := &GPScope{Containers: []GPContainer{{DN: "DC=test", Links: []ScopeLink{
		{GUID: modelHigh, Name: "first", Enabled: true},
		{GUID: modelHigh, Name: "repeat", Enabled: true},
		{Name: "missing", Enabled: true, Missing: true},
		{GUID: modelLow, Name: "unknown-flags", Enabled: true, Flags: -1},
		{GUID: "options", Name: "unknown-options", Enabled: true, Options: 4},
	}}}}
	section, err := explainScope(model, "DC=test", "Machine")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range section.Links {
		if l.Name == "first" {
			if l.Status != "conditional" || l.Priority != 1 || l.ProcessingOrder != 1 {
				t.Fatal(l)
			}
			continue
		}
		if l.Priority != 0 || l.ProcessingOrder != 0 {
			t.Fatal(l)
		}
		if l.Name == "repeat" {
			if l.Status != "excluded" {
				t.Fatal(l)
			}
		} else if l.Status != "conditional" {
			t.Fatal(l)
		}
	}
}
func TestExplainInvalidHierarchy(t *testing.T) {
	_, err := explainScope(&GPScope{Containers: []GPContainer{{DN: "DC=test", Parent: "DC=test"}}}, "DC=test", "User")
	if err == nil {
		t.Fatal("cycle accepted")
	}
}
