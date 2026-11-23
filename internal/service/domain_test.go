package service

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestParseFSMOShow(t *testing.T) {
	in := `SchemaMasterRole owner: CN=NTDS Settings,CN=DC1
PDCEmulatorRole owner: CN=NTDS Settings,CN=DC1
`
	got := parseFSMOShow(in)
	if len(got) < 2 {
		t.Fatalf("got %d roles", len(got))
	}
	if got[0].Owner == "" || got[0].Source != "samba-tool" {
		t.Fatalf("unexpected %#v", got[0])
	}
}

func TestTrustDirectionName(t *testing.T) {
	if TrustDirectionName("3") != "bidirectional" {
		t.Fatal("expected bidirectional")
	}
}

func TestTrustScope(t *testing.T) {
	for _, tc := range []struct{ ldapType, attributes, want string }{
		{"2", "4", "external"},
		{"2", "8", "forest"},
		{"2", "32", "within_forest"},
		{"2", "0", "external"},
		{"2", "", ""},
		{"3", "0", ""},
	} {
		entry := ldap.NewEntry("CN=partner,CN=System,DC=example", map[string][]string{
			"trustType": {tc.ldapType}, "trustAttributes": {tc.attributes},
		})
		if got := entryToTrust(entry).Scope; got != tc.want {
			t.Errorf("type %q, attributes %q: scope %q, want %q", tc.ldapType, tc.attributes, got, tc.want)
		}
	}
}

func TestConfigDN(t *testing.T) {
	if ConfigDN("DC=ex,DC=com") != "CN=Configuration,DC=ex,DC=com" {
		t.Fatal("bad config dn")
	}
}

func TestNormalizeDisplayedFSMORoles(t *testing.T) {
	for input, want := range map[string]string{"SchemaMasterRole": "schema", "DomainNamingMasterRole": "naming", "PdcEmulationMasterRole": "pdc", "RidAllocationMasterRole": "rid", "InfrastructureMasterRole": "infrastructure", "DomainDnsZonesMasterRole": "domaindns", "ForestDnsZonesMasterRole": "forestdns", "pdc": "pdc"} {
		if got := normalizeFSMORole(input); got != want {
			t.Errorf("%s: %s, want %s", input, got, want)
		}
	}
}

func TestFSMOTargetRejectsUnregisteredAndReadOnlyControllers(t *testing.T) {
	controllers := []Controller{{DNS: "dc1.example.test", NTDS: "CN=NTDS Settings,CN=DC1"}, {DNS: "rodc.example.test", NTDS: "CN=NTDS Settings,CN=RODC", RODC: true}, {DNS: "incomplete.example.test"}, {DNS: "evil.example.test/path", NTDS: "CN=NTDS Settings,CN=Evil"}}
	for _, target := range []string{"", "unknown.example.test", "ldaps://dc1.example.test", "rodc.example.test", "incomplete.example.test", "evil.example.test/path"} {
		if _, err := fsmoTarget(controllers, target); err == nil {
			t.Errorf("accepted unsafe target %q", target)
		}
	}
	dc, err := fsmoTarget(controllers, "DC1.EXAMPLE.TEST")
	if err != nil || dc.DNS != "dc1.example.test" {
		t.Fatalf("catalogued RWDC: %v, %v", dc, err)
	}
}
