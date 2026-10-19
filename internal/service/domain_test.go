package service

import "testing"

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
