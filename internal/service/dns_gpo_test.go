package service

import "testing"

func TestParseDNSZoneList(t *testing.T) {
	in := `
  pszZoneName                 : example.com
  pszZoneName                 : _msdcs.example.com
`
	got := parseDNSZoneList(in)
	if len(got) != 2 {
		t.Fatalf("got %d zones: %#v", len(got), got)
	}
	if got[0].Name != "example.com" {
		t.Fatalf("got %q", got[0].Name)
	}
}

func TestSplitDNSData(t *testing.T) {
	got := splitDNSData("10 20 389 dc1.example.com")
	if len(got) != 4 {
		t.Fatalf("got %#v", got)
	}
}

func TestParseGPOListAll(t *testing.T) {
	in := `
GPO          : {31B2F340-016D-11D2-945F-00C04FB984F9}
display name : Default Domain Policy

GPO          : {6AC1786C-016F-11D2-945F-00C04FB984F9}
display name : Default Domain Controllers Policy
`
	got := parseGPOListAll(in)
	if len(got) != 2 {
		t.Fatalf("got %d: %#v", len(got), got)
	}
	if got[0].DisplayName != "Default Domain Policy" {
		t.Fatalf("got %#v", got[0])
	}
}
