package service

import (
	"context"
	"github.com/go-ldap/ldap/v3"
	"strings"
	"testing"
	"time"
)

func TestRODCPolicyUsesFullTokenAndDenyWins(t *testing.T) {
	// S-1-5-32-545, representing a nested/primary token group, not memberOf.
	group := []byte{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0}
	principal := RODCPrincipal{SID: "S-1-5-21-123-1000"}
	allowed := []RODCPrincipal{{SID: principal.SID}}
	denied := []RODCPrincipal{{SID: sidString(group)}}
	decision, _, _ := rodcDecision(principal, [][]byte{group}, allowed, denied)
	if decision != "denied" {
		t.Fatal("nested deny ignored", decision)
	}
	if decision, _, _ := rodcDecision(principal, nil, allowed, nil); decision != "unknown" {
		t.Fatal("incomplete token allowed", decision)
	}
	if decision, _, _ := rodcDecision(principal, [][]byte{group}, allowed, nil); decision != "allowed" {
		t.Fatal(decision)
	}
}
func TestRODCRevealedDNBinariesAndIncompleteRanges(t *testing.T) {
	dn := "CN=Alice,CN=Users,DC=example,DC=com"
	if got, e := rodcRevealedDN("B:4:0ABC:" + dn); e != nil || got != dn {
		t.Fatal(got, e)
	}
	for _, v := range []string{dn, "B:5:ABCD:" + dn, "B:2:ZZ:" + dn, "B:2:AA:not a DN"} {
		if _, e := rodcRevealedDN(v); e == nil {
			t.Fatal("malformed DN-Binary accepted", v)
		}
	}
	entry := ldap.NewEntry(dn, map[string][]string{"msDS-RevealedUsers;range=0-1499": {dn}})
	if _, e := rodcValues(entry, "msDS-RevealedUsers"); e == nil {
		t.Fatal("incomplete range silently accepted")
	}
}
func TestRODCAuthenticationJSONFiltersAndSambaTimeFormat(t *testing.T) {
	log := `[2026] {"timestamp":"2026-11-03T12:00:00.123456+0000","type":"Authentication","Authentication":{"clientAccount":"alice","clientDomain":"EXAMPLE","status":"NT_STATUS_OK","remoteAddress":"ipv4:10.0.0.5:1"}}
{"timestamp":"2026-11-03T12:01:00Z","type":"Authentication","Authentication":{"clientAccount":"alice","status":"NT_STATUS_WRONG_PASSWORD"}}
{"timestamp":"2026-11-03T12:02:00Z","type":"Authorization"}
{"bad json"
`
	events, bad, truncated, e := readRODCAuth(context.Background(), strings.NewReader(log), time.Time{}, "alice")
	if e != nil || len(events) != 2 || bad != 1 || truncated || events[0].Status != "NT_STATUS_WRONG_PASSWORD" {
		t.Fatalf("%+v %d %v %v", events, bad, truncated, e)
	}
	cutoff, _ := time.Parse(time.RFC3339, "2026-11-03T12:00:30Z")
	events, _, _, e = readRODCAuth(context.Background(), strings.NewReader(log), cutoff, "alice")
	if e != nil || len(events) != 1 {
		t.Fatal(events, e)
	}
}
func TestHelperSYSVOLPathCannotEscapePrefix(t *testing.T) {
	for _, p := range []string{"../secret", "example.com/Policies/../other", "other.com/Policies/x", `example.com\Policies\x:stream`, "/example.com/Policies/x"} {
		if _, e := helperSYSVOLPath("example.com/Policies", p); e == nil {
			t.Fatal("unsafe path accepted", p)
		}
	}
	if _, e := helperSYSVOLPath("example.com/Policies", `example.com\Policies\{GUID}\GPT.INI`); e != nil {
		t.Fatal(e)
	}
}
