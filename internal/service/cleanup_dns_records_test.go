package service

import (
	"context"
	"encoding/binary"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/testldap"
	"testing"
)

func dnsFixture(typ uint16, data []byte) []byte {
	raw := make([]byte, 24+len(data))
	binary.LittleEndian.PutUint16(raw, uint16(len(data)))
	binary.LittleEndian.PutUint16(raw[2:], typ)
	copy(raw[24:], data)
	return raw
}
func TestCleanupDNSCountedRecords(t *testing.T) {
	name := []byte{18, 3, 4, 'd', 'e', 'a', 'd', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	for _, typ := range []uint16{2, 5, 12, 15, 33} {
		data := name
		if typ == 15 {
			data = append(make([]byte, 2), name...)
		}
		if typ == 33 {
			data = append(make([]byte, 6), name...)
		}
		got, target, e := cleanupDNSRecord(dnsFixture(typ, data))
		if e != nil || got != typ || target != "dead.example.com" {
			t.Fatalf("%d: %s %v", typ, target, e)
		}
	}
	for _, raw := range [][]byte{nil, dnsFixture(5, []byte{255, 1}), dnsFixture(33, []byte{1}), dnsFixture(1, []byte{1}), dnsFixture(5, append(name, 0))} {
		if _, _, e := cleanupDNSRecord(raw); e == nil {
			t.Fatal("malformed record accepted")
		}
	}
}
func TestCleanupReachableControllerVeto(t *testing.T) {
	// Unit checks for the metadata identity gate do not need real DC ports.
	p := executableCleanupPlan()
	dc := Controller{DN: p.Objects[0].DN, NTDS: "CN=NTDS Settings," + p.Objects[0].DN, Computer: "CN=Computer," + p.BaseDN}
	if cleanupRetiredController(p, dc) {
		t.Fatal("site or incomplete metadata authorized exclusion")
	}
	if err := checkRetiredOffline(context.Background(), ""); err == nil {
		t.Fatal("empty hostname accepted")
	}
}

func TestCleanupDNSPlanningPreservesSharedRecords(t *testing.T) {
	name := []byte{18, 3, 4, 'd', 'e', 'a', 'd', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	live := append([]byte(nil), name...)
	copy(live[3:7], []byte("live"))
	deadA := dnsFixture(1, []byte{192, 0, 2, 7})
	liveA := dnsFixture(1, []byte{192, 0, 2, 8})
	deadSRV := dnsFixture(33, append(make([]byte, 6), name...))
	liveSRV := dnsFixture(33, append(make([]byte, 6), live...))
	soa := dnsFixture(6, append(append(make([]byte, 20), name...), live...))
	for _, tc := range []struct {
		name       string
		additional []testldap.Entry
		wantError  bool
	}{
		{name: "shared SRV and domain apex"},
		{name: "reused address", additional: []testldap.Entry{dnsPlanningEntry("live", deadA)}, wantError: true},
		{name: "last NS", additional: []testldap.Entry{dnsPlanningEntry("delegation", dnsFixture(2, name))}, wantError: true},
		{name: "SOA primary", additional: []testldap.Entry{dnsPlanningEntry("other", soa)}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := []testldap.Entry{dnsPlanningEntry("dead", deadA), dnsPlanningEntry("_ldap._tcp", deadSRV, liveSRV), dnsPlanningEntry("@", deadA, liveA)}
			rows = append(rows, tc.additional...)
			server := testldap.New(t, map[string]string{"service": "password"}, func(q testldap.Search) ([]testldap.Entry, int64) {
				if q.BaseDN == "" {
					return []testldap.Entry{{DN: "", Attributes: map[string][]string{"namingContexts": {"DC=example,DC=com"}}}}, 0
				}
				return rows, 0
			})
			client := ldapproto.NewServiceClient(config.LDAPConfig{URI: server.URI(), BaseDN: "DC=example,DC=com", Bind: config.BindConfig{User: "service", Type: "simple"}}, func() string { return "password" })
			defer client.Close()
			p := executableCleanupPlan()
			p.Objects[0].Attributes["objectClass"] = [][]byte{[]byte("server")}
			p.Objects[0].Attributes["dNSHostName"] = [][]byte{[]byte("dead.example.com")}
			e := (&SiteService{ldap: client}).expandRetiredDNS(context.Background(), p)
			if tc.wantError {
				if e == nil {
					t.Fatal("unsafe DNS cleanup allowed")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if len(p.Objects) != 4 {
				t.Fatalf("unexpected plan size: %d", len(p.Objects))
			}
			for _, o := range p.Objects[1:] {
				if len(o.Remove["dnsRecord"]) != 1 {
					t.Fatal("removed unrelated values")
				}
				if len(o.Attributes["dnsRecord"]) == 2 && len(cleanupRemaining(o, "dnsRecord")) != 1 {
					t.Fatal("lost shared record")
				}
			}
		})
	}
}
func dnsPlanningEntry(name string, records ...[]byte) testldap.Entry {
	values := []string{}
	for _, raw := range records {
		values = append(values, string(raw))
	}
	return testldap.Entry{DN: "DC=" + name + ",DC=example.com,CN=MicrosoftDNS,DC=example,DC=com", Attributes: map[string][]string{"objectClass": {"dnsNode"}, "objectGUID": {"0123456789abcdef"}, "uSNChanged": {"10"}, "dnsRecord": values}}
}
