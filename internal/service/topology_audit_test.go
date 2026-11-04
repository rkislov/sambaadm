package service

import (
	"context"
	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/testldap"
	"testing"
)

func TestTopologyAuditFindsStructuralRemnants(t *testing.T) {
	site := "CN=Branch,CN=Sites,CN=Configuration,DC=example,DC=com"
	server := "CN=DC1,CN=Servers," + site
	ntds := "CN=NTDS Settings," + server
	computer := "CN=DC1,OU=Domain Controllers,DC=example,DC=com"
	entry := func(dn, class string, attrs map[string][]string) *ldap.Entry {
		if attrs == nil {
			attrs = map[string][]string{}
		}
		attrs["objectClass"] = []string{class}
		return ldap.NewEntry(dn, attrs)
	}
	entries := []*ldap.Entry{
		entry(site, "site", nil), entry(server, "server", map[string][]string{"serverReference": {computer}}), entry(ntds, "nTDSDSA", nil),
		entry("CN=Broken,"+ntds, "nTDSConnection", map[string][]string{"fromServer": {"CN=NTDS Settings,CN=Removed,CN=Servers," + site}}),
		entry("CN=Staged,CN=Servers,"+site, "server", nil),
		entry("CN=Future,CN=Sites,CN=Configuration,DC=example,DC=com", "site", nil),
		entry("CN=Subnet,CN=Subnets,CN=Sites,CN=Configuration,DC=example,DC=com", "subnet", map[string][]string{"siteObject": {"CN=Missing,CN=Sites,CN=Configuration,DC=example,DC=com"}}),
	}
	findings := analyzeTopology(entries, map[string]string{dnKey(computer): "present"})
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Code]++
		if f.Severity != "review" {
			t.Fatal(f)
		}
	}
	for _, code := range []string{"unresolved_fromServer", "server_without_ntds", "server_without_computer", "site_without_servers", "unresolved_siteObject"} {
		if counts[code] != 1 {
			t.Fatalf("%s: %+v", code, findings)
		}
	}
	if len(findings) != 5 {
		t.Fatal(findings)
	}
	for _, state := range []string{"unknown", "missing"} {
		fs := analyzeTopology(entries[:3], map[string]string{dnKey(computer): state})
		want := "review"
		if state == "unknown" {
			want = "unknown"
		}
		if len(fs) != 1 || fs[0].Code != "server_computer_reference" || fs[0].Severity != want {
			t.Fatal(fs)
		}
	}
}

func TestTopologyAuditDoesNotTreatOldObjectsAsDead(t *testing.T) {
	site := "CN=Branch,CN=Sites,CN=Configuration,DC=example,DC=com"
	server := "CN=DC1,CN=Servers," + site
	ntds := "CN=NTDS Settings," + server
	computer := "CN=DC1,DC=example,DC=com"
	entries := []*ldap.Entry{ldap.NewEntry(site, map[string][]string{"objectClass": {"site"}, "whenChanged": {"20000101000000.0Z"}}), ldap.NewEntry(server, map[string][]string{"objectClass": {"server"}, "serverReference": {computer}}), ldap.NewEntry(ntds, map[string][]string{"objectClass": {"nTDSDSA"}}), ldap.NewEntry("CN=Link,"+ntds, map[string][]string{"objectClass": {"nTDSConnection"}, "fromServer": {ntds}})}
	if f := analyzeTopology(entries, map[string]string{dnKey(computer): "present"}); len(f) != 0 {
		t.Fatal(f)
	}
}

func TestTopologyAuditSearchFailureIsPartial(t *testing.T) {
	server := testldap.New(t, map[string]string{"service": "password"}, func(testldap.Search) ([]testldap.Entry, int64) { return nil, 50 })
	client := ldapproto.NewServiceClient(config.LDAPConfig{URI: server.URI(), BaseDN: "DC=example", Bind: config.BindConfig{User: "service", Type: "simple"}}, func() string { return "password" })
	defer client.Close()
	report := (&SiteService{ldap: client}).AuditTopology(context.Background())
	if report.Status != "partial" || len(report.Findings) != 0 || report.Finished.IsZero() {
		t.Fatalf("access denial became healthy or missing: %+v", report)
	}
}

func TestTopologyAuditOrphanDCTrustAccount(t *testing.T) {
	entry := ldap.NewEntry("CN=OldDC,DC=example", map[string][]string{"objectClass": {"computer"}, "whenChanged": {"20200101000000.0Z"}})
	findings := analyzeTopology([]*ldap.Entry{entry}, nil)
	if len(findings) != 1 || findings[0].Code != "dc_computer_without_server" {
		t.Fatal(findings)
	}
	server := ldap.NewEntry("CN=DC,CN=Servers,CN=Site", map[string][]string{"objectClass": {"server"}, "serverReference": {entry.DN}})
	for _, f := range analyzeTopology([]*ldap.Entry{entry, server}, map[string]string{dnKey(entry.DN): "present"}) {
		if f.Code == "dc_computer_without_server" {
			t.Fatal(f)
		}
	}
}

func TestTopologyAuditDefaultSingleSiteLinkIsNotStale(t *testing.T) {
	site := "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example"
	entries := []*ldap.Entry{ldap.NewEntry(site, map[string][]string{"objectClass": {"site"}}), ldap.NewEntry("CN=DEFAULTIPSITELINK,CN=IP,CN=Inter-Site Transports,CN=Sites,CN=Configuration,DC=example", map[string][]string{"objectClass": {"siteLink"}, "siteList": {site}})}
	for _, f := range analyzeTopology(entries, nil) {
		if f.Code != "site_without_servers" {
			t.Fatal(f)
		}
	}
}
