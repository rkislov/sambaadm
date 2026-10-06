package web

import "testing"

func TestDNSFromBaseDN(t *testing.T) {
	if got := dnsFromBaseDN("DC=example,DC=com"); got != "example.com" {
		t.Fatalf("got %q", got)
	}
	if got := dnsFromBaseDN("OU=Users,DC=corp,DC=local"); got != "corp.local" {
		t.Fatalf("got %q", got)
	}
}
