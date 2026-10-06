package service

import (
	"strings"
	"testing"
)

func TestBuildDN(t *testing.T) {
	got := BuildDN("CN", "John Doe", "OU=People,DC=example,DC=com")
	want := "CN=John Doe,OU=People,DC=example,DC=com"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestDNSFromBaseDN(t *testing.T) {
	got := dnsFromBaseDN("DC=example,DC=com")
	if got != "example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestDefaultUsersOU(t *testing.T) {
	if got := DefaultUsersOU("", "DC=ex,DC=com"); got != "CN=Users,DC=ex,DC=com" {
		t.Fatalf("got %q", got)
	}
	if got := DefaultUsersOU("OU=X,DC=ex,DC=com", "DC=ex,DC=com"); got != "OU=X,DC=ex,DC=com" {
		t.Fatalf("got %q", got)
	}
}

func TestCnFromDNEscapedComma(t *testing.T) {
	dn := `CN=Smith\, John,OU=People,DC=example,DC=com`
	got := cnFromDN(dn)
	if got != "Smith, John" {
		t.Fatalf("got %q want %q", got, "Smith, John")
	}
}

func TestRdnFromDNEscapedComma(t *testing.T) {
	dn := `CN=Smith\, John,OU=People,DC=example,DC=com`
	rdn, err := rdnFromDN(dn)
	if err != nil {
		t.Fatal(err)
	}
	// Must round-trip as a single RDN with escaped comma, not split early.
	if !strings.Contains(rdn, "smith") && !strings.Contains(rdn, "Smith") {
		t.Fatalf("unexpected rdn %q", rdn)
	}
	if strings.Contains(rdn, "OU=") || strings.Contains(rdn, "ou=") {
		t.Fatalf("rdn should be first component only, got %q", rdn)
	}
	// Re-parse reconstructed DN to ensure comma stays inside value.
	full := rdn + ",OU=People,DC=example,DC=com"
	if got := cnFromDN(full); got != "Smith, John" {
		t.Fatalf("round-trip value %q", got)
	}
}

func TestCnFromDNSimple(t *testing.T) {
	if got := cnFromDN("CN=alice,OU=Users,DC=ex,DC=com"); got != "alice" {
		t.Fatalf("got %q", got)
	}
}
