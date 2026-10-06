package service

import "testing"

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
