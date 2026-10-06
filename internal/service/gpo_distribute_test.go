package service

import "testing"

func TestLooksLikeGUID(t *testing.T) {
	if !looksLikeGUID("{31B2F340-016D-11D2-945F-00C04FB984F9}") {
		t.Fatal("expected guid")
	}
	if looksLikeGUID("Default Domain Policy") {
		t.Fatal("name is not guid")
	}
}

func TestSameHost(t *testing.T) {
	if !sameHost("dc1.example.com", "dc1") {
		t.Fatal("short/fqdn should match")
	}
	if sameHost("dc1", "dc2") {
		t.Fatal("different hosts")
	}
}

func TestBraceGUID(t *testing.T) {
	if braceGUID("31B2F340-016D-11D2-945F-00C04FB984F9") != "{31B2F340-016D-11D2-945F-00C04FB984F9}" {
		t.Fatal("brace")
	}
}
