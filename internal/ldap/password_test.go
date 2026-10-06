package ldap

import (
	"testing"
)

func TestEncodeUnicodePwd(t *testing.T) {
	got := EncodeUnicodePwd("Ab1!")
	// "Ab1!" in quotes → 6 UTF-16LE code units → 12 bytes
	if len(got) != 12 {
		t.Fatalf("len=%d want 12", len(got))
	}
	// first char is '"' = 0x0022 LE → 0x22, 0x00
	if got[0] != 0x22 || got[1] != 0x00 {
		t.Fatalf("unexpected prefix: %v", got[:2])
	}
	// last char is '"'
	if got[10] != 0x22 || got[11] != 0x00 {
		t.Fatalf("unexpected suffix: %v", got[10:])
	}
}
