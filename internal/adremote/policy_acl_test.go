package adremote

import (
	"encoding/binary"
	"testing"
)

func TestPolicyFileACLRejectsMalformed(t *testing.T) {
	for n := 0; n < 40; n++ {
		b := make([]byte, n)
		if n > 0 {
			b[0] = 1
		}
		if _, err := PolicyFileACL(b); err == nil {
			t.Fatalf("accepted %d zero bytes", n)
		}
	}
	b := make([]byte, 40)
	b[0] = 1
	binary.LittleEndian.PutUint32(b[16:], 20)
	binary.LittleEndian.PutUint16(b[22:], 20)
	binary.LittleEndian.PutUint16(b[24:], 1)
	b[28] = 1
	binary.LittleEndian.PutUint16(b[30:], 12)
	if _, err := PolicyFileACL(b); err == nil {
		t.Fatal("deny ACE silently discarded")
	}
}
