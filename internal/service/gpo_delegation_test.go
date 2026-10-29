package service

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func delegationTestSD(t *testing.T, aces [][]byte) []byte {
	t.Helper()
	old := make([]byte, 28)
	old[0] = 1
	old[20] = 2
	binary.LittleEndian.PutUint16(old[2:], 0x8004)
	binary.LittleEndian.PutUint32(old[16:], 20)
	binary.LittleEndian.PutUint16(old[22:], 8)
	sd, err := daclDescriptor(old, aces)
	if err != nil {
		t.Fatal(err)
	}
	return sd
}
func TestDelegationPreservesExistingACEsAndIsIdempotent(t *testing.T) {
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}
	additions, err := delegationACEs(sid, "read-apply")
	if err != nil {
		t.Fatal(err)
	}
	deny := append([]byte(nil), additions[0]...)
	deny[0] = 1
	inherited := append([]byte(nil), additions[0]...)
	inherited[1] |= 16
	opaque := []byte{99, 0, 4, 0}
	old := delegationTestSD(t, [][]byte{deny, opaque, inherited})
	sd, added, err := delegationDescriptor(old, additions)
	if err != nil || len(added) != 2 {
		t.Fatalf("%+v %v", added, err)
	}
	aces, err := policyACEs(sd)
	if err != nil {
		t.Fatal(err)
	}
	if len(aces) != 5 || !bytes.Equal(aces[0], deny) || !bytes.Equal(aces[1], opaque) || !bytes.Equal(aces[4], inherited) {
		t.Fatal("existing ACE/order changed")
	}
	if sd[20] != 4 {
		t.Fatal("object ACE requires ACL revision 4")
	}
	again, added, err := delegationDescriptor(sd, additions)
	if err != nil || len(added) != 0 || !bytes.Equal(again, sd) {
		t.Fatal("not idempotent", err)
	}
	for _, profile := range []string{"read", "read-apply", "edit-ldap"} {
		out, e := delegationACEs(sid, profile)
		if e != nil {
			t.Fatal(e)
		}
		for _, a := range out {
			mask := binary.LittleEndian.Uint32(a[4:])
			if mask&(0x10000|0x40000|0x80000|0x10000000) != 0 {
				t.Fatal("profile grants delete/DACL/owner/full control")
			}
			if a[0] == 0 && a[1] != 2 {
				t.Fatal("LDAP descendant inheritance missing")
			}
		}
	}
}
func TestDelegationRejectsUnknownAndNoncanonical(t *testing.T) {
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}
	if _, e := delegationACEs(sid, "full-control"); e == nil {
		t.Fatal("unknown profile")
	}
	if _, e := delegationACEs(nil, "read"); e == nil {
		t.Fatal("bad SID")
	}
	allow, _ := delegationACEs(sid, "read")
	deny := append([]byte(nil), allow[0]...)
	deny[0] = 1
	inherited := append([]byte(nil), allow[0]...)
	inherited[1] |= 16
	for _, aces := range [][][]byte{{allow[0], deny}, {inherited, allow[0]}} {
		if _, _, e := delegationDescriptor(delegationTestSD(t, aces), allow); e == nil {
			t.Fatal("noncanonical accepted")
		}
	}
	for i := 0; i < 28; i++ {
		if _, _, e := delegationDescriptor(make([]byte, i), allow); e == nil {
			t.Fatal("invalid descriptor")
		}
	}
}
