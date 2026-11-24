package service

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"testing"
)

func TestGroupTypeRoundTrip(t *testing.T) {
	for _, scope := range []string{"global", "domain-local", "universal"} {
		for _, category := range []string{"security", "distribution"} {
			v, e := encodeGroupType(scope, category)
			if e != nil {
				t.Fatal(e)
			}
			_, s, c, b := decodeGroupType(v)
			if s != scope || c != category || b {
				t.Fatal(v, s, c, b)
			}
		}
	}
	for _, v := range []string{"bad", "global\n"} {
		if _, e := encodeGroupType(v, "security"); !errors.Is(e, ErrGroupInput) {
			t.Fatal(e)
		}
	}
	_, s, c, b := decodeGroupType("-2147483643")
	if s != "domain-local" || c != "security" || !b {
		t.Fatal(s, c, b)
	}
}
func TestGroupUpdateRejectsMissingConfirmationAndVersionBeforeLDAP(t *testing.T) {
	s := &GroupService{}
	for _, in := range []UpdateGroupInput{{}, {Confirm: true}, {Confirm: true, Revision: "x"}, {Confirm: true, Revision: "1", Scope: "global", Category: "bad"}, {Confirm: true, Revision: "1", Scope: "global", Category: "security", Description: "invalid\x00"}} {
		if _, e := s.Update(context.Background(), "group", in, "", ""); !errors.Is(e, ErrGroupInput) {
			t.Fatal(in, e)
		}
	}
}
func TestGroupMemberDelegationIsAttributeSpecificAndNotInherited(t *testing.T) {
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}
	a, e := groupAccessACE(sid, "manage-members")
	if e != nil {
		t.Fatal(e)
	}
	if a[0] != 5 || a[1] != 0 || binary.LittleEndian.Uint32(a[4:]) != 0x20 || binary.LittleEndian.Uint32(a[8:]) != 1 {
		t.Fatal("overbroad delegation", a)
	}
	if _, e = groupAccessACE(sid, "full-control"); !errors.Is(e, ErrGroupInput) {
		t.Fatal(e)
	}
	if _, e = groupAccessACE(nil, "read"); !errors.Is(e, ErrGroupInput) {
		t.Fatal(e)
	}
}
func TestGroupPersonComputerKind(t *testing.T) {
	e := ldap.NewEntry("CN=PC", map[string][]string{"objectClass": {"top", "person", "user", "computer"}, "sAMAccountName": {"PC$"}})
	if p := groupPerson(e); p.Kind != "computer" || p.Name != "PC$" {
		t.Fatal(p)
	}
}
