package service

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestScopeLinkOrderAndOptions(t *testing.T) {
	links, e := parseScopeLinks("[LDAP://CN=low,DC=test;0][LDAP://CN=high,DC=test;3]")
	if e != nil || len(links) != 2 || links[0].DN != "CN=high,DC=test" || links[0].Enabled || !links[0].Enforced {
		t.Fatalf("%+v %v", links, e)
	}
	for _, raw := range []string{"bad", "[LDAP://CN=x;bad]", "[LDAP://bad;0]"} {
		if _, e := parseScopeLinks(raw); e == nil {
			t.Fatal(raw)
		}
	}
}
func TestScopeInheritanceBlockEnforced(t *testing.T) {
	m := &GPScope{Containers: []GPContainer{{DN: "DC=test", Links: []ScopeLink{{Name: "root", Enabled: true}, {Name: "forced", Enabled: true, Enforced: true}}}, {DN: "OU=parent,DC=test", Parent: "DC=test", Block: true, Links: []ScopeLink{{Name: "parent", Enabled: true, Enforced: true}}}, {DN: "OU=child,OU=parent,DC=test", Parent: "OU=parent,DC=test", Links: []ScopeLink{{Name: "child", Enabled: true}, {Name: "off", Enabled: false}}}}}
	v, e := ScopeInheritance(m, "OU=child,OU=parent,DC=test")
	if e != nil {
		t.Fatal(e)
	}
	want := []string{"forced", "parent", "child", "off", "root"}
	for i, n := range want {
		if v[i].Name != n {
			t.Fatalf("%+v", v)
		}
	}
	if v[4].Reason != "blocked" || v[3].Reason != "disabled" {
		t.Fatal(v)
	}
}
func TestPolicyDACLPreservesOpaqueAndRights(t *testing.T) {
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}
	a := make([]byte, 28)
	a[0] = 5
	binary.LittleEndian.PutUint16(a[2:], uint16(len(a)+len(sid)))
	binary.LittleEndian.PutUint32(a[4:], 0x100)
	binary.LittleEndian.PutUint32(a[8:], 1)
	copy(a[12:], applyPolicyGUID)
	a = append(a, sid...)
	v := filterACE(a)
	if !v.Editable || !v.Apply || v.SID != "S-1-5-11" {
		t.Fatal(v)
	}
	a[1] = 16
	if filterACE(a).Editable {
		t.Fatal("inherited editable")
	}
	a[1] = 0
	a[0] = 6
	if filterACE(a).Editable {
		t.Fatal("deny editable")
	}
	a[0] = 5
	binary.LittleEndian.PutUint32(a[4:], 0x101)
	if filterACE(a).Editable {
		t.Fatal("combined editable")
	}
	old := make([]byte, 28)
	old[0] = 1
	binary.LittleEndian.PutUint16(old[2:], 0x8004)
	binary.LittleEndian.PutUint32(old[16:], 20)
	old[20] = 4
	binary.LittleEndian.PutUint16(old[22:], 8)
	opaque := []byte{99, 0, 4, 0}
	sd, e := daclDescriptor(old, [][]byte{a, opaque})
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := policyACEs(sd)
	if e != nil || len(parsed) != 2 || !bytes.Equal(parsed[0], a) || !bytes.Equal(parsed[1], opaque) {
		t.Fatalf("%v %v", parsed, e)
	}
	for i := 0; i < len(sd); i++ {
		if _, e := policyACEs(sd[:i]); e == nil {
			t.Fatalf("accepted truncation %d", i)
		}
	}
}
