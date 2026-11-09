package service

import (
	"bytes"
	"context"
	"encoding/binary"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/testldap"
	"strings"
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

func TestMalformedScopeIsIsolatedAndCannotBeSavedOrModeled(t *testing.T) {
	const base = "DC=example,DC=com"
	const bad = "OU=Bad," + base
	fake := testldap.New(t, map[string]string{"service": "password"}, func(q testldap.Search) ([]testldap.Entry, int64) {
		if strings.Contains(string(q.Filter.Bytes()), "groupPolicyContainer") {
			return nil, 0
		}
		return []testldap.Entry{
			{DN: base, Attributes: map[string][]string{"name": {"example"}, "gPLink": {" "}, "uSNChanged": {"1"}}},
			{DN: bad, Attributes: map[string][]string{"name": {"Bad"}, "gPLink": {"broken"}, "uSNChanged": {"1"}}},
			{DN: "OU=Safe," + base, Attributes: map[string][]string{"name": {"Safe"}, "uSNChanged": {"1"}}},
		}, 0
	})
	client := ldapproto.NewServiceClient(config.LDAPConfig{URI: fake.URI(), BaseDN: base, Bind: config.BindConfig{User: "service"}}, func() string { return "password" })
	defer client.Close()
	s := &GPOService{ldap: client}
	model, err := s.Scope(t.Context())
	if err != nil || len(model.Containers) != 3 {
		t.Fatalf("scope failed globally: %+v %v", model, err)
	}
	if _, err := ScopeInheritance(model, "OU=Safe,"+base); err != nil {
		t.Fatal("unrelated OU blocked", err)
	}
	if _, err := ScopeInheritance(model, bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Fatal("bad branch not diagnosed", err)
	}
	if err := s.SaveScope(context.Background(), ScopeChange{Container: bad, Revision: "1"}, "test", ""); err == nil || !strings.Contains(err.Error(), "changes blocked") {
		t.Fatal("unsafe scope save allowed", err)
	}
}

func TestScopeLinkWhitespace(t *testing.T) {
	for _, raw := range []string{"", " ", "\r\n\t"} {
		links, err := parseScopeLinks(raw)
		if err != nil || len(links) != 0 {
			t.Fatalf("empty scope rejected: %q %v", raw, err)
		}
	}
	links, err := parseScopeLinks(" \n[ldap://CN=A,DC=test;0] \r\n[LDAP://CN=B,DC=test;2] ")
	if err != nil || len(links) != 2 || links[0].DN != "CN=B,DC=test" || !links[0].Enforced {
		t.Fatalf("whitespace/order: %+v %v", links, err)
	}
}
