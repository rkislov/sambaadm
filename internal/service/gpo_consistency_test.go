package service

import (
	"context"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func consistencyTestDC(name string) ConsistencyDC {
	v := uint32(7)
	return ConsistencyDC{DNS: name, checked: true, Status: "ready", LDAP: "ok", SYSVOL: "ok", LDAPVersion: &v, GPTVersion: &v, Metadata: "meta", LDAPACL: "acl", Files: []ConsistencyFile{{Path: ".", Kind: "directory", ACL: "root"}, {Path: "GPT.INI", Kind: "file", Size: 22, SHA256: "content", ACL: "acl"}}}
}
func TestConsistencyComparisonSeparatesUnknownAndDifferences(t *testing.T) {
	a, b := consistencyTestDC("dc1"), consistencyTestDC("dc2")
	r := &ConsistencyReport{Controllers: []ConsistencyDC{a, b}}
	compareConsistency(r)
	if r.Status != "consistent" || !r.Complete || r.Reference != "dc1" {
		t.Fatalf("%+v", r)
	}
	b.Files = append([]ConsistencyFile(nil), b.Files...)
	b.Files[1].SHA256 = "changed"
	b.Files[1].ACL = "changed"
	b.Files = append(b.Files, ConsistencyFile{Path: "extra", Kind: "file", SHA256: "x"})
	v := uint32(8)
	b.GPTVersion = &v
	r = &ConsistencyReport{Controllers: []ConsistencyDC{a, b, {DNS: "dc3", Status: "unavailable"}}}
	compareConsistency(r)
	if r.Status != "incomplete" || r.Complete || !r.HasDifferences || r.Controllers[1].DifferenceCount != 5 {
		t.Fatalf("%+v", r)
	}
	kinds := map[string]bool{}
	for _, d := range r.Controllers[1].Differences {
		kinds[d.Kind] = true
	}
	for _, k := range []string{"local-version", "gpt-version", "content", "sysvol-acl", "extra"} {
		if !kinds[k] {
			t.Fatal(k)
		}
	}
	r = &ConsistencyReport{Reference: "dc3", Controllers: []ConsistencyDC{b, {DNS: "dc3", Status: "unavailable"}}}
	compareConsistency(r)
	if r.Status != "incomplete" || r.Reference != "dc3" || !r.HasDifferences {
		t.Fatal("unavailable explicit reference silently replaced", r)
	}
	r = &ConsistencyReport{Controllers: []ConsistencyDC{a}}
	compareConsistency(r)
	if r.Status != "single-controller" {
		t.Fatal("one DC reported redundant consistency")
	}
}
func TestConsistencyMissingPathsAndACLOnlyDifferences(t *testing.T) {
	a, b := consistencyTestDC("a"), consistencyTestDC("b")
	b.Files = nil
	b.LDAPACL = "other"
	r := &ConsistencyReport{Controllers: []ConsistencyDC{a, b}}
	compareConsistency(r)
	if r.Status != "different" || r.Controllers[1].DifferenceCount != 3 {
		t.Fatalf("%+v", r)
	}
	a.checked = false
	a.Status = "pending"
	r = &ConsistencyReport{Controllers: []ConsistencyDC{a, consistencyTestDC("b")}}
	compareConsistency(r)
	if r.Reference != "b" || r.Status != "incomplete" {
		t.Fatal("pending DC used as reference")
	}
}
func TestConsistencyTreeHashesWithoutWriting(t *testing.T) {
	root, _, _, _ := setupDelegationTx(t)
	if err := root.Root.WriteFile("GPT.INI", []byte("[General]\nVersion=7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	snap, e := scanConsistencyTree(context.Background(), root)
	if e != nil {
		t.Fatal(e)
	}
	if len(snap.Files) != 3 || *snap.GPT != 7 || root.writes != 0 {
		t.Fatalf("%+v", snap)
	}
	before := snap.Signature
	root.Root.WriteFile(".sambaadm-backup.json", []byte("not policy content"), 0600)
	snap, e = scanConsistencyTree(context.Background(), root)
	if e != nil || snap.Signature != before {
		t.Fatal("internal metadata affected comparison", e)
	}
	root.Root.WriteFile(editorJournal, []byte("pending"), 0600)
	snap, e = scanConsistencyTree(context.Background(), root)
	if e != nil || !snap.Pending {
		t.Fatal("pending not detected", e)
	}
	root.Remove(editorJournal)
	root.Root.WriteFile("GPT.INI", []byte("[General]\nVersion=8\n"), 0600)
	snap, e = scanConsistencyTree(context.Background(), root)
	if e != nil || snap.Signature == before {
		t.Fatal("content change missed", e)
	}
	root.Root.Symlink("GPT.INI", "link")
	if _, e = scanConsistencyTree(context.Background(), root); e == nil {
		t.Fatal("symlink followed")
	}
	root.Remove("link")
	f, e := root.Root.OpenFile("large", os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	f.Truncate(consistencyBytes + 1)
	f.Close()
	root.acl["large"] = root.acl["."]
	if _, e = scanConsistencyTree(context.Background(), root); e == nil {
		t.Fatal("oversized tree accepted")
	}
}
func TestConsistencyACLIncludesOwnerAndProtection(t *testing.T) {
	_, _, sd, _ := setupDelegationTx(t)
	a, e := consistencyACL(sd)
	if e != nil {
		t.Fatal(e)
	}
	changed := append([]byte(nil), sd...)
	binary.LittleEndian.PutUint16(changed[2:], binary.LittleEndian.Uint16(changed[2:])^0x1000)
	b, _ := consistencyACL(changed)
	if a == b {
		t.Fatal("protection ignored")
	}
	changed = append([]byte(nil), sd...)
	binary.LittleEndian.PutUint32(changed[4:], uint32(len(changed)))
	changed = append(changed, []byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}...)
	b, e = consistencyACL(changed)
	if e != nil || a == b {
		t.Fatal("owner ignored", e)
	}
}
func TestConsistencyTargetsAndDifferenceLimit(t *testing.T) {
	got, e := consistencyPeerURI("ldaps://original:1636", "dc2.example.test")
	if e != nil || got != "ldaps://dc2.example.test:1636" {
		t.Fatal(got, e)
	}
	for _, host := range []string{"", "evil:123", "dc/other", "user@dc", "dc?x"} {
		if _, e = consistencyPeerURI("ldaps://dc", host); e == nil {
			t.Fatal(host)
		}
	}
	if _, e = consistencyPeerURI("ldapi:///var/run/ldap", "dc2"); e == nil {
		t.Fatal("transport changed silently")
	}
	dc := ConsistencyDC{}
	for i := 0; i < consistencyDiffs+1; i++ {
		addConsistencyDifference(&dc, "content", "x", "a", "b")
	}
	if dc.DifferenceCount != consistencyDiffs+1 || len(dc.Differences) != consistencyDiffs {
		t.Fatal("difference cap")
	}
	s := &GPOService{}
	s.consistencyMu.Lock()
	defer s.consistencyMu.Unlock()
	if _, e = s.CheckConsistency(context.Background(), modelHigh, ConsistencyInput{}); e != ErrConsistencyBusy {
		t.Fatal(e)
	}
	if _, e = s.CheckConsistency(context.Background(), strings.Repeat("x", 40), ConsistencyInput{}); e == nil {
		t.Fatal("invalid GUID")
	}
}

func TestConsistencyComparesKnownLDAPWhenSYSVOLIsUnavailable(t *testing.T) {
	a, b := consistencyTestDC("a"), consistencyTestDC("b")
	b.checked = false
	b.Status = "incomplete"
	b.SYSVOL = "unavailable"
	b.Files = nil
	b.Metadata = "changed"
	r := &ConsistencyReport{Controllers: []ConsistencyDC{a, b}}
	compareConsistency(r)
	if r.Complete || r.Status != "incomplete" || !r.HasDifferences || r.Controllers[1].Status != "incomplete" || r.Controllers[1].DifferenceCount != 1 {
		t.Fatalf("%+v", r)
	}
	if r.Controllers[1].Differences[0].Kind != "ldap-metadata" {
		t.Fatal("unavailable files reported missing")
	}
}
