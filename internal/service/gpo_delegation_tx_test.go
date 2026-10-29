package service

import (
	"bytes"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

type aclTestStore struct {
	localPolicyStore
	acl            map[string][]byte
	writes, failAt int
}

func (s *aclTestStore) GetACL(p string) ([]byte, error) { return append([]byte(nil), s.acl[p]...), nil }
func (s *aclTestStore) SetACL(p string, v []byte) error { return s.SetDACL(p, v) }
func (s *aclTestStore) SetDACL(p string, v []byte) error {
	s.writes++
	if s.failAt == s.writes {
		return errors.New("injected SMB ACL failure")
	}
	s.acl[p] = append([]byte(nil), v...)
	return nil
}
func setupDelegationTx(t *testing.T) (*aclTestStore, *os.Root, []byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "GPT.INI"), []byte("unchanged"), 0600)
	os.Mkdir(filepath.Join(dir, "Machine"), 0700)
	root, e := os.OpenRoot(dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0}
	aces, _ := delegationACEs(sid, "read")
	base, _ := normalizeDACL(delegationTestSD(t, aces))
	store := &aclTestStore{localPolicyStore: localPolicyStore{root}, acl: map[string][]byte{".": base, "GPT.INI": base, "Machine": base}}
	s := &GPOService{}
	s.gpoCfg.DelegationStateDir = filepath.Join(t.TempDir(), "state")
	local, e := s.delegationStateRoot()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { local.Close() })
	return store, local, base, []byte{1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0}
}
func TestDelegationRecoveryAtSMBAndLDAPBoundaries(t *testing.T) {
	for _, failure := range []string{"smb", "ldap-unknown"} {
		for _, mode := range []string{"complete", "rollback"} {
			t.Run(failure+"/"+mode, func(t *testing.T) {
				root, local, original, sid := setupDelegationTx(t)
				current := append([]byte(nil), original...)
				uncertain := failure == "ldap-unknown"
				rev := 1
				entry := func() *ldap.Entry {
					return ldap.NewEntry("CN=GPO,DC=test", map[string][]string{"objectGUID": {string(make([]byte, 16))}, "nTSecurityDescriptor": {string(current)}, "uSNChanged": {strconv.Itoa(rev)}})
				}
				read := func() ([]byte, string, error) { return current, strconv.Itoa(rev), nil }
				write := func(data []byte, r string) error {
					if r != strconv.Itoa(rev) {
						return ErrTopologyConflict
					}
					current = append([]byte(nil), data...)
					rev++
					if uncertain {
						uncertain = false
						return errors.New("response lost after LDAP commit")
					}
					return nil
				}
				p, e := buildDelegationPlan(root, local, "dc", entry(), DelegationOperation{Operation: "grant", Profile: "edit", Principal: "CN=user,DC=test"}, sid)
				if e != nil {
					t.Fatal(e)
				}
				if failure == "smb" {
					root.failAt = 2
				}
				if e = applyDelegationPlan(root, local, p, read, write); e == nil {
					t.Fatal("injected failure not returned")
				}
				records, e := delegationRecords(local, "dc", entry().DN)
				if e != nil || len(records) != 1 || records[0].State != "pending" {
					t.Fatalf("journal %+v %v", records, e)
				}
				recovered, e := buildDelegationPlan(root, local, "dc", entry(), DelegationOperation{Operation: mode, Source: records[0].ID}, nil)
				if e != nil || len(recovered.Conflicts) > 0 {
					t.Fatalf("recovery %+v %v", recovered, e)
				}
				root.failAt = 0
				if e = applyDelegationPlan(root, local, recovered, read, write); e != nil {
					t.Fatal(e)
				}
				records, e = delegationRecords(local, "dc", entry().DN)
				if e != nil {
					t.Fatal(e)
				}
				want := "complete"
				if mode == "rollback" {
					want = "rolled-back"
					if !bytes.Equal(current, original) {
						t.Fatal("LDAP original not restored")
					}
					for _, acl := range root.acl {
						if !bytes.Equal(acl, original) {
							t.Fatal("file original not restored")
						}
					}
				}
				if records[0].State != want {
					t.Fatal(records[0].State)
				}
				if _, e = root.Lstat(editorJournal); !os.IsNotExist(e) {
					t.Fatal("journal not removed", e)
				}
				raw, _ := root.Root.ReadFile("GPT.INI")
				if string(raw) != "unchanged" {
					t.Fatal("file content changed")
				}
			})
		}
	}
}
func TestDelegationRejectsConflictingRevokeAndPreservesBaseline(t *testing.T) {
	root, local, original, sid := setupDelegationTx(t)
	current := original
	rev := 1
	entry := func() *ldap.Entry {
		return ldap.NewEntry("CN=GPO,DC=test", map[string][]string{"objectGUID": {string(make([]byte, 16))}, "nTSecurityDescriptor": {string(current)}, "uSNChanged": {strconv.Itoa(rev)}})
	}
	read := func() ([]byte, string, error) { return current, strconv.Itoa(rev), nil }
	write := func(data []byte, _ string) error { current = data; rev++; return nil }
	p, e := buildDelegationPlan(root, local, "dc", entry(), DelegationOperation{Operation: "grant", Profile: "edit"}, sid)
	if e != nil {
		t.Fatal(e)
	}
	if e = applyDelegationPlan(root, local, p, read, write); e != nil {
		t.Fatal(e)
	}
	in := DelegationOperation{Operation: "revoke", Source: p.record.ID}
	root.acl["GPT.INI"] = original // Changed outside the workflow, even if it resembles the desired rollback.
	conflict, e := buildDelegationPlan(root, local, "dc", entry(), in, nil)
	if e != nil || len(conflict.Conflicts) == 0 {
		t.Fatalf("conflict not detected: %+v %v", conflict, e)
	}
	writes := root.writes
	if e = applyDelegationPlan(root, local, conflict, read, write); e == nil || root.writes != writes {
		t.Fatal("conflicting revoke wrote ACLs")
	}
	root.acl["GPT.INI"] = p.record.Files[1].After
	root.Root.WriteFile("new.txt", nil, 0600)
	root.acl["new.txt"] = original
	conflict, e = buildDelegationPlan(root, local, "dc", entry(), in, nil)
	if e != nil || len(conflict.Conflicts) == 0 {
		t.Fatal("tree change accepted")
	}
	root.Remove("new.txt")
	delete(root.acl, "new.txt")
	revoke, e := buildDelegationPlan(root, local, "dc", entry(), in, nil)
	if e != nil || len(revoke.Conflicts) > 0 {
		t.Fatalf("revoke %+v %v", revoke, e)
	}
	if e = applyDelegationPlan(root, local, revoke, read, write); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(current, original) {
		t.Fatal("baseline LDAP changed")
	}
	for _, acl := range root.acl {
		if !bytes.Equal(acl, original) {
			t.Fatal("baseline file ACL changed")
		}
	}
}
func TestDelegationStateAndPathsFailClosed(t *testing.T) {
	s := &GPOService{}
	s.gpoCfg.DelegationStateDir = t.TempDir()
	os.Chmod(s.gpoCfg.DelegationStateDir, 0755)
	if r, e := s.delegationStateRoot(); e == nil {
		r.Close()
		t.Fatal("public state dir accepted")
	}
	if _, e := delegationRecordName("../secret"); e == nil {
		t.Fatal("path escape")
	}
	root, _, _, _ := setupDelegationTx(t)
	if e := root.Root.Symlink("GPT.INI", "link"); e != nil {
		t.Fatal(e)
	}
	if _, e := delegationTree(root); e == nil {
		t.Fatal("symlink accepted")
	}
}

func TestDelegationJournalCannotTargetRecreatedGPO(t *testing.T) {
	root, local, original, sid := setupDelegationTx(t)
	entry := ldap.NewEntry("CN=GPO,DC=test", map[string][]string{"objectGUID": {string(make([]byte, 16))}, "nTSecurityDescriptor": {string(original)}, "uSNChanged": {"1"}})
	p, e := buildDelegationPlan(root, local, "dc", entry, DelegationOperation{Operation: "grant", Profile: "read-apply"}, sid)
	if e != nil {
		t.Fatal(e)
	}
	if len(p.LDAPAdded) != 2 || len(p.LDAPRemoved) != 0 {
		t.Fatalf("preview diff: %+v", p)
	}
	root.failAt = 1
	if e = applyDelegationPlan(root, local, p, func() ([]byte, string, error) { return original, "1", nil }, func([]byte, string) error { return nil }); e == nil {
		t.Fatal("failure not injected")
	}
	replacement := ldap.NewEntry(entry.DN, map[string][]string{"objectGUID": {string(bytes.Repeat([]byte{1}, 16))}, "nTSecurityDescriptor": {string(original)}, "uSNChanged": {"2"}})
	if _, e = buildDelegationPlan(root, local, "dc", replacement, DelegationOperation{Operation: "complete", Source: p.record.ID}, nil); e == nil {
		t.Fatal("record accepted for replacement GPO")
	}
	// Unrelated ACL edits during pending recovery must remain untouched.
	other, _ := delegationACEs(sid, "edit-ldap")
	foreign, _, _ := delegationDescriptor(original, other)
	root.acl["GPT.INI"] = foreign
	plan, e := buildDelegationPlan(root, local, "dc", entry, DelegationOperation{Operation: "rollback", Source: p.record.ID}, nil)
	if e != nil || len(plan.Conflicts) == 0 {
		t.Fatalf("third ACL state accepted: %+v %v", plan, e)
	}
	writes := root.writes
	if e = applyDelegationPlan(root, local, plan, func() ([]byte, string, error) { return original, "1", nil }, func([]byte, string) error { return nil }); e == nil || root.writes != writes {
		t.Fatal("conflicting recovery changed ACLs")
	}
}
