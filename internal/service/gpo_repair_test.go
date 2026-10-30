package service

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

type repairTestVolume struct {
	failStage     bool
	root          *os.Root
	acl           map[string][]byte
	baseACL       []byte
	renames, fail int
	uncertain     bool
}
type repairTestTree struct {
	v    *repairTestVolume
	name string
}

func (v *repairTestVolume) Tree(n string) policyStore { return &repairTestTree{v, n} }
func (v *repairTestVolume) Mkdir(n string) error {
	e := v.root.Mkdir(n, 0700)
	if e == nil {
		v.acl[n] = v.baseACL
	}
	return e
}
func (v *repairTestVolume) Rename(a, b string) error {
	v.renames++
	if v.renames == v.fail && !v.uncertain {
		return errors.New("injected rename failure")
	}
	if e := v.root.Rename(a, b); e != nil {
		return e
	}
	for p, acl := range v.acl {
		if p == a || strings.HasPrefix(p, a+"/") {
			delete(v.acl, p)
			v.acl[b+strings.TrimPrefix(p, a)] = acl
		}
	}
	if v.renames == v.fail {
		return errors.New("rename succeeded but response lost")
	}
	return nil
}
func (s *repairTestTree) p(n string) string                   { return path.Join(s.name, n) }
func (s *repairTestTree) Lstat(n string) (os.FileInfo, error) { return s.v.root.Lstat(s.p(n)) }
func (s *repairTestTree) ReadDir(n string) ([]os.FileInfo, error) {
	return (localPolicyStore{s.v.root}).ReadDir(s.p(n))
}
func (s *repairTestTree) Open(n string) (policyFile, error) { return s.v.root.Open(s.p(n)) }
func (s *repairTestTree) OpenFile(n string, f int, m os.FileMode) (policyFile, error) {
	if s.v.failStage && strings.HasPrefix(s.name, ".sambaadm-repair-") && n == "GPT.INI" {
		return nil, errors.New("staging write failure")
	}
	p := s.p(n)
	file, e := s.v.root.OpenFile(p, f, m)
	if e == nil && s.v.acl[p] == nil {
		s.v.acl[p] = s.v.baseACL
	}
	return file, e
}
func (s *repairTestTree) Remove(n string) error               { return s.v.root.Remove(s.p(n)) }
func (s *repairTestTree) Mkdir(n string, m os.FileMode) error { return s.v.Mkdir(s.p(n)) }
func (s *repairTestTree) Rename(a, b string) error            { return s.v.root.Rename(s.p(a), s.p(b)) }
func (s *repairTestTree) GetACL(n string) ([]byte, error)     { return s.v.acl[s.p(n)], nil }
func (s *repairTestTree) SetACL(n string, b []byte) error     { s.v.acl[s.p(n)] = b; return nil }
func repairFixture(t *testing.T, missing bool) (*repairTestVolume, *os.Root, *RepairRecord) {
	t.Helper()
	_, local, acl, _ := setupDelegationTx(t)
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { root.Close() })
	v := &repairTestVolume{root: root, acl: map[string][]byte{}, baseACL: acl}
	create := func(n, comment string) *repairSnapshot {
		if e := v.Mkdir(n); e != nil {
			t.Fatal(e)
		}
		tree := v.Tree(n)
		if e := createDurablePolicyFile(tree, "GPT.INI", []byte("[General]\nVersion=0\n;"+comment)); e != nil {
			t.Fatal(e)
		}
		if n == "source" {
			if e := tree.Mkdir("Machine", 0700); e != nil {
				t.Fatal(e)
			}
			if e := tree.Mkdir("Machine/Scripts", 0700); e != nil {
				t.Fatal(e)
			}
			if e := createDurablePolicyFile(tree, "Machine/Scripts/test.sh", []byte("echo test")); e != nil {
				t.Fatal(e)
			}
		} else {
			if e := createDurablePolicyFile(tree, "Machine", []byte("old file instead of directory")); e != nil {
				t.Fatal(e)
			}
			if e := createDurablePolicyFile(tree, "obsolete", []byte("retain in backup")); e != nil {
				t.Fatal(e)
			}
		}
		snap, e := captureRepair(context.Background(), tree)
		if e != nil {
			t.Fatal(e)
		}
		return snap
	}
	r := &RepairRecord{Format: 1, ID: uuid.NewString(), GPO: "{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}", Base: "domain/Policies/live", Source: "a", Target: "b", LDAP: "test", State: "pending", Direction: "complete", Created: time.Now()}
	r.After = create("source", "new")
	if !missing {
		r.Before = create("live", "old")
	}
	if e = saveRepair(local, r); e != nil {
		t.Fatal(e)
	}
	return v, local, r
}
func TestRepairRecoveryAtDirectoryBoundaries(t *testing.T) {
	for _, missing := range []bool{false, true} {
		for _, uncertain := range []bool{false, true} {
			for _, failure := range []int{1, 2} {
				for _, direction := range []string{"complete", "rollback"} {
					t.Run(strings.Join([]string{map[bool]string{true: "missing", false: "existing"}[missing], map[bool]string{true: "uncertain", false: "failed"}[uncertain], string(rune('0' + failure)), direction}, "/"), func(t *testing.T) {
						v, local, r := repairFixture(t, missing)
						v.fail = failure
						v.uncertain = uncertain
						ctx := context.Background()
						check := func() error { return nil }
						e := runRepair(ctx, v, local, r, check)
						if missing && failure == 2 {
							if e != nil {
								t.Fatal(e)
							}
						} else if e == nil {
							t.Fatal("expected injected failure")
						}
						// Recovery reloads the on-disk journal as after a process restart.
						r, e = readRepair(local, r.ID)
						if e != nil {
							t.Fatal(e)
						}
						r.Direction = direction
						r.State = "pending"
						if e = saveRepair(local, r); e != nil {
							t.Fatal(e)
						}
						v.fail = 0
						if e = runRepair(ctx, v, local, r, check); e != nil {
							t.Fatal(e)
						}
						want := r.After.Signature
						if direction == "rollback" {
							want = repairSignature(r.Before)
						}
						got, e := repairTreeState(ctx, v, "live", r)
						if e != nil || got != want {
							t.Fatalf("got %s want %s: %v", got, want, e)
						}
						if r.Before != nil && direction == "complete" {
							b, e := repairTreeState(ctx, v, repairBackup(r), r)
							if e != nil || b != r.Before.Signature {
								t.Fatal("backup lost", e)
							}
						}
					})
				}
			}
		}
	}
}
func TestRepairRejectsExternalChangesAndLDAPConflict(t *testing.T) {
	v, local, r := repairFixture(t, false)
	if e := writePolicyFile(v.Tree("live"), "GPT.INI", []byte("[General]\nVersion=7\n")); e != nil {
		t.Fatal(e)
	}
	if e := runRepair(context.Background(), v, local, r, func() error { return nil }); !errors.Is(e, ErrTopologyConflict) {
		t.Fatal(e)
	}
	if v.renames != 0 {
		t.Fatal("conflict mutated live tree")
	}
	v, local, r = repairFixture(t, false)
	if e := runRepair(context.Background(), v, local, r, func() error { return ErrTopologyConflict }); !errors.Is(e, ErrTopologyConflict) {
		t.Fatal(e)
	}
	if v.renames != 0 {
		t.Fatal("LDAP conflict mutated live tree")
	}
}
func TestRepairRollbackRefusesModifiedBackup(t *testing.T) {
	v, local, r := repairFixture(t, false)
	if e := runRepair(context.Background(), v, local, r, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e := writePolicyFile(v.Tree(repairBackup(r)), "GPT.INI", []byte("[General]\nVersion=7\n")); e != nil {
		t.Fatal(e)
	}
	r.Direction = "rollback"
	if e := runRepair(context.Background(), v, local, r, func() error { return nil }); !errors.Is(e, ErrTopologyConflict) {
		t.Fatal(e)
	}
}

func TestRepairRestartsPartialStagingAndRequiresDurableJournal(t *testing.T) {
	v, local, r := repairFixture(t, false)
	v.failStage = true
	if e := runRepair(context.Background(), v, local, r, func() error { return nil }); e == nil {
		t.Fatal("expected stage failure")
	}
	if v.renames != 0 {
		t.Fatal("partial stage touched live tree")
	}
	first := r.Stage
	r, e := readRepair(local, r.ID)
	if e != nil {
		t.Fatal(e)
	}
	v.failStage = false
	if e = runRepair(context.Background(), v, local, r, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if r.Stage == first || r.Attempts != 2 {
		t.Fatal("partial stage reused")
	}
	if _, e = v.Tree(first).Lstat("."); e != nil {
		t.Fatal("partial stage was removed")
	}
	v, local, r = repairFixture(t, false)
	local.Close()
	if e = runRepair(context.Background(), v, local, r, func() error { return nil }); e == nil {
		t.Fatal("expected durable journal failure")
	}
	if v.renames != 0 {
		t.Fatal("journal failure changed live tree")
	}
}

func TestRepairPreservesMalformedAndMissingTargetGPT(t *testing.T) {
	for _, missing := range []bool{false, true} {
		v, local, r := repairFixture(t, false)
		tree := v.Tree("live")
		var e error
		if missing {
			e = tree.Remove("GPT.INI")
		} else {
			e = writePolicyFile(tree, "GPT.INI", []byte("corrupt"))
		}
		if e != nil {
			t.Fatal(e)
		}
		r.Before, e = captureRepair(context.Background(), tree)
		if e != nil {
			t.Fatal(e)
		}
		if e = saveRepair(local, r); e != nil {
			t.Fatal(e)
		}
		if e = runRepair(context.Background(), v, local, r, func() error { return nil }); e != nil {
			t.Fatal(e)
		}
		r.Direction = "rollback"
		r.State = "pending"
		if e = saveRepair(local, r); e != nil {
			t.Fatal(e)
		}
		if e = runRepair(context.Background(), v, local, r, func() error { return nil }); e != nil {
			t.Fatal(e)
		}
		got, e := repairTreeState(context.Background(), v, "live", r)
		if e != nil || got != r.Before.Signature {
			t.Fatal("original damaged GPT not preserved", e)
		}
	}
}
