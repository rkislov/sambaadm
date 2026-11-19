package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	ldapproto "sambaadm/internal/ldap"
)

const backupTestBase = "DC=example,DC=com"
const backupTestGUID = "11111111111111111111111111111111"
const backupTestDomain = "22222222222222222222222222222222"

func backupFixture() *ObjectBackup {
	return &ObjectBackup{Format: objectBackupFormat, ID: uuid.NewString(), Created: time.Now().UTC(), BaseDN: backupTestBase, DomainGUID: backupTestDomain, Objects: []ObjectBackupEntry{{GUID: backupTestGUID, DN: "CN=Alice,CN=Users," + backupTestBase, Kind: "user", Name: "alice", Attributes: map[string][]string{"sAMAccountName": {"alice"}, "displayName": {"Alice"}}}}}
}
func TestObjectBackupStoreIntegrityAndPublication(t *testing.T) {
	s := &ObjectBackupService{root: filepath.Join(t.TempDir(), "backups")}
	b := backupFixture()
	if err := s.save(b); err != nil {
		t.Fatal(err)
	}
	if err := s.save(b); err == nil {
		t.Fatal("overwrote existing backup")
	}
	got, err := s.Load(b.ID)
	if err != nil || got.Objects[0].Name != "alice" {
		t.Fatalf("roundtrip %v: %+v", err, got)
	}
	if _, err = s.Load("../../etc/passwd"); err == nil {
		t.Fatal("accepted traversal")
	}
	list, err := s.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	path := filepath.Join(s.root, b.ID+".json")
	raw, _ := os.ReadFile(path)
	raw = []byte(strings.Replace(string(raw), "Alice", "Alixe", 1))
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Load(b.ID); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corruption accepted: %v", err)
	}
}
func TestObjectBackupRejectsSymlinksAndForeignDN(t *testing.T) {
	s := &ObjectBackupService{root: filepath.Join(t.TempDir(), "backups")}
	b := backupFixture()
	b.Objects[0].DN = "CN=Other,DC=evil,DC=com"
	if err := s.save(b); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(b.ID); err == nil {
		t.Fatal("foreign DN accepted")
	}
	id := uuid.NewString()
	if err := os.Symlink(filepath.Join(s.root, b.ID+".json"), filepath.Join(s.root, id+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(id); err == nil {
		t.Fatal("symlink accepted")
	}
}

type backupFakeLDAP struct {
	deleted       bool
	missing       bool
	collision     bool
	foreign       bool
	missingParent bool
	usn           string
	writes        []*ldap.ModifyRequest
	failProfile   bool
	failDisable   bool
	accountUAC    string
	capture       []*ldap.Entry
	captureErr    error
}

func (f *backupFakeLDAP) BaseDN() string { return backupTestBase }
func (f *backupFakeLDAP) SearchOne(_ context.Context, o ldapproto.SearchOptions) (*ldap.Entry, error) {
	if o.BaseDN == backupTestBase {
		raw, _ := hex.DecodeString(backupTestDomain)
		if f.foreign {
			raw[0] = 0
		}
		return ldap.NewEntry(o.BaseDN, map[string][]string{"objectGUID": {string(raw)}}), nil
	}
	if strings.EqualFold(o.BaseDN, "CN=Users,"+backupTestBase) {
		if f.missingParent {
			return nil, ldap.NewError(32, errors.New("missing parent"))
		}
		return ldap.NewEntry(o.BaseDN, map[string][]string{"objectGUID": {"parent"}}), nil
	}
	raw, _ := hex.DecodeString(backupTestGUID)
	return ldap.NewEntry(o.BaseDN, map[string][]string{"objectGUID": {string(raw)}, "userAccountControl": {"514"}, "uSNChanged": {"43"}}), nil
}
func (f *backupFakeLDAP) Search(_ context.Context, o ldapproto.SearchOptions) ([]*ldap.Entry, error) {
	if strings.HasPrefix(o.Filter, "(|(&(objectCategory=") {
		return f.capture, f.captureErr
	}
	if strings.HasPrefix(o.Filter, "(objectGUID=") {
		if len(o.Controls) != 1 || o.Controls[0].GetControlType() != showDeletedOID {
			return nil, errors.New("missing show deleted control")
		}
		if f.missing {
			return nil, nil
		}
		deleted := "FALSE"
		if f.deleted {
			deleted = "TRUE"
		}
		return []*ldap.Entry{ldap.NewEntry("CN=Deleted,"+backupTestBase, map[string][]string{"isDeleted": {deleted}, "uSNChanged": {f.usn}, "userAccountControl": {f.accountUAC}})}, nil
	}
	if f.collision {
		return []*ldap.Entry{ldap.NewEntry("CN=Collision,"+backupTestBase, nil)}, nil
	}
	return nil, nil
}
func (f *backupFakeLDAP) Modify(_ context.Context, r *ldap.ModifyRequest) error {
	f.writes = append(f.writes, r)
	if f.failDisable && len(f.writes) == 2 {
		return errors.New("disable failure")
	}
	if f.failProfile && len(f.writes) == 3 {
		return errors.New("profile failure")
	}
	return nil
}
func TestObjectRestoreGuardsAndIdentity(t *testing.T) {
	for _, scenario := range []string{"live", "missing", "foreign", "collision", "parent", "stale", "success", "partial", "disable", "dc"} {
		t.Run(scenario, func(t *testing.T) {
			f := &backupFakeLDAP{deleted: true, usn: "42", accountUAC: "514"}
			s := &ObjectBackupService{root: filepath.Join(t.TempDir(), "backups"), ldap: f}
			b := backupFixture()
			if err := s.save(b); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "live":
				f.deleted = false
			case "missing":
				f.missing = true
			case "foreign":
				f.foreign = true
			case "collision":
				f.collision = true
			case "parent":
				f.missingParent = true
			case "partial":
				f.failProfile = true
			case "disable":
				f.failDisable = true
			case "dc":
				f.accountUAC = "8192"
			}
			p, err := s.Preview(context.Background(), b.ID, backupTestGUID)
			if scenario == "foreign" {
				if err == nil {
					t.Fatal("foreign domain accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "live" || scenario == "missing" || scenario == "collision" || scenario == "parent" || scenario == "dc" {
				if p.CanRestore {
					t.Fatalf("unsafe plan %+v", p)
				}
				if err = s.Restore(context.Background(), b.ID, backupTestGUID, p.Revision, "tester", ""); err == nil || len(f.writes) != 0 {
					t.Fatal("unsafe restore mutated LDAP")
				}
				return
			}
			if scenario == "stale" {
				f.usn = "44"
			}
			err = s.Restore(context.Background(), b.ID, backupTestGUID, p.Revision, "tester", "")
			if scenario == "stale" {
				if err == nil || len(f.writes) != 0 {
					t.Fatal("stale plan applied")
				}
				return
			}
			if scenario == "disable" {
				if err == nil || !strings.Contains(err.Error(), "disabling failed") || len(f.writes) != 2 {
					t.Fatalf("disable failure hidden: %v", err)
				}
				return
			}
			if scenario == "partial" {
				if err == nil || !strings.Contains(err.Error(), "reanimated and disabled") {
					t.Fatalf("partial result hidden: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(f.writes) != 3 {
				t.Fatalf("writes: %d", len(f.writes))
			}
			r := f.writes[0]
			if len(r.Controls) != 2 {
				t.Fatal("missing critical assertion or show-deleted control")
			}
			disabled := false
			for _, c := range f.writes[1].Changes {
				if c.Modification.Type == "userAccountControl" && c.Modification.Vals[0] == "514" {
					disabled = true
				}
			}
			if !disabled {
				t.Fatal("restored account not disabled before profile writes")
			}
		})
	}
}
func TestObjectBackupDoesNotPublishIncompleteCapture(t *testing.T) {
	f := &backupFakeLDAP{captureErr: errors.New("LDAP interrupted")}
	s := &ObjectBackupService{root: filepath.Join(t.TempDir(), "backups"), ldap: f}
	if _, err := s.Create(context.Background(), "tester", ""); err == nil {
		t.Fatal("failed capture succeeded")
	}
	files, _ := os.ReadDir(s.root)
	if len(files) != 0 {
		t.Fatal("published incomplete backup")
	}
	raw, _ := hex.DecodeString(backupTestGUID)
	f.captureErr = nil
	f.capture = []*ldap.Entry{ldap.NewEntry("CN=Alice,CN=Users,"+backupTestBase, map[string][]string{"objectGUID": {string(raw)}, "objectClass": {"top", "person", "user"}, "sAMAccountName": {"alice"}, "unicodePwd": {"DO_NOT_CAPTURE"}, "supplementalCredentials": {"SECRET"}})}
	b, err := s.Create(context.Background(), "tester", "")
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(b)
	if strings.Contains(string(encoded), "SECRET") || strings.Contains(string(encoded), "DO_NOT_CAPTURE") {
		t.Fatal("captured secrets")
	}
}
