package service

import (
	"context"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"os"
	"path/filepath"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/testldap"
	"strings"
	"testing"
)

func testCleanupPlan() *CleanupPlan {
	p := &CleanupPlan{Format: 1, BaseDN: "DC=example,DC=com", LDAPServer: "dc.example.com", Blockers: []string{"not executable"}, Objects: []CleanupObject{{DN: "CN=old,DC=example,DC=com", USN: "12", GUID: make([]byte, 16), Attributes: map[string][][]byte{"description": {[]byte("old")}}}}}
	p.Revision = cleanupRevision(p)
	return p
}
func TestCleanupSelectionAndRevision(t *testing.T) {
	for _, dns := range [][]string{nil, {"invalid"}, {"CN=x,DC=com", "cn=x,dc=com"}, make([]string, 51)} {
		if validateCleanupSelection(dns) == nil {
			t.Fatal("accepted invalid selection", dns)
		}
	}
	p := testCleanupPlan()
	before := p.Revision
	p.Objects[0].USN = "13"
	if cleanupRevision(p) == before {
		t.Fatal("revision did not change")
	}
	p = testCleanupPlan()
	p.Objects[0].Attributes["description"][0] = []byte("new")
	if cleanupRevision(p) == before {
		t.Fatal("attributes not bound")
	}
}
func TestCleanupSnapshotIntegrityAndConfinement(t *testing.T) {
	cfg := &config.Config{}
	cfg.Helper.BackupRoot = t.TempDir()
	p := testCleanupPlan()
	out, err := helperTopologySnapshot(cfg, "topology.snapshot.store", HostOperation{Input: hostInput(p)})
	if err != nil {
		t.Fatal(err)
	}
	r := out.(*CleanupReceipt)
	op := HostOperation{Name: r.ID, Revision: r.SHA256}
	if _, err = helperTopologySnapshot(cfg, "topology.snapshot.load", op); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.Helper.BackupRoot, "topology-snapshots", r.ID+".json")
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
	if err = os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = helperTopologySnapshot(cfg, "topology.snapshot.load", op); err == nil {
		t.Fatal("accepted corruption")
	}
	op.Name = "../../outside"
	if _, err = helperTopologySnapshot(cfg, "topology.snapshot.load", op); err == nil {
		t.Fatal("accepted traversal")
	}
	p.CanApply = true
	if _, err = helperTopologySnapshot(cfg, "topology.snapshot.store", HostOperation{Input: hostInput(p)}); err == nil {
		t.Fatal("accepted executable plan")
	}
	if err = os.Chmod(filepath.Join(cfg.Helper.BackupRoot, "topology-snapshots"), 0755); err != nil {
		t.Fatal(err)
	}
	p = testCleanupPlan()
	if _, err = helperTopologySnapshot(cfg, "topology.snapshot.store", HostOperation{Input: hostInput(p)}); err == nil {
		t.Fatal("accepted public directory")
	}
}

func TestCleanupSnapshotSignedHTTPS(t *testing.T) {
	cfg := &config.Config{}
	cfg.Helper.Node = "test.example"
	cfg.Helper.BackupRoot = t.TempDir()
	logger, err := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	client := testHelperClient(t, &Services{Audit: logger}, cfg)
	p := testCleanupPlan()
	var receipt CleanupReceipt
	if err := client.Call(context.Background(), cfg.Helper.Node, "topology.snapshot.store", HostOperation{Input: hostInput(p)}, &receipt); err != nil {
		t.Fatal(err)
	}
	var saved CleanupPlan
	if err := client.Call(context.Background(), cfg.Helper.Node, "topology.snapshot.load", HostOperation{Name: receipt.ID, Revision: receipt.SHA256}, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Revision != p.Revision || saved.CanApply {
		t.Fatal("invalid saved plan")
	}
}

func TestCleanupPreviewRevalidation(t *testing.T) {
	dn := "CN=Future,CN=Sites,CN=Configuration,DC=example,DC=com"
	// testldap serializes each request; state changes occur only between calls.
	usn := "12"
	denied := false
	server := testldap.New(t, map[string]string{"service": "password"}, func(q testldap.Search) ([]testldap.Entry, int64) {
		if denied {
			return nil, 50
		}
		filter, _ := ldap.DecompileFilter(q.Filter)
		if q.Scope == 1 || strings.Contains(filter, "userAccountControl") {
			return nil, 0
		}
		return []testldap.Entry{{DN: dn, Attributes: map[string][]string{"objectClass": {"site"}, "objectGUID": {"0123456789abcdef"}, "uSNChanged": {usn}}}}, 0
	})
	client := ldapproto.NewServiceClient(config.LDAPConfig{URI: server.URI(), BaseDN: "DC=example,DC=com", Bind: config.BindConfig{User: "service", Type: "simple"}}, func() string { return "password" })
	defer client.Close()
	svc := &SiteService{ldap: client}
	p, err := svc.PreviewCleanup(context.Background(), []string{dn})
	if err != nil {
		t.Fatal(err)
	}
	if p.CanApply || len(p.Objects) != 1 || len(p.Blockers) == 0 {
		t.Fatal(p)
	}
	if _, err = svc.PreviewCleanup(context.Background(), []string{"CN=Unrelated,DC=example,DC=com"}); err == nil {
		t.Fatal("accepted arbitrary DN")
	}
	usn = "13"
	if _, err = svc.ArchiveCleanup(context.Background(), CleanupRequest{DNs: []string{dn}, Revision: p.Revision}, "test", ""); !errors.Is(err, ErrTopologyConflict) {
		t.Fatal("stale plan accepted", err)
	}
	denied = true
	if _, err = svc.PreviewCleanup(context.Background(), []string{dn}); err == nil {
		t.Fatal("partial audit accepted")
	}
}
