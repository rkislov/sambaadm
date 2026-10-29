package service

import (
	"context"
	"encoding/json"
	"fmt"
	smb2 "github.com/cloudsoda/go-smb2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIntegrationConsistencyAcrossTwoDCs(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_SECOND_DC") == "" {
		t.Skip("requires two DCs")
	}
	s, cfg := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	name := fmt.Sprintf("IT-Consistency-%d", time.Now().UnixNano())
	if _, e := s.GPO.Create(ctx, name, "test", ""); e != nil {
		t.Fatal(e)
	}
	all, e := s.GPO.List(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var id string
	for _, p := range all {
		if p.DisplayName == name {
			id = p.GUID
		}
	}
	if id == "" {
		t.Fatal("GPO missing")
	}
	t.Cleanup(func() { s.GPO.Delete(context.Background(), id, "test", "") })
	dc2, e := s.Sites.controller(ctx, os.Getenv("SAMBAADM_IT_SECOND_DC"))
	if e != nil {
		t.Fatal(e)
	}
	dc1, e := s.Sites.controller(ctx, "DC1")
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Repl.Sync(ctx, dc2.DNS, dc1.DNS, cfg.BaseDN, "test", ""); e != nil {
		t.Fatal(e)
	}
	report, e := s.GPO.CheckConsistency(ctx, id, ConsistencyInput{Reference: dc1.DNS})
	if e != nil {
		t.Fatal(e)
	}
	if report.Status != "incomplete" {
		t.Fatalf("missing SYSVOL not reported: %+v", report)
	}
	for _, dc := range report.Controllers {
		if dc.DNS == dc2.DNS && dc.SYSVOL != "missing" {
			t.Fatalf("second DC: %+v", dc)
		}
	}
	dir := t.TempDir()
	if e = s.GPO.backupNative(ctx, id, dir, "test", ""); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(dir, "policy", id, "sambaadm-backup.json"))
	if e != nil {
		t.Fatal(e)
	}
	var snapshot policyBackup
	if e = json.Unmarshal(raw, &snapshot); e != nil {
		t.Fatal(e)
	}
	entry, e := s.GPO.policyEntry(ctx, id)
	if e != nil {
		t.Fatal(e)
	}
	base, e := s.GPO.policyPath(ctx, entry)
	if e != nil {
		t.Fatal(e)
	}
	remote := *s.GPO.remote
	remote.Host = dc2.DNS
	t.Cleanup(func() {
		remote.SYSVOL(context.Background(), s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error { return sh.RemoveAll(base) })
	})
	if e = remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error { return installPolicySnapshot(sh, base, snapshot) }); e != nil {
		t.Fatal(e)
	}
	report, e = s.GPO.CheckConsistency(ctx, id, ConsistencyInput{Reference: dc1.DNS})
	if e != nil {
		t.Fatal(e)
	}
	if report.Status != "consistent" {
		t.Fatalf("matching DC snapshots: %+v", report.Controllers)
	}
	// Keep the same Version but change bytes and DACL on one replica.
	e = remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		store := &smbPolicyStore{share: sh, base: strings.ReplaceAll(base, `\`, "/")}
		data, e := readPolicyFile(store, "GPT.INI")
		if e != nil {
			return e
		}
		if e = writePolicyFile(store, "GPT.INI", append(data, []byte("\r\n; replica-only comment\r\n")...)); e != nil {
			return e
		}
		acl, e := store.GetACL("GPT.INI")
		if e != nil {
			return e
		}
		sid := []byte{1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0}
		ace, e := delegationFileACE(sid, "read", false)
		if e != nil {
			return e
		}
		desired, _, e := delegationDescriptor(acl, [][]byte{ace})
		if e != nil {
			return e
		}
		return store.SetDACL("GPT.INI", desired)
	})
	if e != nil {
		t.Fatal(e)
	}
	report, e = s.GPO.CheckConsistency(ctx, id, ConsistencyInput{Reference: dc1.DNS})
	if e != nil {
		t.Fatal(e)
	}
	kinds := map[string]bool{}
	for _, dc := range report.Controllers {
		if dc.DNS == dc2.DNS {
			for _, d := range dc.Differences {
				kinds[d.Kind] = true
			}
		}
	}
	if report.Status != "different" || !kinds["content"] || !kinds["sysvol-acl"] {
		t.Fatalf("drift not detected: %+v", report)
	}
	// A pending journal prevents a healthy report even if content is otherwise readable.
	if e = remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error { return sh.WriteFile(base+`\`+editorJournal, []byte("unfinished"), 0600) }); e != nil {
		t.Fatal(e)
	}
	report, e = s.GPO.CheckConsistency(ctx, id, ConsistencyInput{Reference: dc1.DNS})
	if e != nil || report.Status != "incomplete" {
		t.Fatalf("pending report %+v %v", report, e)
	}
	for _, dc := range report.Controllers {
		if dc.DNS == dc2.DNS && (!dc.Pending || dc.Status != "pending") {
			t.Fatal(dc)
		}
	}
	// Refuse arbitrary endpoint input rather than authenticating to a user URL.
	if _, e = s.GPO.CheckConsistency(ctx, id, ConsistencyInput{Reference: "attacker.invalid"}); e == nil {
		t.Fatal("unknown endpoint accepted")
	}
}
