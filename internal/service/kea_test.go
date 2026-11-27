package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sambaadm/internal/config"
)

func testKeaHost(t *testing.T) *keaHost {
	t.Helper()
	h := &keaHost{cfg: &config.Config{}, family: "4", unit: "kea-dhcp4.service", binary: "kea-dhcp4", path: filepath.Join(t.TempDir(), "kea-dhcp4.conf"), run: func(context.Context, string, ...string) (string, error) { return "active", nil }}
	if e := os.WriteFile(h.path, []byte(`{"Dhcp4":{"valid-lifetime":3600,"user-context":{"unknown":"preserved"}}}`), 0640); e != nil {
		t.Fatal(e)
	}
	return h
}
func TestKeaDocumentCommentsRelaysAndUnknownFields(t *testing.T) {
	input := `# server
 {"Dhcp4":{ /* original */ "subnet4":[{"id":1,"subnet":"10.0.0.0/24","relay":{"ip-addresses":["192.0.2.1"]},}],"user-context":{"url":"http://example/#tag","quote":"\"//"},},}`
	doc, e := keaDocument(input, "4")
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"192.0.2.1", "http://example/#tag", "user-context"} {
		if !strings.Contains(string(doc), v) {
			t.Fatalf("lost %s: %s", v, doc)
		}
	}
	for _, invalid := range []string{`{"Dhcp6":{}}`, `{"Dhcp4":null}`, `{"Dhcp4":{ /* broken }}`, `{"Dhcp4": <?include "other.json"?>}`, `{"Dhcp4":{}} {}`} {
		if _, e := keaDocument(invalid, "4"); e == nil {
			t.Errorf("accepted %s", invalid)
		}
	}
}
func TestKeaPlanChecksOnHelperAndDoesNotWrite(t *testing.T) {
	h := testKeaHost(t)
	before, _ := os.ReadFile(h.path)
	h.run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name != "kea-dhcp4" || len(args) != 2 || args[0] != "-t" {
			t.Fatalf("unsafe command %s %v", name, args)
		}
		raw, e := os.ReadFile(args[1])
		if e != nil || !strings.Contains(string(raw), "relay") {
			t.Fatalf("wrong candidate: %s %v", raw, e)
		}
		return "checked", nil
	}
	req := KeaRequest{Family: "4", Config: `{"Dhcp4":{"subnet4":[{"id":1,"subnet":"10.0.0.0/24","relay":{"ip-addresses":["192.0.2.1"]}}]}}`}
	p, e := h.plan(context.Background(), req)
	if e != nil {
		t.Fatal(e)
	}
	after, _ := os.ReadFile(h.path)
	if string(after) != string(before) || p.Revision == p.ProposedRevision {
		t.Fatal("invalid preview")
	}
	req.Revision = "stale"
	if _, e = h.plan(context.Background(), req); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("stale edit accepted: %v", e)
	}
}
func TestKeaApplyConflictAndRollback(t *testing.T) {
	h := testKeaHost(t)
	ctx := context.Background()
	before, _ := os.ReadFile(h.path)
	req := KeaRequest{Family: "4", Config: `{"Dhcp4":{"valid-lifetime":7200}}`, Confirm: true}
	if _, e := h.apply(ctx, req); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("missing preview: %v", e)
	}
	p, e := h.plan(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	req.Revision = p.Revision
	req.ProposedRevision = p.ProposedRevision
	restarts := 0
	h.run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" && args[0] == "restart" {
			restarts++
			if restarts == 1 {
				return "", errors.New("failed")
			}
		}
		return "active", nil
	}
	if _, e = h.apply(ctx, req); e == nil || !strings.Contains(e.Error(), "откат") {
		t.Fatalf("rollback missing: %v", e)
	}
	after, _ := os.ReadFile(h.path)
	if string(after) != string(before) || restarts != 2 {
		t.Fatalf("rollback failed: %s, restarts=%d", after, restarts)
	}
}
func TestKeaStoppedServerAndMissingConfiguration(t *testing.T) {
	h := testKeaHost(t)
	os.Remove(h.path)
	ctx := context.Background()
	var restarted bool
	h.run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" && args[0] == "is-active" {
			return "inactive", errors.New("inactive")
		}
		if name == "systemctl" && args[0] == "restart" {
			restarted = true
		}
		return "ok", nil
	}
	req := KeaRequest{Family: "4", Config: `{"Dhcp4":{"valid-lifetime":3600}}`, Confirm: true}
	p, e := h.plan(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	req.Revision = p.Revision
	req.ProposedRevision = p.ProposedRevision
	result, e := h.apply(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	if restarted {
		t.Fatal("unexpected start")
	}
	if result.Backup == "" {
		t.Fatal("missing backup")
	}
	after, _ := os.ReadFile(h.path)
	if string(after) != req.Config {
		t.Fatal("wrong file")
	}
}
func TestKeaInstallUsesOnlyALTAllowlistedPackages(t *testing.T) {
	h := testKeaHost(t)
	var installed bool
	h.run = func(ctx context.Context, name string, args ...string) (string, error) {
		switch name {
		case "apt-cache":
			if args[1] == "kea-dhcp4" {
				return "", errors.New("no split package")
			}
			return "kea", nil
		case "apt-get":
			return "Inst kea (version ALT)", nil
		case "systemd-run":
			if args[len(args)-1] != "kea-hooks" || !strings.Contains(strings.Join(args, " "), "/usr/bin/apt-get -y install kea kea-hooks") {
				t.Fatalf("wrong install command %v", args)
			}
			installed = true
		}
		return "ok", nil
	}
	p, e := h.installPlan(context.Background())
	if e != nil || p.Proposed != "kea kea-hooks" {
		t.Fatalf("fallback: %v %v", p, e)
	}
	req := KeaRequest{Confirm: true, Revision: p.Revision, ProposedRevision: "stale"}
	if _, e = h.install(context.Background(), req); !errors.Is(e, ErrTopologyConflict) || installed {
		t.Fatal("stale install accepted")
	}
	req.ProposedRevision = p.ProposedRevision
	if _, e = h.install(context.Background(), req); e != nil || !installed {
		t.Fatalf("install failed: %v", e)
	}
}
func TestKeaServiceRejectsArbitraryCommands(t *testing.T) {
	h := testKeaHost(t)
	if _, e := h.service(context.Background(), KeaRequest{Confirm: true, Action: "daemon-reexec"}); e == nil {
		t.Fatal("accepted arbitrary systemctl")
	}
	if _, e := h.service(context.Background(), KeaRequest{Confirm: true, Action: "start"}); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("start without revision: %v", e)
	}
}
