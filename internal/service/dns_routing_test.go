package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sambaadm/internal/config"
	"strings"
	"testing"
)

func TestDelegationGlueAndBoundaries(t *testing.T) {
	valid := DNSDelegationInput{Zone: "IPR.LOC.", Child: "app.ipr.loc", Servers: []DNSNameServer{{Name: "ns.app.ipr.loc", Addresses: []string{"10.20.0.53", "2001:db8::53"}}}}
	normalized, e := normalizeDelegation(valid)
	if e != nil || normalized.Child != "app" {
		t.Fatalf("normalize: %+v %v", normalized, e)
	}
	p, e := delegationPlan(valid, nil, []DNSZone{{Name: "ipr.loc"}})
	if e != nil || len(p.Changes) != 3 {
		t.Fatalf("glue+NS: %+v %v", p, e)
	}
	for _, input := range []DNSDelegationInput{{Zone: "ipr.loc", Child: "@", Servers: valid.Servers}, {Zone: "ipr.loc", Child: "app", Servers: []DNSNameServer{{Name: "ns.app.ipr.loc"}}}, {Zone: "ipr.loc", Child: "app", Servers: []DNSNameServer{{Name: "ns.other.loc", Addresses: []string{"10.0.0.1"}}}}} {
		if _, e := normalizeDelegation(input); e == nil {
			t.Fatalf("unsafe delegation accepted: %+v", input)
		}
	}
	if _, e := delegationPlan(valid, nil, []DNSZone{{Name: "app.ipr.loc"}}); e == nil {
		t.Fatal("existing child AD zone allowed")
	}
	old := []delegationRecord{{Name: "app", Type: "NS", Data: "ns.app.ipr.loc"}, {Name: "ns.app", Type: "A", Data: "10.20.0.53"}}
	remove := DNSDelegationInput{Zone: "ipr.loc", Child: "app", Remove: true}
	p, e = delegationPlan(remove, old, nil)
	if e != nil || len(p.Changes) != 1 || p.Changes[0].Type != "NS" || !p.Changes[0].Remove {
		t.Fatalf("removed shared glue: %+v %v", p, e)
	}
}
func TestForwardBlockPreservesManualConfiguration(t *testing.T) {
	rules := []DNSForwardRule{{Domain: "App.IPR.LOC.", Servers: []string{"10.20.0.53"}, Mode: "only"}}
	normalized, e := normalizeForwardRules(rules)
	if e != nil {
		t.Fatal(e)
	}
	before := "// manual\ninclude \"/etc/bind/local.conf\";\n"
	block := renderForwardBlock(normalized)
	outside, read, parsed, e := splitForwardConfig([]byte(before + block))
	if e != nil || outside != before || read != block || len(parsed) != 1 || parsed[0].Domain != "app.ipr.loc" {
		t.Fatalf("round trip: %q %v", outside, e)
	}
	if _, _, _, e = splitForwardConfig([]byte(before + strings.Replace(block, "forward only;", "forward first;", 1))); e == nil {
		t.Fatal("manual block changes overwritten")
	}
	for _, v := range []DNSForwardRule{{Domain: ".", Servers: []string{"10.0.0.1"}, Mode: "only"}, {Domain: "x.example;bad", Servers: []string{"10.0.0.1"}, Mode: "only"}, {Domain: "x.example", Servers: []string{"127.0.0.1"}, Mode: "only"}, {Domain: "x.example", Servers: []string{"10.0.0.1; reboot"}, Mode: "only"}} {
		if _, e := normalizeForwardRules([]DNSForwardRule{v}); e == nil {
			t.Fatalf("unsafe forward accepted: %+v", v)
		}
	}
}
func TestForwardConcurrentChangeAndFreshRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named.conf")
	if e := os.WriteFile(path, []byte("// existing config\n"), 0640); e != nil {
		t.Fatal(e)
	}
	h := &dnsForwardHost{cfg: &config.Config{}, path: path, run: func(context.Context, string, ...string) (string, error) { return "ok", nil }}
	ctx := context.Background()
	wanted := DNSForwardRule{Domain: "first.example", Servers: []string{"192.0.2.53"}, Mode: "only"}
	first := DNSForwardRequest{Rules: []DNSForwardRule{wanted}, Confirm: true}
	p, e := h.plan(ctx, first)
	if e != nil {
		t.Fatal(e)
	}
	first.Revision, first.ProposedRevision = p.Revision, p.ProposedRevision
	other := DNSForwardRequest{Rules: []DNSForwardRule{{Domain: "second.example", Servers: []string{"192.0.2.54"}, Mode: "first"}}, Confirm: true}
	p, e = h.plan(ctx, other)
	if e != nil {
		t.Fatal(e)
	}
	other.Revision, other.ProposedRevision = p.Revision, p.ProposedRevision
	if _, e = h.apply(ctx, other); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.apply(ctx, first); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("stale administrator preview accepted: %v", e)
	}
	after, e := os.ReadFile(path)
	if e != nil || string(after) != string(before) {
		t.Fatalf("conflict changed the second administrator's configuration: %v", e)
	}
	current, e := h.inspect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	first.Rules = append(current.Rules, wanted)
	first.Revision, first.ProposedRevision = current.Revision, ""
	p, e = h.plan(ctx, first)
	if e != nil {
		t.Fatal(e)
	}
	first.ProposedRevision = p.ProposedRevision
	result, e := h.apply(ctx, first)
	if e != nil {
		t.Fatal(e)
	}
	if got := result.Status.Rules; !reflect.DeepEqual(got, []DNSForwardRule{wanted, other.Rules[0]}) {
		t.Fatalf("fresh retry lost or duplicated a rule: %+v", got)
	}
}

func TestForwardApplyPreviewConflictAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named.conf")
	before := []byte("// existing config\n")
	if e := os.WriteFile(path, before, 0640); e != nil {
		t.Fatal(e)
	}
	cfg := &config.Config{}
	cfg.Helper.Node = "dc.example"
	fail := false
	h := &dnsForwardHost{cfg: cfg, path: path, run: func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "rndc" && args[0] == "reconfig" && fail {
			fail = false
			return "", errors.New("reload failed")
		}
		return "ok", nil
	}}
	req := DNSForwardRequest{Rules: []DNSForwardRule{{Domain: "app.example", Servers: []string{"192.0.2.53"}, Mode: "only"}}, Confirm: true}
	ctx := context.Background()
	if _, e := h.apply(ctx, req); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("unreviewed apply: %v", e)
	}
	p, e := h.plan(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(path)
	if string(raw) != string(before) {
		t.Fatal("preview modified config")
	}
	req.Revision = p.Revision
	req.ProposedRevision = p.ProposedRevision
	if e := os.WriteFile(path, append(before, []byte("// external change\n")...), 0640); e != nil {
		t.Fatal(e)
	}
	if _, e := h.apply(ctx, req); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("stale apply: %v", e)
	}
	os.WriteFile(path, before, 0640)
	fail = true
	if _, e = h.apply(ctx, req); e == nil {
		t.Fatal("reload failure ignored")
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != string(before) {
		t.Fatal("rollback did not restore original")
	}
	result, e := h.apply(ctx, req)
	if e != nil || len(result.Status.Rules) != 1 {
		t.Fatalf("apply: %+v %v", result, e)
	}
	backup, _ := os.ReadFile(result.Backup)
	if string(backup) != string(before) {
		t.Fatal("backup differs")
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0640 {
		t.Fatal("permissions changed")
	}
}
