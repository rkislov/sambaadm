package service

import (
	"context"
	"encoding/json"
	"github.com/go-ldap/ldap/v3"
	"os"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestIntegrationCleanupReplicationDivergence(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("requires disposable two-DC domain")
	}
	s, cfg := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	site, e := s.Sites.Create(ctx, "Cleanup-Repl-Test", "test", "")
	must(e)
	t.Cleanup(func() { s.Sites.Delete(context.Background(), "Cleanup-Repl-Test", "test", "") })
	sync := func() {
		must(s.Repl.Sync(ctx, "dc2.sambaadm.test", "dc1.sambaadm.test", ConfigDN(cfg.BaseDN), "test", ""))
	}
	sync()
	uri, e := consistencyPeerURI(s.Sites.ldap.URI(), "dc2.sambaadm.test")
	must(e)
	peer := s.Sites.ldap.ServicePeer(uri)
	defer peer.Close()
	restore := []func(){}
	for _, pair := range []struct {
		client *ldapproto.Client
		name   string
	}{{s.Sites.ldap, "dc1.sambaadm.test"}, {peer, "dc2.sambaadm.test"}} {
		dc, e := s.Sites.controller(ctx, pair.name)
		must(e)
		entry, e := pair.client.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dc.NTDS, Scope: ldapproto.ScopeBase(), Attributes: []string{"options"}})
		must(e)
		old := entry.GetAttributeValues("options")
		value, _ := strconv.Atoi(entry.GetAttributeValue("options"))
		client, dn := pair.client, dc.NTDS
		reset := func() {
			req := ldap.NewModifyRequest(dn, nil)
			req.Replace("options", old)
			if e := client.Modify(context.Background(), req); e != nil {
				t.Errorf("restore fixture replication flags: %v", e)
			}
		}
		restore = append(restore, reset)
		req := ldap.NewModifyRequest(dn, nil)
		req.Replace("options", []string{strconv.Itoa(value | 2)})
		must(client.Modify(ctx, req))
	}
	defer func() {
		for _, reset := range restore {
			reset()
		}
	}()
	preview := func() *CleanupPlan { p, e := s.Sites.PreviewCleanup(ctx, []string{site.DN}); must(e); return p }
	check := func(p *CleanupPlan) *CleanupChecks {
		r, e := s.Sites.CheckCleanup(ctx, CleanupChecksRequest{CleanupRequest: CleanupRequest{DNs: []string{site.DN}, Revision: p.Revision}, Peer: "dc2.sambaadm.test"})
		must(e)
		if r.CanApply {
			t.Fatal("cleanup became executable")
		}
		return r
	}
	status := func(r *CleanupChecks, id string) string {
		for _, c := range r.Checks {
			if c.ID == id {
				return c.Status
			}
		}
		return "missing"
	}
	before := preview()
	change := ldap.NewModifyRequest(site.DN, nil)
	change.Replace("description", []string{"not yet replicated"})
	must(s.Sites.ldap.Modify(ctx, change))
	if _, e = s.Sites.CheckCleanup(ctx, CleanupChecksRequest{CleanupRequest: CleanupRequest{DNs: []string{site.DN}, Revision: before.Revision}, Peer: "dc2.sambaadm.test"}); e != ErrTopologyConflict {
		t.Fatalf("stale plan: %v", e)
	}
	p := preview()
	r := check(p)
	if status(r, "peer") != "blocked" {
		t.Fatalf("replica divergence missed: %+v", r)
	}
	if status(r, "replication_enabled") != "blocked" || status(r, "peer_replication_enabled") != "blocked" {
		t.Fatalf("disabled replication not surfaced: %+v", r)
	}
	t.Log("PASS: stale plan, disabled replication and unreplicated metadata are blocked")
	// Make the selected attributes agree locally, without replicating other objects.
	must(peer.Modify(ctx, change))
	subnet := "CN=198.51.100.0/24," + SubnetsContainerDN(cfg.BaseDN)
	must(peer.Add(ctx, subnet, []ldap.Attribute{{Type: "objectClass", Vals: []string{"subnet"}}, {Type: "siteObject", Vals: []string{site.DN}}}))
	defer peer.Delete(context.Background(), subnet)
	r = check(p)
	if status(r, "peer") != "ok" || status(r, "references") != "ok" || status(r, "peer_references") != "blocked" {
		t.Fatalf("peer-only reference missed: %+v", r)
	}
	found := false
	for _, d := range r.Dependencies {
		if dnKey(d.Source) == dnKey(subnet) && d.Controller == "dc2.sambaadm.test" {
			found = true
		}
	}
	if !found {
		t.Fatal("dependency lacks replica provenance")
	}
	t.Log("PASS: reference present only on DC2 blocks removal despite matching selected object")
	must(peer.Delete(ctx, subnet))
	// Missing on a replica is unknown, not proof of a stale object.
	extra, e := s.Sites.Create(ctx, "Cleanup-Not-Replicated", "test", "")
	must(e)
	defer s.Sites.Delete(context.Background(), "Cleanup-Not-Replicated", "test", "")
	ep, e := s.Sites.PreviewCleanup(ctx, []string{extra.DN})
	must(e)
	er, e := s.Sites.CheckCleanup(ctx, CleanupChecksRequest{CleanupRequest: CleanupRequest{DNs: []string{extra.DN}, Revision: ep.Revision}, Peer: "dc2.sambaadm.test"})
	must(e)
	if status(er, "peer") != "unknown" {
		t.Fatalf("missing replica classified as confirmed: %+v", er)
	}
	t.Log("PASS: object not yet replicated is unknown")
	for _, reset := range restore {
		reset()
	}
	restore = nil
	sync()
	p = preview()
	r = check(p)
	if status(r, "peer") != "ok" || status(r, "peer_references") != "ok" {
		t.Fatalf("converged replicas: %+v", r)
	}
	// Test deletion propagation only on our disposable, empty fixture site.
	// The cleanup apply API remains absent; this uses the existing site API.
	must(s.Sites.Delete(ctx, "Cleanup-Repl-Test", "test", ""))
	sync()
	_, e = peer.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: site.DN, Scope: ldapproto.ScopeBase()})
	if !ldap.IsErrorWithCode(e, ldap.LDAPResultNoSuchObject) {
		t.Fatalf("deleted fixture remains on peer: %v", e)
	}
	t.Log("PASS: deletion of disposable empty site propagates to DC2")
}

func integrationCleanupApply(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	site, e := s.Sites.Create(ctx, "Cleanup-Apply-Test", "test", "")
	must(e)
	defer s.Sites.Delete(context.Background(), "Cleanup-Apply-Test", "test", "")
	must(s.Repl.Sync(ctx, "dc2.sambaadm.test", "dc1.sambaadm.test", ConfigDN(s.Sites.ldap.BaseDN()), "test", ""))
	// Freshly joined fixtures may have no successful inbound history yet.
	// Establish real bidirectional replication for every hosted partition.
	base := s.Sites.ldap.BaseDN()
	for _, nc := range []string{base, ConfigDN(base), "CN=Schema," + ConfigDN(base), "DC=DomainDnsZones," + base, "DC=ForestDnsZones," + base} {
		must(s.Repl.Sync(ctx, "dc1.sambaadm.test", "dc2.sambaadm.test", nc, "test", ""))
		must(s.Repl.Sync(ctx, "dc2.sambaadm.test", "dc1.sambaadm.test", nc, "test", ""))
	}
	for _, name := range []string{"dc1.sambaadm.test", "dc2.sambaadm.test"} {
		st, e := s.Repl.StatusFor(ctx, name)
		must(e)
		if st.Health != "healthy" {
			t.Fatalf("fixture replication not ready: %+v", st)
		}
	}
	plan, e := s.Sites.PreviewCleanup(ctx, []string{site.DN})
	must(e)
	if len(plan.Objects) != 3 {
		t.Fatalf("standard site children missing from preview: %d", len(plan.Objects))
	}
	domain, e := s.Sites.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: plan.BaseDN, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
	must(e)
	helperCfg := &config.Config{}
	helperCfg.Helper.Node = "dc2.sambaadm.test"
	helperCfg.Helper.DomainBackupEnabled = true
	helperCfg.Helper.BackupRoot = t.TempDir()
	job := seedVerifiedCleanupBackup(t, helperCfg, plan, domain.GetRawAttributeValue("objectGUID"))
	s.Sites.helpers = testHelperClient(t, &Services{Audit: s.Audit}, helperCfg)
	in := CleanupApplyRequest{CleanupBackupRequest: CleanupBackupRequest{CleanupRequest: CleanupRequest{DNs: []string{site.DN}, Revision: plan.Revision}, ID: job.ID, Controller: job.Controller}, Confirm: true}
	noConfirm := in
	noConfirm.Confirm = false
	if _, e = s.Sites.ApplyCleanup(ctx, noConfirm, "test", "", s.Repl); e == nil {
		t.Fatal("confirmation bypass")
	}
	result, e := s.Sites.ApplyCleanup(ctx, in, "test", "", s.Repl)
	must(e)
	if result.Status != "completed" {
		t.Fatalf("apply stopped: %+v", result)
	}
	for _, name := range []string{"dc1.sambaadm.test", "dc2.sambaadm.test"} {
		uri, e := consistencyPeerURI(s.Sites.ldap.URI(), name)
		must(e)
		peer := s.Sites.ldap.ServicePeer(uri)
		_, e = peer.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: site.DN, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
		peer.Close()
		if !ldap.IsErrorWithCode(e, ldap.LDAPResultNoSuchObject) {
			t.Fatalf("site remains on %s: %v", name, e)
		}
	}
	status, e := s.Sites.DomainBackupStatus(ctx, job.Controller, job.ID)
	must(e)
	if !status.ApplyReserved || len(status.ApplyEvents) != 7 || status.ApplyEvents[6].Status != "completed" {
		t.Fatalf("missing persisted journal: %+v", status)
	}
	if _, e = s.Sites.ApplyCleanup(ctx, in, "test", "", s.Repl); e == nil {
		t.Fatal("replayed deleted plan")
	}
	t.Log("PASS: application consumed verified fixture receipt, deleted 3 revision-asserted objects, persisted journal and confirmed deletion on both DCs")
}

func TestIntegrationCleanupApplyConflictAfterFirstDelete(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("requires disposable two-DC domain")
	}
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	site, e := s.Sites.Create(ctx, "Cleanup-Partial-Test", "test", "")
	must(e)
	defer s.Sites.Delete(context.Background(), "Cleanup-Partial-Test", "test", "")
	base := s.Sites.ldap.BaseDN()
	for _, nc := range []string{base, ConfigDN(base), "CN=Schema," + ConfigDN(base), "DC=DomainDnsZones," + base, "DC=ForestDnsZones," + base} {
		must(s.Repl.Sync(ctx, "dc1.sambaadm.test", "dc2.sambaadm.test", nc, "test", ""))
		must(s.Repl.Sync(ctx, "dc2.sambaadm.test", "dc1.sambaadm.test", nc, "test", ""))
	}
	p, e := s.Sites.PreviewCleanup(ctx, []string{site.DN})
	must(e)
	order, e := cleanupOrder(p)
	must(e)
	domain, e := s.Sites.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: p.BaseDN, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
	must(e)
	cfg := &config.Config{}
	cfg.Helper.Node = "dc2.sambaadm.test"
	cfg.Helper.DomainBackupEnabled = true
	cfg.Helper.BackupRoot = t.TempDir()
	job := seedVerifiedCleanupBackup(t, cfg, p, domain.GetRawAttributeValue("objectGUID"))
	var changed atomic.Bool
	hook := func(ctx context.Context, method string, raw json.RawMessage) error {
		if method != "topology.cleanup.event" {
			return nil
		}
		var in HostOperation
		if err := json.Unmarshal(raw, &in); err != nil {
			return err
		}
		var event CleanupApplyEvent
		if err := json.Unmarshal(in.Input, &event); err != nil {
			return err
		}
		if event.Status == "deleted" && changed.CompareAndSwap(false, true) {
			request := ldap.NewModifyRequest(order[1].DN, nil)
			request.Replace("description", []string{"concurrent administrator change"})
			return s.Sites.ldap.Modify(ctx, request)
		}
		return nil
	}
	s.Sites.helpers = testHelperClient(t, &Services{Audit: s.Audit}, cfg, hook)
	in := CleanupApplyRequest{CleanupBackupRequest: CleanupBackupRequest{CleanupRequest: CleanupRequest{DNs: []string{site.DN}, Revision: p.Revision}, ID: job.ID, Controller: job.Controller}, Confirm: true}
	result, e := s.Sites.ApplyCleanup(ctx, in, "test", "", s.Repl)
	must(e)
	if !changed.Load() || result.Status != "stopped" || len(result.Events) != 4 || result.Events[3].Status != "stopped" {
		t.Fatalf("did not stop on second object conflict: %+v", result)
	}
	for _, o := range order[1:] {
		_, e = s.Sites.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: o.DN, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
		must(e)
	}
	status, e := s.Sites.DomainBackupStatus(ctx, job.Controller, job.ID)
	must(e)
	if !status.ApplyReserved || len(status.ApplyEvents) != 4 {
		t.Fatalf("partial journal lost: %+v", status)
	}
	t.Log("PASS: real LDAP revision changed after first deletion; later objects survived and stopped journal persisted")
}

func TestIntegrationCleanupDCRemnants(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("requires disposable two-DC domain")
	}
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	base := s.Sites.ldap.BaseDN()
	computer := "CN=Retired-Test,OU=Domain Controllers," + base
	server := "CN=Retired-Test,CN=Servers,CN=Default-First-Site-Name," + SitesContainerDN(base)
	must(s.Sites.ldap.Add(ctx, computer, []ldap.Attribute{{Type: "objectClass", Vals: []string{"computer"}}, {Type: "sAMAccountName", Vals: []string{"Retired-Test$"}}, {Type: "userAccountControl", Vals: []string{"8194"}}, {Type: "dNSHostName", Vals: []string{"retired-test.sambaadm.test"}}}))
	defer s.Sites.ldap.Delete(context.Background(), computer)
	must(s.Sites.ldap.Add(ctx, server, []ldap.Attribute{{Type: "objectClass", Vals: []string{"server"}}, {Type: "serverReference", Vals: []string{computer}}, {Type: "dNSHostName", Vals: []string{"retired-test.sambaadm.test"}}}))
	defer s.Sites.ldap.Delete(context.Background(), server)
	for _, nc := range []string{base, ConfigDN(base), "CN=Schema," + ConfigDN(base), "DC=DomainDnsZones," + base, "DC=ForestDnsZones," + base} {
		must(s.Repl.Sync(ctx, "dc1.sambaadm.test", "dc2.sambaadm.test", nc, "test", ""))
		must(s.Repl.Sync(ctx, "dc2.sambaadm.test", "dc1.sambaadm.test", nc, "test", ""))
	}
	p, e := s.Sites.PreviewCleanup(ctx, []string{server})
	must(e)
	if len(p.Objects) != 2 {
		t.Fatalf("retired computer not included: %+v", p.Objects)
	}
	// An account enabled only on the other replica must block cleanup even
	// though the primary still shows a retired disabled account.
	uri, e := consistencyPeerURI(s.Sites.ldap.URI(), "dc2.sambaadm.test")
	must(e)
	peer := s.Sites.ldap.ServicePeer(uri)
	defer peer.Close()
	dc, e := s.Sites.controller(ctx, "dc2.sambaadm.test")
	must(e)
	ntds, e := peer.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dc.NTDS, Scope: ldapproto.ScopeBase(), Attributes: []string{"options"}})
	must(e)
	old := ntds.GetAttributeValues("options")
	flags, e := strconv.Atoi(ntds.GetAttributeValue("options"))
	must(e)
	reset := func() {
		req := ldap.NewModifyRequest(dc.NTDS, nil)
		req.Replace("options", old)
		_ = peer.Modify(context.Background(), req)
	}
	defer reset()
	pause := ldap.NewModifyRequest(dc.NTDS, nil)
	pause.Replace("options", []string{strconv.Itoa(flags | 2)})
	must(peer.Modify(ctx, pause))
	enabled := ldap.NewModifyRequest(computer, nil)
	enabled.Replace("userAccountControl", []string{"8192"})
	must(peer.Modify(ctx, enabled))
	checks, e := s.Sites.CheckCleanup(ctx, CleanupChecksRequest{CleanupRequest: CleanupRequest{DNs: []string{server}, Revision: p.Revision}, Peer: "dc2.sambaadm.test"})
	must(e)
	mismatch := false
	for _, check := range checks.Checks {
		if check.ID == "peer" && check.Status == "blocked" {
			mismatch = true
		}
	}
	if !mismatch {
		t.Fatalf("peer-only enabled DC account was not blocked: %+v", checks)
	}
	enabled = ldap.NewModifyRequest(computer, nil)
	enabled.Replace("userAccountControl", []string{"8194"})
	must(peer.Modify(ctx, enabled))
	reset()
	// The paused DC can record failed background replication for any NC, and
	// its options live in Configuration. Restore every partition on both
	// peers before asking the production health guard to permit deletion.
	for _, nc := range []string{base, ConfigDN(base), "CN=Schema," + ConfigDN(base), "DC=DomainDnsZones," + base, "DC=ForestDnsZones," + base} {
		must(s.Repl.Sync(ctx, "dc1.sambaadm.test", "dc2.sambaadm.test", nc, "test", ""))
		must(s.Repl.Sync(ctx, "dc2.sambaadm.test", "dc1.sambaadm.test", nc, "test", ""))
	}
	p, e = s.Sites.PreviewCleanup(ctx, []string{server})
	must(e)
	domain, e := s.Sites.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: base, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
	must(e)
	cfg := &config.Config{}
	cfg.Helper.Node = "dc2.sambaadm.test"
	cfg.Helper.DomainBackupEnabled = true
	cfg.Helper.BackupRoot = t.TempDir()
	job := seedVerifiedCleanupBackup(t, cfg, p, domain.GetRawAttributeValue("objectGUID"))
	s.Sites.helpers = testHelperClient(t, &Services{Audit: s.Audit}, cfg)
	in := CleanupApplyRequest{CleanupBackupRequest: CleanupBackupRequest{CleanupRequest: CleanupRequest{DNs: []string{server}, Revision: p.Revision}, ID: job.ID, Controller: job.Controller}, Confirm: true}
	if _, e = s.Sites.ApplyCleanup(ctx, in, "test", "", s.Repl); e == nil {
		t.Fatal("retirement confirmation bypass")
	}
	in.ConfirmDecommissioned = true
	out, e := s.Sites.ApplyCleanup(ctx, in, "test", "", s.Repl)
	must(e)
	if out.Status != "completed" {
		t.Fatalf("cleanup failed: %+v", out)
	}
	for _, name := range []string{"dc1.sambaadm.test", "dc2.sambaadm.test"} {
		uri, e := consistencyPeerURI(s.Sites.ldap.URI(), name)
		must(e)
		peer := s.Sites.ldap.ServicePeer(uri)
		for _, dn := range []string{server, computer} {
			_, e = peer.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
			if !ldap.IsErrorWithCode(e, ldap.LDAPResultNoSuchObject) {
				t.Fatalf("remnant remains on %s: %s: %v", name, dn, e)
			}
		}
		peer.Close()
	}
	t.Log("PASS: retired server and disabled computer deleted with receipt and journal; Configuration and domain NC converged on both DCs")
}
