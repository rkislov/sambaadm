package service

import (
	"context"
	"encoding/json"
	"github.com/go-ldap/ldap/v3"
	"os"
	"os/exec"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"testing"
	"time"
)

func TestIntegrationCleanupExtendedDCMetadata(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("requires two disposable DCs")
	}
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	base := s.Sites.ldap.BaseDN()
	host := "retired-full.sambaadm.test"
	computer := "CN=Retired-Full,OU=Domain Controllers," + base
	server := "CN=Retired-Full,CN=Servers,CN=Default-First-Site-Name," + SitesContainerDN(base)
	ntds := "CN=NTDS Settings," + server
	created := []string{}
	defer func() {
		for i := len(created) - 1; i >= 0; i-- {
			_ = s.Sites.ldap.Delete(context.Background(), created[i])
		}
	}()
	add := func(dn, class string, attrs ...ldap.Attribute) {
		t.Helper()
		attrs = append([]ldap.Attribute{{Type: "objectClass", Vals: []string{class}}}, attrs...)
		if class == "nTDSDSA" || class == "rIDSet" {
			data, _ := json.Marshal(attrs)
			script := `import json,sys
from samba.auth import system_session
from samba.samdb import SamDB
from samba import param
lp=param.LoadParm();lp.load("/etc/samba/smb.conf")
sam=SamDB(session_info=system_session(),lp=lp)
record={'dn':sys.argv[1]}
for attribute in json.loads(sys.argv[2]):
 record[attribute['Type']]=attribute['Vals']
sam.add(record,controls=['relax:0'])`
			output, err := exec.CommandContext(ctx, "/usr/bin/python3", "-c", script, dn, string(data)).CombinedOutput()
			if err != nil {
				t.Fatalf("system-only fixture: %v: %s", err, output)
			}
			created = append(created, dn)
			return
		}
		conn, e := s.Sites.ldap.Conn(ctx)
		must(e)
		request := ldap.NewAddRequest(dn, []ldap.Control{ldap.NewControlString("1.3.6.1.4.1.4203.666.5.12", true, "")})
		request.Attributes = attrs
		must(conn.Add(request))
		created = append(created, dn)
	}
	add(computer, "computer", ldap.Attribute{Type: "sAMAccountName", Vals: []string{"Retired-Full$"}}, ldap.Attribute{Type: "userAccountControl", Vals: []string{"8194"}}, ldap.Attribute{Type: "dNSHostName", Vals: []string{host}})
	add(server, "server", ldap.Attribute{Type: "serverReference", Vals: []string{computer}}, ldap.Attribute{Type: "dNSHostName", Vals: []string{host}})
	add(ntds, "nTDSDSA", ldap.Attribute{Type: "options", Vals: []string{"6"}}, ldap.Attribute{Type: "invocationId", Vals: []string{"0123456789abcdef"}}, ldap.Attribute{Type: "hasMasterNCs", Vals: []string{base, ConfigDN(base), "CN=Schema," + ConfigDN(base)}}, ldap.Attribute{Type: "msDS-hasMasterNCs", Vals: []string{base, ConfigDN(base), "CN=Schema," + ConfigDN(base)}})
	partition, e := s.Sites.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: "CN=Partitions," + ConfigDN(base), Filter: "(&(objectClass=crossRef)(nCName=" + ldap.EscapeFilter("DC=DomainDnsZones,"+base) + "))", Attributes: []string{"objectGUID"}})
	must(e)
	replica := ldap.NewModifyRequest(partition.DN, nil)
	replica.Add("msDS-NC-Replica-Locations", []string{ntds})
	must(s.Sites.ldap.Modify(ctx, replica))
	add("CN=RID Set,"+computer, "rIDSet", ldap.Attribute{Type: "rIDAllocationPool", Vals: []string{"21474836484500"}}, ldap.Attribute{Type: "rIDPreviousAllocationPool", Vals: []string{"21474836484500"}}, ldap.Attribute{Type: "rIDNextRID", Vals: []string{"4500"}}, ldap.Attribute{Type: "rIDUsedPool", Vals: []string{"0"}})
	global := "CN=Cleanup-DFSR-Global,CN=System," + base
	add(global, "msDFSR-GlobalSettings")
	group := "CN=CleanupRG," + global
	add(group, "msDFSR-ReplicationGroup", ldap.Attribute{Type: "msDFSR-ReplicationGroupType", Vals: []string{"1"}})
	topology := "CN=Topology," + group
	add(topology, "msDFSR-Topology")
	member := "CN=Retired-Full," + topology
	add(member, "msDFSR-Member", ldap.Attribute{Type: "msDFSR-ComputerReference", Vals: []string{computer}})
	liveDC, e := s.Sites.controller(ctx, "dc1.sambaadm.test")
	must(e)
	liveMember := "CN=Live-Full," + topology
	add(liveMember, "msDFSR-Member", ldap.Attribute{Type: "msDFSR-ComputerReference", Vals: []string{liveDC.Computer}})
	add("CN=retired-dfsr-inbound,"+liveMember, "msDFSR-Connection", ldap.Attribute{Type: "fromServer", Vals: []string{member}})
	groupEntry, e := s.Sites.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: group, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
	must(e)
	groupGUID := string(groupEntry.GetRawAttributeValue("objectGUID"))
	local := "CN=DFSR-LocalSettings," + computer
	add(local, "msDFSR-LocalSettings")
	subscriber := "CN=Domain System Volume," + local
	add(subscriber, "msDFSR-Subscriber", ldap.Attribute{Type: "msDFSR-MemberReference", Vals: []string{member}}, ldap.Attribute{Type: "msDFSR-ReplicationGroupGuid", Vals: []string{groupGUID}})
	add("CN=SYSVOL Subscription,"+subscriber, "msDFSR-Subscription", ldap.Attribute{Type: "msDFSR-Enabled", Vals: []string{"FALSE"}}, ldap.Attribute{Type: "msDFSR-ReplicationGroupGuid", Vals: []string{groupGUID}}, ldap.Attribute{Type: "msDFSR-ContentSetGuid", Vals: []string{"0123456789abcdef"}})
	live, e := s.Sites.controller(ctx, "dc2.sambaadm.test")
	must(e)
	add("CN=retired-full-connection,"+live.NTDS, "nTDSConnection", ldap.Attribute{Type: "fromServer", Vals: []string{ntds}}, ldap.Attribute{Type: "enabledConnection", Vals: []string{"FALSE"}}, ldap.Attribute{Type: "options", Vals: []string{"0"}})
	// Shared DNS owner: removing the retired SRV must preserve the live SRV.
	records := []AddDNSRecordInput{{Zone: "sambaadm.test", Name: "retired-full", Type: "A", Data: "192.0.2.231"}, {Zone: "sambaadm.test", Name: "@", Type: "A", Data: "192.0.2.231"}, {Zone: "sambaadm.test", Name: "_cleanup._tcp", Type: "SRV", Data: host + " 389 0 100"}, {Zone: "sambaadm.test", Name: "_cleanup._tcp", Type: "SRV", Data: "dc1.sambaadm.test 389 0 100"}}
	for _, r := range records {
		must(s.DNS.AddRecord(ctx, r, "test", ""))
	}
	defer func() {
		for _, r := range records {
			_ = s.DNS.DeleteRecord(context.Background(), r, "test", "")
		}
	}()
	for _, nc := range []string{base, ConfigDN(base), "CN=Schema," + ConfigDN(base), "DC=DomainDnsZones," + base, "DC=ForestDnsZones," + base} {
		must(s.Repl.Sync(ctx, "dc1.sambaadm.test", "dc2.sambaadm.test", nc, "test", ""))
		must(s.Repl.Sync(ctx, "dc2.sambaadm.test", "dc1.sambaadm.test", nc, "test", ""))
	}
	p, e := s.Sites.PreviewCleanup(ctx, []string{server})
	must(e)
	peerURI, e := consistencyPeerURI(s.Sites.ldap.URI(), "dc2.sambaadm.test")
	must(e)
	peerCheck := s.Sites.ldap.ServicePeer(peerURI)
	peerPlan, e := (&SiteService{ldap: peerCheck}).PreviewCleanup(ctx, []string{server})
	peerCheck.Close()
	must(e)
	if len(p.Objects) != len(peerPlan.Objects) {
		t.Fatalf("fixture plans differ in length: %d/%d", len(p.Objects), len(peerPlan.Objects))
	}
	for i, o := range p.Objects {
		if string(comparableCleanupObject(o)) != string(comparableCleanupObject(peerPlan.Objects[i])) {
			t.Fatalf("fixture divergence %s: primary=%s peer=%s", o.DN, comparableCleanupObject(o), comparableCleanupObject(peerPlan.Objects[i]))
		}
	}
	order, e := cleanupOrder(p)
	must(e)
	if len(order) < 10 {
		t.Fatalf("incomplete expanded plan: %+v", p.Objects)
	}
	domain, e := s.Sites.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: base, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
	must(e)
	cfg := &config.Config{}
	cfg.Helper.Node = "dc2.sambaadm.test"
	cfg.Helper.DomainBackupEnabled = true
	cfg.Helper.BackupRoot = t.TempDir()
	job := seedVerifiedCleanupBackup(t, cfg, p, domain.GetRawAttributeValue("objectGUID"))
	s.Sites.helpers = testHelperClient(t, &Services{Audit: s.Audit}, cfg)
	request := CleanupApplyRequest{CleanupBackupRequest: CleanupBackupRequest{CleanupRequest: CleanupRequest{DNs: []string{server}, Revision: p.Revision}, ID: job.ID, Controller: job.Controller}, Confirm: true, ConfirmDecommissioned: true}
	out, e := s.Sites.ApplyCleanup(ctx, request, "test", "", s.Repl)
	must(e)
	if out.Status != "completed" {
		t.Fatalf("extended cleanup stopped: %+v", out)
	}
	// Normal LDAP searches hide links to deleted objects. Inspect storage too:
	// cleanup must replicate a deleted link, not merely hide an active one.
	script := `import sys,ldb
from samba.auth import system_session
from samba.samdb import SamDB
from samba import param
lp=param.LoadParm();lp.load("/etc/samba/smb.conf")
sam=SamDB(session_info=system_session(),lp=lp)
row=sam.search(base=sys.argv[1],scope=ldb.SCOPE_BASE,attrs=['msDS-NC-Replica-Locations'],controls=['reveal_internals:0','extended_dn:1:1'])[0]
for value in row.get('msDS-NC-Replica-Locations',[]):
 link=ldb.Dn(sam,str(value))
 if 'cn=retired-full' in str(link).lower():
  assert int(link.get_extended_component('RMD_FLAGS'))==1, 'Active dangling replica link'
`
	output, err := exec.CommandContext(ctx, "/usr/bin/python3", "-c", script, partition.DN).CombinedOutput()
	if err != nil {
		t.Fatalf("replica link storage check: %v: %s", err, output)
	}
	results, e := s.DNS.QueryRecords(ctx, "sambaadm.test", "_cleanup._tcp", "SRV")
	must(e)
	srvCount := 0
	for _, record := range results {
		if record.Type == "SRV" {
			srvCount++
			if record.Data != "dc1.sambaadm.test. 389 0 100" {
				t.Fatalf("unexpected surviving SRV: %+v", record)
			}
		}
	}
	if srvCount != 1 {
		t.Fatalf("shared SRV owner damaged: %+v", results)
	}
	for _, name := range []string{"dc1.sambaadm.test", "dc2.sambaadm.test"} {
		uri, e := consistencyPeerURI(s.Sites.ldap.URI(), name)
		must(e)
		peer := s.Sites.ldap.ServicePeer(uri)
		for _, o := range p.Objects {
			if len(o.Remove) > 0 {
				must(verifyCleanupModification(ctx, peer, o))
				continue
			}
			_, e = peer.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: o.DN, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID"}})
			if !ldap.IsErrorWithCode(e, ldap.LDAPResultNoSuchObject) {
				t.Fatalf("object remains on %s: %s: %v", name, o.DN, e)
			}
		}
		peer.Close()
	}
	t.Log("PASS: NTDS, inbound connection, RID/DFSR descendants removed; shared DNS preserved and all affected partitions verified on both surviving DCs")
}
