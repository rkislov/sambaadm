package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
)

func integrationServices(t *testing.T, mutate bool) (*Services, config.LDAPConfig) {
	t.Helper()
	if os.Getenv("SAMBAADM_IT") != "1" {
		t.Skip("set SAMBAADM_IT=1 to run against the disposable DC")
	}
	cfg := config.LDAPConfig{URI: os.Getenv("SAMBAADM_IT_URI"), BaseDN: os.Getenv("SAMBAADM_IT_BASE"), Bind: config.BindConfig{Type: "simple", User: os.Getenv("SAMBAADM_IT_USER"), PasswordEnv: "SAMBAADM_PASSWORD"}}
	if cfg.BaseDN == "" {
		cfg.BaseDN = "DC=sambaadm,DC=test"
	}
	if cfg.URI == "" || cfg.Bind.User == "" || os.Getenv("SAMBAADM_PASSWORD") == "" {
		t.Fatal("SAMBAADM_IT_URI, SAMBAADM_IT_USER and SAMBAADM_PASSWORD are required")
	}
	if mutate && (os.Getenv("SAMBAADM_IT_MUTATE") != "SAMBAADM.TEST" || !strings.EqualFold(cfg.BaseDN, "DC=sambaadm,DC=test")) {
		t.Fatal("mutating tests require SAMBAADM_IT_MUTATE=SAMBAADM.TEST and the disposable SAMBAADM.TEST domain")
	}
	client := ldapproto.NewServiceClient(cfg, func() string { return os.Getenv("SAMBAADM_PASSWORD") })
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if e := client.Connect(ctx); e != nil {
		t.Fatal(e)
	}
	logger, e := audit.New(t.TempDir() + "/audit.log")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { logger.Close() })
	return NewWithOptions(client, logger, ServiceOptions{ToolUser: cfg.Bind.User, ToolPassword: func() string { return os.Getenv("SAMBAADM_PASSWORD") }}), cfg
}
func TestIntegrationDomainInfo(t *testing.T) {
	s, _ := integrationServices(t, false)
	info, e := s.Domain.Info(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if info.NetBIOS == "" || info.FunctionLvl == "" {
		t.Fatalf("domain info did not read actual LDAP data: %+v", info)
	}
	t.Logf("domain base=%s function-level=%s", info.BaseDN, info.FunctionLvl)
}
func TestIntegrationDirectoryLifecycle(t *testing.T) {
	s, cfg := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	actor := "integration"
	ip := "127.0.0.1"
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	login := "it" + suffix
	root, e := s.OU.Create(ctx, CreateOUInput{Name: "IT-" + suffix}, actor, ip)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.OU.Delete(context.Background(), root.DN, actor, ip) })
	source, e := s.OU.Create(ctx, CreateOUInput{Name: "Source", ParentDN: root.DN}, actor, ip)
	if e != nil {
		t.Fatal(e)
	}
	sourceDN := source.DN
	t.Cleanup(func() { s.OU.Delete(context.Background(), sourceDN, actor, ip) })
	target, e := s.OU.Create(ctx, CreateOUInput{Name: "Target", ParentDN: root.DN}, actor, ip)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.OU.Delete(context.Background(), target.DN, actor, ip) })
	groupName := "itg" + suffix
	group, e := s.Groups.Create(ctx, CreateGroupInput{Name: groupName, OU: root.DN}, actor, ip)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Groups.Delete(context.Background(), groupName, actor, ip) })
	t.Cleanup(func() { s.Users.Delete(context.Background(), login, actor, ip) })
	user, e := s.Users.Create(ctx, CreateUserInput{Login: login, DisplayName: "Integration " + suffix, OU: source.DN, Password: "Lab-User-Pass1!", Enabled: true}, actor, ip)
	if e != nil {
		t.Fatal(e)
	}
	if !user.Enabled || !strings.Contains(user.DN, source.DN) {
		t.Fatalf("unexpected created user: %+v", user)
	}
	if e = s.Groups.AddMember(ctx, groupName, user.DN, actor, ip); e != nil {
		t.Fatal(e)
	}
	members, e := s.Groups.Members(ctx, groupName)
	if e != nil || len(members) != 1 || !strings.EqualFold(members[0], user.DN) {
		t.Fatalf("membership: %+v, %v", members, e)
	}
	if e = s.Groups.RemoveMember(ctx, groupName, user.DN, actor, ip); e != nil {
		t.Fatal(e)
	}
	members, e = s.Groups.Members(ctx, groupName)
	if e != nil || len(members) != 0 {
		t.Fatalf("member removal: %+v %v", members, e)
	}
	if e = s.Users.Disable(ctx, login, actor, ip); e != nil {
		t.Fatal(e)
	}
	user, e = s.Users.Show(ctx, login)
	if e != nil || user.Enabled {
		t.Fatalf("disable: %+v %v", user, e)
	}
	if e = s.Users.Enable(ctx, login, actor, ip); e != nil {
		t.Fatal(e)
	}
	user, e = s.Users.Show(ctx, login)
	if e != nil || !user.Enabled {
		t.Fatalf("enable: %+v %v", user, e)
	}
	if e = s.Users.SetPassword(ctx, login, "Lab-User-New-Pass2!", actor, ip); e != nil {
		t.Fatal(e)
	}
	authClient := ldapproto.NewClient(cfg)
	if e = authClient.BindSimple(ctx, login+"@sambaadm.test", "Lab-User-New-Pass2!"); e != nil {
		t.Fatal(e)
	}
	authClient.Close()
	if e = s.Users.Move(ctx, login, target.DN, actor, ip); e != nil {
		t.Fatal(e)
	}
	user, e = s.Users.Show(ctx, login)
	if e != nil || !strings.Contains(user.DN, target.DN) {
		t.Fatalf("move: %+v %v", user, e)
	}
	if e = s.OU.Move(ctx, sourceDN, target.DN, actor, ip); e != nil {
		t.Fatal(e)
	}
	sourceDN = "OU=Source," + target.DN
	if _, e = s.Groups.Show(ctx, group.SAMAccountName); e != nil {
		t.Fatal(e)
	}
	if e = s.OU.Delete(ctx, sourceDN, actor, ip); e != nil {
		t.Fatal(e)
	}
	if e = s.Users.Delete(ctx, login, actor, ip); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Users.Show(ctx, login); e == nil {
		t.Fatal("deleted user is still visible")
	}
	t.Log("created, grouped, disabled, enabled, reset password, moved and deleted a real AD user")
}
func TestIntegrationDNSLifecycle(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	zone := fmt.Sprintf("it%d.sambaadm.test", time.Now().UnixNano())
	actor := "integration"
	ip := "127.0.0.1"
	if e := s.DNS.CreateZone(ctx, zone, actor, ip); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.DNS.DeleteZone(context.Background(), zone, actor, ip) })
	in := AddDNSRecordInput{Zone: zone, Name: "files", Type: "A", Data: "192.0.2.20"}
	if e := s.DNS.AddRecord(ctx, in, actor, ip); e != nil {
		t.Fatal(e)
	}
	check := func(want string) {
		t.Helper()
		records, e := s.DNS.QueryRecords(ctx, zone, "files", "A")
		if e != nil {
			t.Fatal(e)
		}
		for _, r := range records {
			if strings.Contains(r.Raw, want) {
				return
			}
		}
		t.Fatalf("record %s not found in %+v", want, records)
	}
	check(in.Data)
	nodes, e := s.DNS.Nodes(ctx, zone)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, n := range nodes {
		if n == "files" {
			found = true
		}
	}
	if !found {
		t.Fatalf("DNS tree missing files: %+v", nodes)
	}
	if e = s.DNS.UpdateRecord(ctx, UpdateDNSRecordInput{Zone: zone, Name: "files", Type: "A", OldData: in.Data, NewData: "192.0.2.21"}, actor, ip); e != nil {
		t.Fatal(e)
	}
	check("192.0.2.21")
	in.Data = "192.0.2.21"
	if e = s.DNS.DeleteRecord(ctx, in, actor, ip); e != nil {
		t.Fatal(e)
	}
	records, e := s.DNS.QueryRecords(ctx, zone, "files", "A")
	if e == nil && len(records) > 0 {
		t.Fatalf("deleted DNS record remains: %+v", records)
	}
	t.Log("created zone and A record, enumerated LDAP nodes, updated and deleted the record")
}
func TestIntegrationGPOLifecycle(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	name := fmt.Sprintf("IT-GPO-%d", time.Now().UnixNano())
	actor := "integration"
	ip := "127.0.0.1"
	if _, e := s.GPO.Create(ctx, name, actor, ip); e != nil {
		t.Fatal(e)
	}
	gpos, e := s.GPO.List(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var guid string
	for _, g := range gpos {
		if g.DisplayName == name {
			guid = g.GUID
		}
	}
	if guid == "" {
		t.Fatalf("new GPO missing in list: %+v", gpos)
	}
	t.Cleanup(func() { s.GPO.Delete(context.Background(), guid, actor, ip) })
	ou, e := s.OU.Create(ctx, CreateOUInput{Name: name}, actor, ip)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.OU.Delete(context.Background(), ou.DN, actor, ip) })
	if e = s.GPO.Link(ctx, ou.DN, guid, actor, ip); e != nil {
		t.Fatal(e)
	}
	links, e := s.GPO.GetLinks(ctx, ou.DN)
	if e != nil || !strings.Contains(strings.ToLower(links), strings.ToLower(strings.Trim(guid, "{}"))) {
		t.Fatalf("GPO link: %s %v", links, e)
	}
	if _, e = s.GPO.Show(ctx, guid); e != nil {
		t.Fatal(e)
	}
	sysvol := filepath.Join("/var/lib/samba/sysvol/sambaadm.test/Policies", guid)
	marker := []byte("sambaadm integration backup content")
	if e = os.WriteFile(filepath.Join(sysvol, "Machine", "integration.txt"), marker, 0644); e != nil {
		t.Fatal(e)
	}
	backupRoot := t.TempDir()
	if e = s.GPO.Backup(ctx, guid, backupRoot, actor, ip); e != nil {
		t.Fatal(e)
	}
	backupPath := filepath.Join(backupRoot, "policy", guid)
	if contents, err := os.ReadFile(filepath.Join(backupPath, "Machine", "integration.txt.SAMBABACKUP")); err != nil || string(contents) != string(marker) {
		t.Fatalf("backup content: %q %v", contents, err)
	}
	restoredName := name + "-restored"
	if e = s.GPO.Restore(ctx, restoredName, backupPath, actor, ip); e != nil {
		t.Fatal(e)
	}
	restoredList, err := s.GPO.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var restoredGUID string
	for _, g := range restoredList {
		if g.DisplayName == restoredName {
			restoredGUID = g.GUID
		}
	}
	if restoredGUID == "" || restoredGUID == guid {
		t.Fatalf("restore did not create a new policy: %q", restoredGUID)
	}
	t.Cleanup(func() { s.GPO.Delete(context.Background(), restoredGUID, actor, ip) })
	restoredFile := filepath.Join("/var/lib/samba/sysvol/sambaadm.test/Policies", restoredGUID, "Machine", "integration.txt")
	if contents, err := os.ReadFile(restoredFile); err != nil || string(contents) != string(marker) {
		t.Fatalf("restored content: %q %v", contents, err)
	}
	if e = s.GPO.Unlink(ctx, ou.DN, guid, actor, ip); e != nil {
		t.Fatal(e)
	}
	t.Log("created GPO, linked it to OU, read details, backed up files, restored into a new GPO and unlinked")
}
