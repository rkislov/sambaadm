package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sambaadm/internal/policy"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
)

func integrationServices(t *testing.T, mutate bool) (*Services, config.LDAPConfig) {
	t.Helper()
	if os.Getenv("SAMBAADM_IT") != "1" {
		t.Skip("set SAMBAADM_IT=1 to run against the disposable DC")
	}
	cfg := config.LDAPConfig{CACert: os.Getenv("SAMBAADM_IT_CA"), URI: os.Getenv("SAMBAADM_IT_URI"), BaseDN: os.Getenv("SAMBAADM_IT_BASE"), Bind: config.BindConfig{Type: "simple", User: os.Getenv("SAMBAADM_IT_USER"), PasswordEnv: "SAMBAADM_PASSWORD"}}
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
	port, _ := strconv.Atoi(os.Getenv("SAMBAADM_IT_SMB_PORT"))
	return NewWithOptions(client, logger, ServiceOptions{GPO: config.GPOConfig{SMBPort: port}, Username: cfg.Bind.User, Password: func() string { return os.Getenv("SAMBAADM_PASSWORD") }}), cfg
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
	// Editing is explicitly enabled only for this disposable local DC.
	s.GPO.gpoCfg.EditorEnabled = true
	s.GPO.gpoCfg.ADMXPath = editorTemplate(t)
	original := []policy.Record{{Key: `Software\Unrelated`, Name: "Preserve", Type: 3, Data: []byte{0, 59, 0, 93, 255}}}
	originalBytes, _ := policy.Encode(original)
	userPolicy := filepath.Join(sysvol, "User", "Registry.pol")
	if e = os.WriteFile(userPolicy, originalBytes, 0640); e != nil {
		t.Fatal(e)
	}
	polPath := filepath.Join(sysvol, "Machine", "Registry.pol")
	if e = os.WriteFile(polPath, originalBytes, 0640); e != nil {
		t.Fatal(e)
	}
	// Preserve the user half of the version and unrelated CSE metadata.
	existingExtension := "[{00000000-0000-0000-0000-000000000001}{00000000-0000-0000-0000-000000000002}]"
	seed := ldap.NewModifyRequest("CN="+guid+",CN=Policies,CN=System,"+s.GPO.ldap.BaseDN(), nil)
	seed.Replace("versionNumber", []string{"65536"})
	seed.Replace("gPCMachineExtensionNames", []string{existingExtension})
	if e = s.GPO.ldap.Modify(ctx, seed); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(sysvol, "GPT.INI"), []byte("[General]\r\nVersion=65536\r\n"), 0644); e != nil {
		t.Fatal(e)
	}
	before, e := s.GPO.ALTSettings(ctx, guid)
	if e != nil {
		t.Fatal(e)
	}
	saved, e := s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: "chronyd.service", State: "enabled", Revision: before.Revision}, actor, ip)
	if e != nil {
		t.Fatal(e)
	}
	if saved.Version != before.Version+1 || saved.Settings[0].State != "enabled" {
		t.Fatalf("editor save %+v", saved)
	}
	if _, e = s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: "chronyd.service", State: "disabled", Revision: before.Revision}, actor, ip); !errors.Is(e, ErrPolicyConflict) {
		t.Fatalf("stale save: %v", e)
	}
	metadata, e := s.GPO.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: seed.DN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"gPCMachineExtensionNames", "versionNumber"}})
	if e != nil || metadata.GetAttributeValue("gPCMachineExtensionNames") != existingExtension+registryCSE || metadata.GetAttributeValue("versionNumber") != "65537" {
		t.Fatalf("metadata preservation: %+v %v", metadata, e)
	}
	bytesAfter, e := os.ReadFile(polPath)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := policy.Parse(bytesAfter)
	if e != nil || len(parsed) != 2 || !bytes.Equal(parsed[0].Data, original[0].Data) {
		t.Fatalf("unrelated registry data lost: %+v %v", parsed, e)
	}
	info, _ := os.Stat(polPath)
	if info.Mode().Perm() != 0640 {
		t.Fatalf("file mode changed: %v", info.Mode())
	}
	python := `from samba.dcerpc import preg
from samba.ndr import ndr_unpack
import sys
p=ndr_unpack(preg.file,open(sys.argv[1],"rb").read())
assert p.num_entries==2
assert p.entries[1].valuename=="chronyd.service"
assert p.entries[1].type==4
print("Samba preg accepted generated Registry.pol")`
	if output, err := exec.Command("/usr/bin/python3", "-c", python, polPath).CombinedOutput(); err != nil {
		t.Fatalf("Samba parser: %s %v", output, err)
	} else {
		t.Log(string(output))
	}
	disabled, e := s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: "chronyd.service", State: "disabled", Revision: saved.Revision}, actor, ip)
	if e != nil || disabled.Settings[0].State != "disabled" {
		t.Fatalf("disable setting: %+v %v", disabled, e)
	}
	cleared, e := s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: "chronyd.service", State: "not-configured", Revision: disabled.Revision}, actor, ip)
	if e != nil || cleared.Settings[0].State != "not-configured" {
		t.Fatalf("clear setting: %+v %v", cleared, e)
	}
	if contents, _ := os.ReadFile(polPath); !bytes.Equal(contents, originalBytes) {
		t.Fatal("clearing setting changed existing records")
	}
	// A definitive LDAP access denial must restore both files and version.
	viewerLogin := "gpedit" + fmt.Sprint(time.Now().UnixNano())
	if _, e = s.Users.Create(ctx, CreateUserInput{Login: viewerLogin, Password: "Editor-Viewer-Pass1!", OU: ou.DN, Enabled: true}, actor, ip); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Users.Delete(context.Background(), viewerLogin, actor, ip) })
	viewerConfig := config.LDAPConfig{CACert: os.Getenv("SAMBAADM_IT_CA"), URI: os.Getenv("SAMBAADM_IT_URI"), BaseDN: "DC=sambaadm,DC=test", Bind: config.BindConfig{Type: "simple", User: viewerLogin + "@sambaadm.test"}}
	viewerLDAP := ldapproto.NewServiceClient(viewerConfig, func() string { return "Editor-Viewer-Pass1!" })
	defer viewerLDAP.Close()
	deniedEditor := &GPOService{remote: s.GPO.remote, ldap: viewerLDAP, audit: s.GPO.audit, gpoCfg: s.GPO.gpoCfg}
	if _, e = deniedEditor.SetALTSetting(ctx, guid, ALTChange{ID: "chronyd.service", State: "enabled", Revision: cleared.Revision}, actor, ip); e == nil {
		t.Fatal("read-only LDAP identity wrote GPO")
	}
	afterDenied, e := s.GPO.ALTSettings(ctx, guid)
	if e != nil || afterDenied.Revision != cleared.Revision {
		t.Fatalf("failed LDAP save was not rolled back: %+v %v", afterDenied, e)
	}
	if contents, _ := os.ReadFile(userPolicy); !bytes.Equal(contents, originalBytes) {
		t.Fatal("user registry file changed")
	}
	journalPath := filepath.Join(sysvol, editorJournal)
	if e = os.WriteFile(journalPath, []byte("interrupted test save"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.GPO.ALTSettings(ctx, guid); e == nil {
		t.Fatal("ignored pending recovery journal")
	}
	if e = os.Remove(journalPath); e != nil {
		t.Fatal(e)
	}
	backupRoot := t.TempDir()
	if e = s.GPO.Backup(ctx, guid, backupRoot, actor, ip); e != nil {
		t.Fatal(e)
	}
	backupPath := filepath.Join(backupRoot, "policy", guid)
	contents, err := os.ReadFile(filepath.Join(backupPath, "sambaadm-backup.json"))
	if err != nil {
		t.Fatal(err)
	}
	var nativeBackup policyBackup
	if err = json.Unmarshal(contents, &nativeBackup); err != nil || !bytes.Equal(nativeBackup.Files["Machine/integration.txt"], marker) {
		t.Fatalf("backup contents: %v", err)
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

func TestIntegrationUnicodeUserProfile(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	suffix := fmt.Sprint(time.Now().UnixNano())
	ou, err := s.OU.Create(ctx, CreateOUInput{Name: "Проверка, кириллица " + suffix}, "integration", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.OU.Delete(context.Background(), ou.DN, "integration", ""); err != nil {
			t.Error(err)
		}
	})
	login := "unicode" + suffix
	user, err := s.Users.Create(ctx, CreateUserInput{Login: login, DisplayName: "Приёмная Иванова " + suffix, OU: ou.DN}, "integration", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Users.Delete(context.Background(), login, "integration", ""); err != nil {
			t.Error(err)
		}
	})
	parent, _ := ldap.ParseDN(ou.DN)
	child, _ := ldap.ParseDN(user.DN)
	if !parent.AncestorOfFold(child) {
		t.Fatalf("wrong OU: %s", user.DN)
	}
	updated, err := s.Users.Update(ctx, login, UpdateUserInput{Revision: user.Revision, Attributes: map[string]string{"company": "Организация", "l": "Москва", "mobile": "+7 000 0000000"}}, "integration", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(updated.Attributes["l"], "") != "Москва" || strings.Join(updated.Attributes["company"], "") != "Организация" {
		t.Fatalf("attributes not saved: %+v", updated.Attributes)
	}
	users, err := s.Users.List(ctx, ou.DN, "  Иванова  ")
	if err != nil || len(users) != 1 || users[0].SAMAccountName != login {
		t.Fatalf("Cyrillic search: %+v %v", users, err)
	}
	_, err = s.Users.Update(ctx, login, UpdateUserInput{Revision: user.Revision, Attributes: map[string]string{"l": "Другой город"}}, "integration", "")
	if !errors.Is(err, ErrUserConflict) {
		t.Fatalf("stale update allowed: %v", err)
	}
	updated, err = s.Users.Update(ctx, login, UpdateUserInput{Revision: updated.Revision, Attributes: map[string]string{"mobile": ""}}, "integration", "")
	if err != nil || len(updated.Attributes["mobile"]) != 0 {
		t.Fatalf("clear mobile: %+v %v", updated, err)
	}
}
