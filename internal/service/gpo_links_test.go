package service

import (
	"context"
	"fmt"
	smb2 "github.com/cloudsoda/go-smb2"
	"os"
	"path/filepath"
	ldapproto "sambaadm/internal/ldap"
	"strings"
	"testing"
	"time"
)

func TestEditGPLinkPreservesOptionsAndOrder(t *testing.T) {
	target := "CN={A},CN=Policies,DC=test"
	other := "[LDAP://CN={B},CN=Policies,DC=test;3]"
	raw := other + "[LDAP://" + target + ";2]"
	got, err := editGPLink(raw, target, false)
	if err != nil || got != raw {
		t.Fatalf("existing link changed: %q %v", got, err)
	}
	got, err = editGPLink(raw, target, true)
	if err != nil || got != other {
		t.Fatalf("unlink: %q %v", got, err)
	}
	for _, bad := range []string{"[;0]", "[LDAP://x;bad]", "[LDAP://CN=x;0", "garbage"} {
		if _, err := editGPLink(bad, target, false); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestIntegrationNativeGPOLinks(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx := context.Background()
	policies, err := s.GPO.List(ctx)
	if err != nil || len(policies) == 0 {
		t.Fatalf("policies: %v", err)
	}
	guid := policies[0].GUID
	if detail, err := s.GPO.Show(ctx, guid); err != nil || !strings.Contains(detail, "gPCFileSysPath") {
		t.Fatalf("details: %s %v", detail, err)
	}
	ou, err := s.OU.Create(ctx, CreateOUInput{Name: fmt.Sprintf("NativeLinks-%d", time.Now().UnixNano())}, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.OU.Delete(ctx, ou.DN, "test", "")
	if err := s.GPO.Link(ctx, ou.DN, guid, "test", ""); err != nil {
		t.Fatal(err)
	}
	links, err := s.GPO.GetLinks(ctx, ou.DN)
	if err != nil || !strings.Contains(strings.ToLower(links), strings.ToLower(guid)) {
		t.Fatalf("links: %s %v", links, err)
	}
	if err := s.GPO.Unlink(ctx, ou.DN, guid, "test", ""); err != nil {
		t.Fatal(err)
	}
	links, err = s.GPO.GetLinks(ctx, ou.DN)
	if err != nil || links != "" {
		t.Fatalf("remaining: %s %v", links, err)
	}
}

func TestIntegrationNativeGPOCreate(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx := context.Background()
	name := fmt.Sprintf("Native-%d", time.Now().UnixNano())
	out, err := s.GPO.Create(ctx, name, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(out)
	t.Cleanup(func() {
		if err := s.GPO.Delete(ctx, name, "test", ""); err != nil {
			t.Error(err)
		}
	})
	if _, err := s.GPO.Show(ctx, name); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationNativeGPOBackupRestore(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx := context.Background()
	name := fmt.Sprintf("Backup-%d", time.Now().UnixNano())
	if _, err := s.GPO.Create(ctx, name, "test", ""); err != nil {
		t.Fatal(err)
	}
	defer s.GPO.Delete(ctx, name, "test", "")
	guid, err := s.GPO.resolveGUID(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	if err := s.GPO.Backup(ctx, name, path, "test", ""); err != nil {
		t.Fatal(err)
	}
	copyName := name + "-restored"
	if err := s.GPO.Restore(ctx, copyName, filepath.Join(path, "policy", braceGUID(guid)), "test", ""); err != nil {
		t.Fatal(err)
	}
	defer s.GPO.Delete(ctx, copyName, "test", "")
	if _, err := s.GPO.Show(ctx, copyName); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationNativeDomainRead(t *testing.T) {
	s, _ := integrationServices(t, false)
	ctx := context.Background()
	roles, err := s.Domain.FSMOShow(ctx)
	if err != nil || len(roles) < 5 {
		t.Fatalf("roles: %v %v", roles, err)
	}
	level, err := s.Domain.LevelShow(ctx)
	if err != nil || level.Domain == "" || level.Forest == "" {
		t.Fatalf("level: %+v %v", level, err)
	}
}

func TestIntegrationNativeDistribution(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_SECOND_DC") == "" {
		t.Skip("two controllers required")
	}
	s, _ := integrationServices(t, true)
	ctx := context.Background()
	name := fmt.Sprintf("Distribute-%d", time.Now().UnixNano())
	if _, err := s.GPO.Create(ctx, name, "test", ""); err != nil {
		t.Fatal(err)
	}
	defer s.GPO.Delete(ctx, name, "test", "")
	job, err := s.GPO.StartDistribute(ctx, name, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		current, _ := s.GPO.GetDistributeJob(job.ID)
		if current.Status == JobFailed {
			t.Fatalf("distribution: %s (%+v)", current.Error, current.Steps)
		}
		if current.Status == JobOK {
			remote := *s.GPO.remote
			remote.Host = os.Getenv("SAMBAADM_IT_SECOND_DC")
			err := remote.SYSVOL(ctx, 445, func(share *smb2.Share) error {
				data, e := share.ReadFile("sambaadm.test\\Policies\\" + braceGUID(job.GUID) + "\\GPT.INI")
				if e != nil {
					return e
				}
				if !strings.Contains(string(data), "Version=0") {
					return fmt.Errorf("invalid GPT.INI: %q", data)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("distribution timed out")
}

func TestIntegrationNativeTrust(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx := context.Background()
	domain := "service-synthetic.invalid"
	err := s.Trusts.Create(ctx, CreateTrustInput{Domain: domain, NetBIOS: "SYNTHSERVICE", SID: "S-1-5-21-1900000011-1900000012-1900000013", Password: "Synthetic-Only-Pass1!", Direction: "both", Type: "external"}, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Trusts.Delete(ctx, domain, "test", ""); err != nil {
			t.Error(err)
		}
	})
	if _, err := s.Trusts.Show(ctx, domain); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trusts.Validate(ctx, domain, "test", ""); err == nil {
		t.Fatal("nonexistent remote domain reported valid")
	}
}

func TestIntegrationNativeFSMOTransfer(t *testing.T) {
	host := os.Getenv("SAMBAADM_IT_SECOND_DC")
	if host == "" {
		t.Skip("two controllers required")
	}
	s, _ := integrationServices(t, true)
	ctx := context.Background()
	client := s.Domain.ldap.ServicePeer("ldaps://" + host + ":636")
	defer client.Close()
	other := NewWithOptions(client, s.Audit, ServiceOptions{Username: os.Getenv("SAMBAADM_IT_USER"), Password: func() string { return os.Getenv("SAMBAADM_PASSWORD") }})
	for _, role := range []string{"pdc", "domaindns", "forestdns"} {
		if err := other.Domain.FSMOTransfer(ctx, role, "test", ""); err != nil {
			t.Fatalf("transfer %s to DC2: %v", role, err)
		}
		nc := s.Domain.ldap.BaseDN()
		if role == "domaindns" {
			nc = "DC=DomainDnsZones," + nc
		}
		if role == "forestdns" {
			nc = "DC=ForestDnsZones," + nc
		}
		if err := s.Repl.Sync(ctx, "dc1.sambaadm.test", host, nc, "test", ""); err != nil {
			t.Fatal(err)
		}
		dn, _ := s.Domain.roleDN(role)
		entry, err := s.Domain.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"fSMORoleOwner"}})
		if err != nil || !strings.Contains(strings.ToLower(entry.GetAttributeValue("fSMORoleOwner")), "cn=dc2,") {
			t.Fatalf("owner %s: %v %v", role, entry, err)
		}
		if err := s.Domain.FSMOTransfer(ctx, role, "test", ""); err != nil {
			t.Fatalf("restore %s: %v", role, err)
		}
	}
}
