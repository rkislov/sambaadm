package service

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"os"
	"sambaadm/internal/agent"
	"testing"
	"time"
)

func TestIntegrationHelperSSHAndHTTPS(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("requires two helper nodes")
	}
	s, serverConfig := integrationServices(t, false)
	ctx := context.Background()
	for _, transport := range []string{"https", "ssh"} {
		t.Run(transport, func(t *testing.T) {
			cfg := s.Helpers.Config
			cfg.Nodes = append([]agent.Node(nil), cfg.Nodes...)
			if transport == "ssh" {
				cfg.Nodes[1] = agent.Node{Name: "dc2.sambaadm.test", Transport: "ssh", Endpoint: "root@dc2.sambaadm.test", SSHKey: "/tmp/helper-ssh", KnownHosts: "/tmp/helper-known-hosts"}
			}
			client := &agent.Client{Config: cfg}
			var health map[string]any
			if e := client.Call(ctx, "dc2.sambaadm.test", "health", struct{}{}, &health); e != nil {
				t.Fatal(e)
			}
			if health["node"] != "dc2.sambaadm.test" {
				t.Fatal(health)
			}
			var inventory ControllerInventory
			if e := client.Call(ctx, "dc2.sambaadm.test", "host.inventory", HostOperation{}, &inventory); e != nil || len(inventory.Checks) != 4 || inventory.Checks[0].Status != "ok" {
				t.Fatalf("inventory: %+v %v", inventory, e)
			}
			var auth RODCAuthReport
			if e := client.Call(ctx, "dc2.sambaadm.test", "rodc.auth", struct{ After, Account string }{}, &auth); e != nil {
				t.Fatal(e)
			}
			// Use the browser identity for real SMB through each transport. A
			// deliberately nonexistent identity must fail even though the helper has
			// valid configured credentials: no fallback to the service account.
			scoped := agent.WithCredentials(ctx, func() (agent.Credentials, error) {
				return agent.Credentials{Username: serverConfig.Bind.User, Password: os.Getenv(serverConfig.Bind.PasswordEnv)}, nil
			})
			var scopedFiles []helperFileInfo
			if e := client.Call(scoped, "dc2.sambaadm.test", "sysvol.list", helperFSRequest{Path: `sambaadm.test\Policies`}, &scopedFiles); e != nil {
				t.Fatal("session SYSVOL identity", e)
			}
			rejected := agent.WithCredentials(ctx, func() (agent.Credentials, error) {
				return agent.Credentials{Username: "missing-session-" + uuid.NewString() + "@sambaadm.test", Password: "not-a-real-password"}, nil
			})
			if e := client.Call(rejected, "dc2.sambaadm.test", "sysvol.list", helperFSRequest{Path: `sambaadm.test\Policies`}, &scopedFiles); e == nil {
				t.Fatal("invalid session identity fell back to configured credentials")
			}
			var files []helperFileInfo
			if e := client.Call(ctx, "dc2.sambaadm.test", "sysvol.list", helperFSRequest{Path: `sambaadm.test\Policies`}, &files); e != nil {
				t.Fatal(e)
			}
			var info helperFileInfo
			if e := client.Call(ctx, "dc2.sambaadm.test", "sysvol.stat", helperFSRequest{Path: `sambaadm.test\Policies`}, &info); e != nil || !info.IsDir() {
				t.Fatalf("SYSVOL root: %+v %v", info, e)
			}
			filename := `sambaadm.test\Policies\.sambaadm-helper-test-` + uuid.NewString()
			t.Cleanup(func() {
				client.Call(context.Background(), "dc2.sambaadm.test", "sysvol.remove", helperFSRequest{Path: filename}, nil)
			})
			if e := client.Call(ctx, "dc2.sambaadm.test", "sysvol.open", helperFSRequest{Path: filename, Flags: 1 | 4 | 8, Mode: 0600}, nil); e != nil {
				t.Fatal(e)
			}
			payload := []byte("helper transport check")
			var n int
			if e := client.Call(ctx, "dc2.sambaadm.test", "sysvol.write-at", helperFSRequest{Path: filename, Data: payload}, &n); e != nil || n != len(payload) {
				t.Fatal(n, e)
			}
			if e := client.Call(ctx, "dc2.sambaadm.test", "sysvol.sync", helperFSRequest{Path: filename}, nil); e != nil {
				t.Fatal(e)
			}
			var data []byte
			if e := client.Call(ctx, "dc2.sambaadm.test", "sysvol.read", helperFSRequest{Path: filename}, &data); e != nil || !bytes.Equal(data, payload) {
				t.Fatal(string(data), e)
			}
			var acl []byte
			if e := client.Call(ctx, "dc2.sambaadm.test", "sysvol.get-acl", helperFSRequest{Path: filename, Security: 7}, &acl); e != nil {
				t.Fatal(e)
			}
			if e := client.Call(ctx, "dc2.sambaadm.test", "sysvol.set-acl", helperFSRequest{Path: filename, Security: 7, Data: acl}, nil); e != nil {
				t.Fatal(e)
			}
			if e := client.Call(ctx, "dc2.sambaadm.test", "sysvol.rename", helperFSRequest{Path: filename, To: filename + "-moved"}, nil); e != nil {
				t.Fatal(e)
			}
			filename += "-moved"
		})
	}
}

func TestIntegrationTopologySurvey(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("requires disposable helper domain")
	}
	s, _ := integrationServices(t, false)
	report := s.Sites.AuditTopology(context.Background())
	if report.Status != "complete" || report.Objects == 0 {
		t.Fatalf("audit incomplete: %+v", report)
	}
	for _, f := range report.Findings {
		if f.Code != "site_without_servers" {
			t.Fatalf("unexpected remnant in test domain: %+v", f)
		}
	}
	inventory, e := s.RODC.Inventory(context.Background(), "dc2.sambaadm.test")
	if e != nil || inventory.Controller != "dc2.sambaadm.test" {
		t.Fatalf("inventory: %+v %v", inventory, e)
	}
	auth, e := s.RODC.ControllerAuthentications(context.Background(), "dc2.sambaadm.test", time.Time{}, "")
	if e != nil || auth.Controller != "dc2.sambaadm.test" {
		t.Fatalf("RWDC audit: %+v %v", auth, e)
	}
}

func TestIntegrationCleanupPreparation(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_HELPERS") != "1" {
		t.Skip("requires disposable two-DC helper domain")
	}
	s, cfg := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	site, e := s.Sites.Create(ctx, "Cleanup-Preview-Test", "test", "")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Sites.Delete(context.Background(), "Cleanup-Preview-Test", "test", "") })
	if e = s.Repl.Sync(ctx, "dc2.sambaadm.test", "dc1.sambaadm.test", ConfigDN(cfg.BaseDN), "test", ""); e != nil {
		t.Fatal(e)
	}
	p, e := s.Sites.PreviewCleanup(ctx, []string{site.DN})
	if e != nil {
		t.Fatal(e)
	}
	report, e := s.Sites.CheckCleanup(ctx, CleanupChecksRequest{CleanupRequest: CleanupRequest{DNs: []string{site.DN}, Revision: p.Revision}, Peer: "dc2.sambaadm.test"})
	if e != nil {
		t.Fatal(e)
	}
	matched := false
	for _, check := range report.Checks {
		if check.ID == "peer" {
			matched = check.Status == "ok"
		}
	}
	if !matched || report.CanApply {
		t.Fatalf("peer mismatch or unsafe apply: %+v", report)
	}
	receipt, e := s.Sites.ArchiveCleanup(ctx, CleanupRequest{DNs: []string{site.DN}, Revision: p.Revision}, "test", "")
	if e != nil || !receipt.Verified {
		t.Fatal(receipt, e)
	}
	same, e := s.Sites.CheckCleanup(ctx, CleanupChecksRequest{CleanupRequest: CleanupRequest{DNs: []string{site.DN}, Revision: p.Revision}, Peer: "dc1.sambaadm.test"})
	if e != nil {
		t.Fatal(e)
	}
	blocked := false
	for _, check := range same.Checks {
		if check.ID == "peer" {
			blocked = check.Status == "blocked"
		}
	}
	if !blocked {
		t.Fatal("same DC counted as independent peer")
	}
}
