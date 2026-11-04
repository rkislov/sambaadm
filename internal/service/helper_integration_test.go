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
	s, _ := integrationServices(t, false)
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
