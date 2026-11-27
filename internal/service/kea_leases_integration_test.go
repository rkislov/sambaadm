package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sambaadm/internal/config"
	"testing"
	"time"
)

// This test uses a real isolated daemon, including the installed lease command hook.
// Run only inside a disposable ALT container, with SAMBAADM_KEA_REAL_TEST=1.
func TestKeaRealLeaseControl(t *testing.T) {
	if os.Getenv("SAMBAADM_KEA_REAL_TEST") != "1" {
		t.Skip("requires disposable ALT container with Kea")
	}
	if e := os.MkdirAll("/run/kea", 0750); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"4", "6", "PD"} {
		t.Run(kind, func(t *testing.T) {
			family := kind
			if kind == "PD" {
				family = "6"
			}
			dir := t.TempDir()
			cfg := &config.Config{}
			cfg.Helper.Node = "test-kea"
			path := filepath.Join(dir, "kea.conf")
			if family == "4" {
				cfg.Helper.Kea4Config = path
			} else {
				cfg.Helper.Kea6Config = path
			}
			h, e := newKeaHost(cfg, family)
			if e != nil {
				t.Fatal(e)
			}
			library := h.hooks()["libdhcp_lease_cmds.so"]
			if library == "" {
				t.Fatal("missing lease command hook")
			}
			socket := fmt.Sprintf("/run/kea/sambaadm-test-%d-%s.sock", os.Getpid(), family)
			service := map[string]any{"interfaces-config": map[string]any{"interfaces": []string{}}, "valid-lifetime": 3600, "lease-database": map[string]any{"type": "memfile", "persist": false}, "control-socket": map[string]any{"socket-type": "unix", "socket-name": socket}, "hooks-libraries": []any{map[string]any{"library": library}}, "subnet" + family: []any{map[string]any{"id": 1, "subnet": map[string]string{"4": "10.0.0.0/24", "6": "2001:db8::/64"}[family]}}}
			raw, _ := json.Marshal(map[string]any{"Dhcp" + family: service})
			if e = os.WriteFile(path, raw, 0640); e != nil {
				t.Fatal(e)
			}
			log, e := os.Create(filepath.Join(dir, "daemon.log"))
			if e != nil {
				t.Fatal(e)
			}
			defer log.Close()
			cmd := exec.Command(h.binary, "-d", "-c", path)
			cmd.Env = append(os.Environ(), "KEA_PIDFILE_DIR="+dir, "KEA_LOCKFILE_DIR="+dir)
			cmd.Stdout = log
			cmd.Stderr = log
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() {
				cmd.Process.Signal(os.Interrupt)
				cmd.Wait()
				if t.Failed() {
					log.Sync()
					data, _ := os.ReadFile(log.Name())
					t.Log(string(data))
				}
			}()
			deadline := time.Now().Add(8 * time.Second)
			for {
				if _, e = os.Stat(socket); e == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("control socket not created")
				}
				time.Sleep(20 * time.Millisecond)
			}
			health := h.dhcpHealth(context.Background(), true)
			if health.Source != "runtime" || !health.Standalone {
				t.Fatalf("running unclustered Kea not recognized: %+v", health)
			}
			command := func(name string, args any) keaCommandResponse {
				t.Helper()
				conn, e := net.DialTimeout("unix", socket, time.Second)
				if e != nil {
					t.Fatal(e)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if e = json.NewEncoder(conn).Encode(map[string]any{"command": name, "arguments": args}); e != nil {
					t.Fatal(e)
				}
				var response keaCommandResponse
				if e = json.NewDecoder(conn).Decode(&response); e != nil {
					t.Fatal(e)
				}
				return response
			}
			address := map[string]string{"4": "10.0.0.10", "6": "2001:db8::10"}[family]
			lease := map[string]any{"ip-address": address, "subnet-id": 1, "hw-address": "00:11:22:33:44:55", "valid-lft": 3600, "cltt": time.Now().Unix(), "hostname": "client.example.test"}
			if family == "6" {
				lease["duid"] = "00:03:00:01:00:11:22:33:44:55"
				lease["iaid"] = 7
				lease["type"] = "IA_NA"
				lease["preferred-lft"] = 1800
			}
			if kind == "PD" {
				address = "2001:db8:10::"
				lease["ip-address"] = address
				lease["type"] = "IA_PD"
				lease["prefix-len"] = 64
			}
			if out := command("lease"+family+"-add", lease); out.Result != 0 {
				t.Fatalf("add failed: %#v", out)
			}
			page, e := h.leases(context.Background(), KeaRequest{SubnetID: 1})
			if e != nil {
				t.Fatal(e)
			}
			if len(page.Leases) != 1 || page.Leases[0].Address != address {
				t.Fatalf("wrong page: %#v", page)
			}
			l := page.Leases[0]
			ref := &KeaLeaseRef{Address: l.Address, Type: l.Type, SubnetID: l.SubnetID, Revision: l.Revision}
			before, _ := os.ReadFile(path)
			plan, e := h.reserveLeasePlan(context.Background(), KeaRequest{Revision: configRevision(before), Lease: ref})
			if e != nil {
				t.Fatal(e)
			}
			if plan.Proposed == string(before) {
				t.Fatal("reservation not added")
			}
			if _, e = h.deleteLease(context.Background(), KeaRequest{Lease: ref, Confirm: true}); e != nil {
				t.Fatal(e)
			}
			page, e = h.leases(context.Background(), KeaRequest{SubnetID: 1})
			if e != nil || len(page.Leases) != 0 {
				t.Fatalf("lease not deleted: %#v %v", page, e)
			}
		})
	}
}
