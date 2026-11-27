package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type keaTestCommand struct {
	Command   string         `json:"command"`
	Arguments map[string]any `json:"arguments"`
}

func testKeaControl(t *testing.T, family string, respond func(keaTestCommand) any) (*keaHost, <-chan keaTestCommand) {
	t.Helper()
	dir, e := os.MkdirTemp("", "kl-")
	if e != nil {
		t.Fatal(e)
	}
	// Keep AF_UNIX paths below Linux's 108-byte limit, also on macOS test hosts.
	if len(dir) > 65 {
		os.Remove(dir)
		dir, e = os.MkdirTemp("/tmp", "kl-")
		if e != nil {
			t.Fatal(e)
		}
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "control.sock")
	listener, e := net.Listen("unix", path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { listener.Close() })
	commands := make(chan keaTestCommand, 32)
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				var request keaTestCommand
				if json.NewDecoder(conn).Decode(&request) != nil {
					return
				}
				commands <- request
				json.NewEncoder(conn).Encode(respond(request))
			}()
		}
	}()
	h := testKeaHost(t)
	h.family = family
	h.binary = "kea-dhcp" + family
	doc := map[string]any{"Dhcp" + family: map[string]any{"control-socket": map[string]any{"socket-type": "unix", "socket-name": path}, "subnet" + family: []any{map[string]any{"id": 1, "subnet": map[string]string{"4": "10.0.0.0/24", "6": "2001:db8::/64"}[family], "user-context": map[string]any{"custom": "retained"}}}, "user-context": map[string]any{"custom": "retained"}}}
	raw, _ := json.Marshal(doc)
	if e = os.WriteFile(h.path, raw, 0640); e != nil {
		t.Fatal(e)
	}
	return h, commands
}
func testKeaLeaseRaw(family string) json.RawMessage {
	lease := map[string]any{"ip-address": "10.0.0.10", "subnet-id": 1, "hw-address": "00:11:22:33:44:55", "client-id": "01:00:11:22:33:44:55", "cltt": time.Now().Unix(), "valid-lft": 3600, "state": 0, "hostname": "client.example.test", "user-context": map[string]any{"vendor": "retained"}}
	if family == "6" {
		lease["ip-address"] = "2001:db8::10"
		lease["type"] = "IA_NA"
		lease["duid"] = "00:03:00:01:00:11:22:33:44:55"
		lease["iaid"] = 7
	}
	raw, _ := json.Marshal(lease)
	return raw
}
func refForKeaLease(t *testing.T, raw json.RawMessage) *KeaLeaseRef {
	t.Helper()
	lease, e := decodeKeaLease(raw)
	if e != nil {
		t.Fatal(e)
	}
	return &KeaLeaseRef{Address: lease.Address, Type: lease.Type, SubnetID: lease.SubnetID, Revision: lease.Revision}
}
func TestKeaLeasesPagingFiltersActiveBySubnet(t *testing.T) {
	records := make([]map[string]any, keaLeasePageSize)
	now := time.Now().Unix()
	for i := range records {
		records[i] = map[string]any{"ip-address": fmt.Sprintf("10.0.%d.%d", i/256, i%256), "subnet-id": 1, "cltt": now, "valid-lft": 3600, "state": 0}
	}
	records[6]["hostname"] = "MiXeD-Client"
	records[0]["valid-lft"] = 0
	records[1]["cltt"] = now - 7200
	records[2]["state"] = 1
	records[3]["state"] = 2
	records[4]["subnet-id"] = 2
	records[5]["valid-lft"] = uint32(0xffffffff)
	h, commands := testKeaControl(t, "4", func(request keaTestCommand) any {
		return map[string]any{"result": 0, "arguments": map[string]any{"leases": records}}
	})
	page, e := h.leases(context.Background(), KeaRequest{SubnetID: 1})
	if e != nil {
		t.Fatal(e)
	}
	if len(page.Leases) != 251 || page.Next != "10.0.0.255" || page.Scanned != 256 || !page.Leases[0].Infinite {
		t.Fatalf("wrong page: %#v", page)
	}
	command := <-commands
	if command.Command != "lease4-get-page" || command.Arguments["from"] != "start" || command.Arguments["limit"] != float64(256) {
		t.Fatalf("wrong command %#v", command)
	}
	searched, e := h.leases(context.Background(), KeaRequest{SubnetID: 1, Search: "mixed-client"})
	if e != nil || len(searched.Leases) != 1 || searched.Leases[0].Address != "10.0.0.6" || searched.Next == "" {
		t.Fatalf("search: %#v %v", searched, e)
	}
	empty, e := h.leases(context.Background(), KeaRequest{SubnetID: 1, Search: "not-present"})
	if e != nil || len(empty.Leases) != 0 || empty.Next == "" {
		t.Fatalf("search lost cursor: %#v %v", empty, e)
	}
	if _, e = h.leases(context.Background(), KeaRequest{From: "::"}); e == nil {
		t.Fatal("accepted wrong-family cursor")
	}
}
func TestKeaLeaseDeleteRequiresConfirmationAndExactSnapshot(t *testing.T) {
	for _, family := range []string{"4", "6"} {
		t.Run(family, func(t *testing.T) {
			raw := testKeaLeaseRaw(family)
			h, commands := testKeaControl(t, family, func(request keaTestCommand) any {
				if strings.HasSuffix(request.Command, "-get") {
					return []any{map[string]any{"result": 0, "arguments": raw}}
				}
				return map[string]any{"result": 0, "text": "deleted"}
			})
			req := KeaRequest{Lease: refForKeaLease(t, raw)}
			if _, e := h.deleteLease(context.Background(), req); e == nil {
				t.Fatal("unconfirmed deletion")
			}
			if len(commands) != 0 {
				t.Fatal("unconfirmed command sent")
			}
			req.Confirm = true
			req.Lease.Revision = "stale"
			if _, e := h.deleteLease(context.Background(), req); e == nil {
				t.Fatal("stale snapshot deleted")
			}
			if (<-commands).Command != "lease"+family+"-get" || len(commands) != 0 {
				t.Fatal("delete sent on stale snapshot")
			}
			req.Lease = refForKeaLease(t, raw)
			req.UpdateDDNS = true
			if _, e := h.deleteLease(context.Background(), req); e != nil {
				t.Fatal(e)
			}
			<-commands
			command := <-commands
			if command.Command != "lease"+family+"-del" || command.Arguments["update-ddns"] != true || command.Arguments["subnet-id"] != float64(1) {
				t.Fatalf("wrong delete %#v", command)
			}
			if family == "6" && command.Arguments["type"] != "IA_NA" {
				t.Fatal("IPv6 type lost")
			}
		})
	}
}
func TestKeaReserveLeasePlansIPv4IPv6AndPrefix(t *testing.T) {
	for _, kind := range []string{"4", "6", "PD"} {
		t.Run(kind, func(t *testing.T) {
			family := kind
			if kind == "PD" {
				family = "6"
			}
			raw := testKeaLeaseRaw(family)
			if kind == "PD" {
				var v map[string]any
				json.Unmarshal(raw, &v)
				v["type"] = "IA_PD"
				v["ip-address"] = "2001:db8:10::"
				v["prefix-len"] = 64
				raw, _ = json.Marshal(v)
			}
			h, _ := testKeaControl(t, family, func(request keaTestCommand) any {
				return map[string]any{"result": 0, "arguments": map[string]any{"leases": []json.RawMessage{raw}}}
			})
			before, _ := os.ReadFile(h.path)
			before = []byte(strings.Replace(string(before), `"custom":"retained"`, `"custom":"retained","large-id":9007199254740993`, 1))
			if e := os.WriteFile(h.path, before, 0640); e != nil {
				t.Fatal(e)
			}
			hostname := "reserved.example.test"
			req := KeaRequest{Revision: configRevision(before), Lease: refForKeaLease(t, raw), ReservationHostname: &hostname}
			plan, e := h.reserveLeasePlan(context.Background(), req)
			if e != nil {
				t.Fatal(e)
			}
			_, root, e := keaRoot([]byte(plan.Proposed), family)
			if e != nil {
				t.Fatal(e)
			}
			sub := findKeaSubnet(root, family, 1)
			reservation := sub["reservations"].([]any)[0].(map[string]any)
			if reservation["hostname"] != hostname || (!strings.Contains(plan.Proposed, "retained") || !strings.Contains(plan.Proposed, "9007199254740993")) {
				t.Fatal("metadata lost")
			}
			switch kind {
			case "4":
				if reservation["hw-address"] != "00:11:22:33:44:55" || reservation["ip-address"] != "10.0.0.10" {
					t.Fatalf("wrong v4 %#v", reservation)
				}
			case "6":
				if reservation["duid"] == nil || reservation["ip-addresses"] == nil {
					t.Fatalf("wrong v6 %#v", reservation)
				}
			case "PD":
				if reservation["prefixes"].([]any)[0] != "2001:db8:10::/64" {
					t.Fatalf("wrong prefix %#v", reservation)
				}
			}
			after, _ := os.ReadFile(h.path)
			if string(after) != string(before) {
				t.Fatal("preview changed file")
			}
			if e = os.WriteFile(h.path, []byte(plan.Proposed), 0640); e != nil {
				t.Fatal(e)
			}
			req.Revision = plan.ProposedRevision
			if _, e = h.reserveLeasePlan(context.Background(), req); e == nil || !strings.Contains(e.Error(), "уже существует") {
				t.Fatalf("duplicate accepted: %v", e)
			}
		})
	}
}
func TestKeaControlRejectsUnsupportedAndMalformedReplies(t *testing.T) {
	for _, response := range []any{map[string]any{"result": 2, "text": "unsupported"}, map[string]any{"text": "missing result"}, []any{map[string]any{"result": 0}, map[string]any{"result": 0}}} {
		h, _ := testKeaControl(t, "4", func(keaTestCommand) any { return response })
		if _, e := h.leases(context.Background(), KeaRequest{}); e == nil {
			t.Fatalf("accepted %#v", response)
		}
	}
	h, commands := testKeaControl(t, "4", func(keaTestCommand) any { return nil })
	if _, e := h.leaseCommand(context.Background(), "shutdown", nil); e == nil || len(commands) != 0 {
		t.Fatal("arbitrary command accepted")
	}
}
