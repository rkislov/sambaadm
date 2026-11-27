package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"sambaadm/internal/config"
)

// Exercise real DHCP -> D2 -> signed BIND updates. Only inside a disposable ALT container.
func TestKeaRealDDNS(t *testing.T) {
	if os.Getenv("SAMBAADM_KEA_REAL_TEST") != "1" {
		t.Skip("requires disposable ALT container with Kea, hooks and BIND")
	}
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Helper.Kea4Config = filepath.Join(dir, "kea4.conf")
	cfg.Helper.Kea6Config = filepath.Join(dir, "kea6.conf")
	cfg.Helper.KeaDDNSConfig = filepath.Join(dir, "d2.conf")
	if e := os.MkdirAll("/run/kea", 0755); e != nil {
		t.Fatal(e)
	}
	sockets := map[string]string{}
	for _, family := range []string{"4", "6"} {
		h, e := newKeaHost(cfg, family)
		if e != nil {
			t.Fatal(e)
		}
		socket := fmt.Sprintf("/run/kea/ddns-test-%d-%s.sock", os.Getpid(), family)
		sockets[family] = socket
		service := map[string]any{"interfaces-config": map[string]any{"interfaces": []string{}}, "valid-lifetime": 3600, "lease-database": map[string]any{"type": "memfile", "persist": false}, "control-socket": map[string]any{"socket-type": "unix", "socket-name": socket}, "hooks-libraries": []any{map[string]any{"library": h.hooks()["libdhcp_lease_cmds.so"]}}, "subnet" + family: []any{map[string]any{"id": 1, "subnet": map[string]string{"4": "10.0.0.0/24", "6": "2001:db8::/64"}[family]}}}
		raw, _ := json.Marshal(map[string]any{"Dhcp" + family: service})
		if e = os.WriteFile(h.path, raw, 0640); e != nil {
			t.Fatal(e)
		}
	}
	h, _ := newKeaHost(cfg, "4")
	zones4, _ := keaReverseZones("10.0.0.0/24")
	zones6, _ := keaReverseZones("2001:db8::/64")
	settings := &KeaDDNSSettings{ForwardZone: "clients.example.test.", ReverseZones: append(zones4, zones6...), DNSAddress: "127.0.0.1", DNSPort: 15353, NCRPort: 15301, Auth: "tsig", KeyName: "sambaadm-kea.", Secret: base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")), OverrideClient: true}
	_, candidates, e := h.ddnsPlan(context.Background(), KeaRequest{DDNS: settings})
	if e != nil {
		t.Fatal(e)
	}
	for _, candidate := range candidates {
		if e = os.WriteFile(candidate.host.path, []byte(candidate.plan.Proposed), 0640); e != nil {
			t.Fatal(e)
		}
	}
	namedConfig := fmt.Sprintf(`options { directory %q; listen-on port 15353 { 127.0.0.1; }; listen-on-v6 { none; }; recursion no; dnssec-validation no; pid-file %q; session-keyfile %q; }; key "sambaadm-kea." { algorithm hmac-sha256; secret %q; };`, dir, filepath.Join(dir, "named.pid"), filepath.Join(dir, "session.key"), settings.Secret)
	for i, zone := range append([]string{settings.ForwardZone}, settings.ReverseZones...) {
		path := filepath.Join(dir, fmt.Sprintf("zone%d", i))
		content := fmt.Sprintf("$ORIGIN %s\n$TTL 60\n@ IN SOA ns.clients.example.test. hostmaster.clients.example.test. (1 60 60 3600 60)\n@ IN NS ns.clients.example.test.\n", zone)
		if i == 0 {
			content += "ns IN A 127.0.0.1\n"
		}
		if e = os.WriteFile(path, []byte(content), 0600); e != nil {
			t.Fatal(e)
		}
		namedConfig += fmt.Sprintf("\nzone %q { type primary; file %q; allow-update { key \"sambaadm-kea.\"; }; };", zone, path)
	}
	namedPath := filepath.Join(dir, "named.conf")
	os.WriteFile(namedPath, []byte(namedConfig), 0600)
	start := func(name string, args ...string) {
		t.Helper()
		binary, e := exec.LookPath(name)
		if e != nil {
			t.Fatal(e)
		}
		log, e := os.Create(filepath.Join(dir, name+".log"))
		if e != nil {
			t.Fatal(e)
		}
		cmd := exec.Command(binary, args...)
		cmd.Env = append(os.Environ(), "KEA_PIDFILE_DIR="+dir, "KEA_LOCKFILE_DIR="+dir)
		cmd.Stdout = log
		cmd.Stderr = log
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			cmd.Process.Signal(os.Interrupt)
			cmd.Wait()
			log.Close()
			if t.Failed() {
				data, _ := os.ReadFile(log.Name())
				t.Logf("%s: %s", name, data)
			}
		})
	}
	start("named", "-g", "-t", "/", "-u", "root", "-c", namedPath)
	query := func(name string, qtype uint16) (*dns.Msg, error) {
		message := new(dns.Msg)
		message.SetQuestion(name, qtype)
		client := dns.Client{Timeout: 300 * time.Millisecond}
		out, _, e := client.Exchange(message, "127.0.0.1:15353")
		return out, e
	}
	wait := func(description string, check func() bool) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			time.Sleep(30 * time.Millisecond)
		}
		t.Fatal("timeout: " + description)
	}
	wait("BIND ready", func() bool {
		answer, e := query(settings.ForwardZone, dns.TypeSOA)
		return e == nil && answer.Rcode == dns.RcodeSuccess
	})
	for _, candidate := range candidates {
		if candidate.host.binary != "" {
			start(candidate.host.binary, "-d", "-c", candidate.host.path)
		}
	}
	for _, socket := range sockets {
		socket := socket
		wait("control socket", func() bool { _, e := os.Stat(socket); return e == nil })
	}
	// D2 has no test control socket: allow the independent UDP receiver to finish initialization.
	time.Sleep(150 * time.Millisecond)
	command := func(family, name string, args any) keaCommandResponse {
		t.Helper()
		conn, e := net.DialTimeout("unix", sockets[family], time.Second)
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		json.NewEncoder(conn).Encode(map[string]any{"command": name, "arguments": args})
		var out keaCommandResponse
		if e = json.NewDecoder(conn).Decode(&out); e != nil {
			t.Fatal(e)
		}
		if out.Result != 0 {
			t.Fatalf("%s: %#v", name, out)
		}
		return out
	}
	for _, family := range []string{"4", "6"} {
		family := family
		t.Run("IPv"+family, func(t *testing.T) {
			address := map[string]string{"4": "10.0.0.20", "6": "2001:db8::20"}[family]
			hostname := "client" + family + ".clients.example.test."
			lease := map[string]any{"ip-address": address, "subnet-id": 1, "hw-address": "00:11:22:33:44:55", "valid-lft": 3600, "cltt": time.Now().Unix(), "hostname": hostname, "fqdn-fwd": true, "fqdn-rev": true}
			if family == "6" {
				lease["type"] = "IA_NA"
				lease["duid"] = "00:03:00:01:00:11:22:33:44:55"
				lease["iaid"] = 7
				lease["preferred-lft"] = 1800
			}
			command(family, "lease"+family+"-add", lease)
			command(family, "lease"+family+"-resend-ddns", map[string]any{"ip-address": address})
			recordType := uint16(dns.TypeA)
			if family == "6" {
				recordType = dns.TypeAAAA
			}
			reverse, _ := dns.ReverseAddr(address)
			wait("forward update", func() bool {
				out, e := query(hostname, recordType)
				if e != nil {
					return false
				}
				for _, rr := range out.Answer {
					if rr.Header().Rrtype == recordType && strings.Contains(rr.String(), address) {
						return true
					}
				}
				return false
			})
			wait("reverse update", func() bool {
				out, e := query(reverse, dns.TypePTR)
				return e == nil && len(out.Answer) > 0 && strings.Contains(out.Answer[0].String(), hostname)
			})
			host, _ := newKeaHost(cfg, family)
			page, e := host.leases(context.Background(), KeaRequest{SubnetID: 1})
			if e != nil || len(page.Leases) != 1 {
				t.Fatalf("leases: %#v %v", page, e)
			}
			l := page.Leases[0]
			if _, e = host.deleteLease(context.Background(), KeaRequest{Lease: &KeaLeaseRef{Address: l.Address, Type: l.Type, SubnetID: l.SubnetID, Revision: l.Revision}, Confirm: true, UpdateDDNS: true}); e != nil {
				t.Fatal(e)
			}
			wait("forward removal", func() bool { out, e := query(hostname, recordType); return e == nil && len(out.Answer) == 0 })
			wait("reverse removal", func() bool { out, e := query(reverse, dns.TypePTR); return e == nil && len(out.Answer) == 0 })
		})
	}
}
