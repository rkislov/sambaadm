package service

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sambaadm/internal/config"
	"strings"
	"testing"
)

func testKeaDDNS(t *testing.T) (*keaHost, KeaRequest) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Helper.Kea4Config = filepath.Join(dir, "kea4.conf")
	cfg.Helper.Kea6Config = filepath.Join(dir, "kea6.conf")
	cfg.Helper.KeaDDNSConfig = filepath.Join(dir, "kea-ddns.conf")
	configs := map[string]string{cfg.Helper.Kea4Config: `{"Dhcp4":{"valid-lifetime":3600,"subnet4":[{"id":1,"subnet":"10.0.0.0/24","ddns-send-updates":false}],"user-context":{"custom":9007199254740993}}}`, cfg.Helper.Kea6Config: `{"Dhcp6":{"valid-lifetime":3600,"subnet6":[{"id":2,"subnet":"2001:db8::/64"}]}}`, cfg.Helper.KeaDDNSConfig: `{"DhcpDdns":{"user-context":{"custom":"retained"},"forward-ddns":{"ddns-domains":[{"name":"old.example.","dns-servers":[{"ip-address":"192.0.2.200"}]}]}}}`}
	for path, text := range configs {
		if e := os.WriteFile(path, []byte(text), 0644); e != nil {
			t.Fatal(e)
		}
	}
	h, e := configuredKeaHost(cfg, "4")
	if e != nil {
		t.Fatal(e)
	}
	h.run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "systemctl" {
			if args[0] == "is-active" {
				if args[1] == "kea-dhcp4.service" {
					return "active", nil
				}
				return "inactive", errors.New("inactive")
			}
			if args[0] == "is-enabled" {
				return "disabled", errors.New("disabled")
			}
		}
		return "configuration OK", nil
	}
	req := KeaRequest{DDNS: &KeaDDNSSettings{ForwardZone: "clients.example.test", ReverseZones: []string{"0.0.10.in-addr.arpa.", "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."}, DNSAddress: "192.0.2.53", DNSPort: 53, NCRPort: 53001, Auth: "tsig", KeyName: "kea-key.", Secret: base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012")), OverrideClient: true}, Confirm: true}
	return h, req
}
func TestKeaDDNSReverseZoneHints(t *testing.T) {
	for _, test := range []struct {
		cidr  string
		count int
		first string
	}{{"10.0.4.0/23", 2, "4.0.10.in-addr.arpa."}, {"10.0.4.128/25", 1, "4.0.10.in-addr.arpa."}, {"192.0.2.9/32", 1, "2.0.192.in-addr.arpa."}, {"2001:db8::/64", 1, "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."}, {"2001:db8::/57", 8, "0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."}} {
		got, e := keaReverseZones(test.cidr)
		if e != nil || len(got) != test.count || got[0] != test.first {
			t.Fatalf("%s: %v %v", test.cidr, got, e)
		}
	}
}
func TestKeaDDNSPlanCoversBothProtocolsAndRedactsSecrets(t *testing.T) {
	h, req := testKeaDDNS(t)
	original, _ := os.ReadFile(h.cfg.Helper.KeaDDNSConfig)
	plan, files, e := h.ddnsPlan(context.Background(), req)
	if e != nil {
		t.Fatal(e)
	}
	if len(files) != 4 || len(plan.Files) != 4 {
		t.Fatal("missing file")
	}
	if strings.Contains(plan.Files[0].Proposed, req.DDNS.Secret) || !strings.Contains(plan.Files[0].Proposed, "[скрыто]") || !strings.Contains(plan.DNSInstructions, req.DDNS.Secret) {
		t.Fatal("incorrect secret handling")
	}
	if !strings.Contains(plan.Files[1].Proposed, "old.example.") || !strings.Contains(plan.Files[1].Proposed, "retained") {
		t.Fatal("other D2 configuration lost")
	}
	for _, file := range files[2:] {
		_, root, e := keaRoot([]byte(file.plan.Proposed), file.host.family)
		if e != nil {
			t.Fatal(e)
		}
		conn := root["dhcp-ddns"].(map[string]any)
		if conn["enable-updates"] != true || conn["server-ip"] != "127.0.0.1" || root["ddns-qualifying-suffix"] != "clients.example.test" {
			t.Fatal("incorrect DHCP config")
		}
		for _, subnet := range keaSubnets(root, file.host.family) {
			if subnet["ddns-send-updates"] != true {
				t.Fatal("subnet override still disables DDNS")
			}
		}
	}
	if !strings.Contains(plan.Files[2].Proposed, "9007199254740993") {
		t.Fatal("numeric metadata changed")
	}
	after, _ := os.ReadFile(h.cfg.Helper.KeaDDNSConfig)
	if string(original) != string(after) {
		t.Fatal("preview changed file")
	}
}
func TestKeaDDNSApplyAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[fail], func(t *testing.T) {
			h, req := testKeaDDNS(t)
			plan, _, e := h.ddnsPlan(context.Background(), req)
			if e != nil {
				t.Fatal(e)
			}
			req.Revision = plan.Revision
			req.ProposedRevision = plan.ProposedRevision
			original := map[string]string{}
			for _, file := range plan.Files {
				if file.Family == "TSIG" {
					continue
				}
				raw, _ := os.ReadFile(file.Path)
				original[file.Path] = string(raw)
			}
			oldRun := h.run
			var calls []string
			state := map[string]string{}
			failed := false
			h.run = func(ctx context.Context, name string, args ...string) (string, error) {
				if name == "systemctl" {
					calls = append(calls, strings.Join(args, " "))
					if args[0] == "is-active" {
						if value, ok := state[args[1]]; ok {
							if value == "active" {
								return value, nil
							}
							return value, errors.New(value)
						}
					}
					if fail && !failed && args[0] == "restart" && args[1] == "kea-dhcp4.service" {
						failed = true
						return "", errors.New("test failure")
					}
					if args[0] == "restart" {
						state[args[1]] = "active"
					}
					if args[0] == "stop" {
						state[args[1]] = "inactive"
					}
				}
				return oldRun(ctx, name, args...)
			}
			result, e := h.ddnsApply(context.Background(), req)
			if fail {
				if e == nil || !strings.Contains(e.Error(), "восстановлены") {
					t.Fatalf("rollback: %v", e)
				}
				for path, before := range original {
					after, _ := os.ReadFile(path)
					if string(after) != before {
						t.Fatalf("not restored: %s", path)
					}
				}
				if !strings.Contains(strings.Join(calls, "\n"), "stop kea-dhcp-ddns.service") || !strings.Contains(strings.Join(calls, "\n"), "disable kea-dhcp-ddns.service") {
					t.Fatal("D2 state not restored")
				}
			} else {
				if e != nil {
					t.Fatal(e)
				}
				if len(result.Backups) != 4 {
					t.Fatal("backups missing")
				}
				if strings.Contains(strings.Join(calls, "\n"), "restart kea-dhcp6.service") {
					t.Fatal("started stopped DHCP6")
				}
				st, _ := os.Stat(h.cfg.Helper.KeaDDNSConfig)
				if st.Mode().Perm()&0007 != 0 {
					t.Fatal("secret readable by others")
				}
			}
		})
	}
}
func TestKeaDDNSStalePlanAndInvalidSettings(t *testing.T) {
	h, req := testKeaDDNS(t)
	req.Revision = "stale"
	req.ProposedRevision = "stale"
	before, _ := os.ReadFile(h.path)
	if _, e := h.ddnsApply(context.Background(), req); !errors.Is(e, ErrTopologyConflict) {
		t.Fatalf("stale apply: %v", e)
	}
	after, _ := os.ReadFile(h.path)
	if string(before) != string(after) {
		t.Fatal("stale plan wrote file")
	}
	for _, mutate := range []func(*KeaDDNSSettings){func(s *KeaDDNSSettings) { s.DNSAddress = "0.0.0.0" }, func(s *KeaDDNSSettings) { s.Secret = "invalid" }, func(s *KeaDDNSSettings) { s.ForwardZone = "example.test;danger" }, func(s *KeaDDNSSettings) { s.ReverseZones = []string{"clients.example.test"} }, func(s *KeaDDNSSettings) { s.Auth = "none" }} {
		settings := *req.DDNS
		mutate(&settings)
		if _, _, e := h.ddnsPlan(context.Background(), KeaRequest{DDNS: &settings}); e == nil {
			t.Fatal("invalid settings accepted")
		}
	}
}

func TestKeaDDNSReportsCredentialHealth(t *testing.T) {
	h, _ := testKeaDDNS(t)
	profile := filepath.Join(filepath.Dir(h.cfg.Helper.KeaDDNSConfig), "sambaadm-gss-profile.json")
	if err := os.WriteFile(profile, []byte(`{"principal":"kea@EXAMPLE.TEST","state":"ready","verified":"2026-11-27T07:50:00Z"}`), 0600); err != nil {
		t.Fatal(err)
	}
	original := h.run
	healthy := true
	h.run = func(ctx context.Context, name string, args ...string) (string, error) {
		command := name + " " + strings.Join(args, " ")
		switch {
		case strings.Contains(command, "is-active sambaadm-kea-ddns-credentials.timer"):
			if healthy {
				return "active", nil
			}
			return "inactive", nil
		case strings.Contains(command, "--property=Result sambaadm-kea-ddns-credentials.service"):
			return "success", nil
		case strings.Contains(command, "--property=ExecMainStartTimestamp sambaadm-kea-ddns-credentials.service"):
			return "Fri 2026-11-27 07:50:35 UTC", nil
		case name == "klist":
			if healthy {
				return "", nil
			}
			return "", errors.New("expired cache")
		}
		return original(ctx, name, args...)
	}
	status := h.ddnsInspect(t.Context())
	if status.CredentialTimer != "active" || status.CredentialResult != "success" || status.CredentialCacheValid == nil || !*status.CredentialCacheValid || status.CredentialLastRun == "" {
		t.Fatalf("missing health: %+v", status)
	}
	healthy = false
	status = h.ddnsInspect(t.Context())
	if status.CredentialCacheValid == nil || *status.CredentialCacheValid || !strings.Contains(status.Warning, "Таймер Kerberos") {
		t.Fatalf("failure hidden: %+v", status)
	}
}
