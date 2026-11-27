package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sambaadm/internal/config"
)

// Execute only on a disposable, provisioned ALT host (see testdata/kea/gss).
func TestKeaRealGSSPlan(t *testing.T) {
	if os.Getenv("SAMBAADM_KEA_GSS_TEST") != "1" {
		t.Skip("requires real Kea GSS hook and provisioned Samba AD profile")
	}
	profile, err := os.ReadFile("/etc/kea/sambaadm-gss-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	var identity struct {
		Principal       string `json:"principal"`
		ServerPrincipal string `json:"serverPrincipal"`
	}
	json.Unmarshal(profile, &identity)
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.Helper.Kea4Config = filepath.Join(dir, "kea4.conf")
	cfg.Helper.Kea6Config = filepath.Join(dir, "kea6.conf")
	cfg.Helper.KeaDDNSConfig = filepath.Join(dir, "d2.conf")
	cfg.Helper.KeaDDNSKeytab = "/etc/kea/ddns.keytab"
	os.WriteFile(filepath.Join(dir, "sambaadm-gss-profile.json"), profile, 0600)
	for family, path := range map[string]string{"4": cfg.Helper.Kea4Config, "6": cfg.Helper.Kea6Config} {
		subnet := "10.0.0.0/24"
		if family == "6" {
			subnet = "2001:db8::/64"
		}
		raw, _ := json.Marshal(map[string]any{"Dhcp" + family: map[string]any{"interfaces-config": map[string]any{"interfaces": []string{}}, "valid-lifetime": 3600, "subnet" + family: []any{map[string]any{"id": 1, "subnet": subnet}}}})
		if err := os.WriteFile(path, raw, 0640); err != nil {
			t.Fatal(err)
		}
	}
	h, err := configuredKeaHost(cfg, "4")
	if err != nil {
		t.Fatal(err)
	}
	request := KeaRequest{DDNS: &KeaDDNSSettings{ForwardZone: "sambaadm.test.", ReverseZones: []string{"0.0.10.in-addr.arpa."}, DNSAddress: os.Getenv("GSS_DNS_IP"), DNSPort: 1053, NCRPort: 15899, Auth: "gss-tsig", ClientPrincipal: identity.Principal, ServerPrincipal: identity.ServerPrincipal}}
	_, files, err := h.ddnsPlan(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 3 {
		t.Fatalf("expected D2 and both DHCP configs, got %d", len(files))
	}
	for _, file := range files {
		proposed := file.plan.Proposed
		if file.host.family == "Ddns" {
			if !strings.Contains(proposed, "credentials-cache") || strings.Contains(proposed, "client-keytab") {
				t.Fatal("auto profile must use refreshed credentials cache")
			}
		} else if !strings.Contains(proposed, `"ddns-conflict-resolution-mode": "no-check-without-dhcid"`) {
			t.Fatal("missing Samba AD conflict mode")
		}
	}
	request.DDNS.ClientPrincipal = "other@SAMBAADM.TEST"
	if _, _, err := h.ddnsPlan(context.Background(), request); err == nil {
		t.Fatal("mismatching keytab identity accepted")
	}
}

// Configure only fresh disposable QEMU guests; preserves service state across test exit.
func TestKeaRealGSSVMConfigure(t *testing.T) {
	if os.Getenv("SAMBAADM_KEA_GSS_VM_CONFIGURE") != "1" {
		t.Skip("requires disposable VM with prepared AD identity")
	}
	cfg := &config.Config{}
	cfg.Helper.Kea4Config = "/etc/kea/kea-dhcp4.conf"
	cfg.Helper.Kea6Config = "/etc/kea/kea-dhcp6.conf"
	cfg.Helper.KeaDDNSConfig = "/etc/kea/kea-dhcp-ddns.conf"
	cfg.Helper.KeaDDNSKeytab = "/etc/kea/ddns.keytab"
	for family, path := range map[string]string{"4": cfg.Helper.Kea4Config, "6": cfg.Helper.Kea6Config} {
		raw := `{"Dhcp` + family + `":{"interfaces-config":{"interfaces":[]},"valid-lifetime":3600,"subnet` + family + `":[]}}`
		if err := os.WriteFile(path, []byte(raw), 0640); err != nil {
			t.Fatal(err)
		}
	}
	h, err := configuredKeaHost(cfg, "4")
	if err != nil {
		t.Fatal(err)
	}
	p := h.gssProfile()
	req := KeaRequest{Confirm: true, DDNS: &KeaDDNSSettings{ForwardZone: "sambaadm.test.", ReverseZones: []string{"0.0.10.in-addr.arpa.", "0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."}, DNSAddress: "10.0.2.2", DNSPort: 1053, NCRPort: 15999, Auth: "gss-tsig", ClientPrincipal: p["principal"].(string), ServerPrincipal: p["serverPrincipal"].(string)}}
	plan, _, err := h.ddnsPlan(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	req.Revision = plan.Revision
	req.ProposedRevision = plan.ProposedRevision
	if _, err = h.ddnsApply(context.Background(), req); err != nil {
		t.Fatal(err)
	}
}
