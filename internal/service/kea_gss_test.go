package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeaGSSRejectsUnsafeRequestsBeforeWorker(t *testing.T) {
	h, _ := testKeaDDNS(t)
	cases := []KeaRequest{{}, {GSS: &KeaGSSSettings{}, DDNS: &KeaDDNSSettings{ForwardZone: "bad\nzone"}}, {GSS: &KeaGSSSettings{}, DDNS: &KeaDDNSSettings{ForwardZone: "example.test", ReverseZones: []string{"0.0.10.in-addr.arpa."}, DNSPort: 53, DNSAddress: "0.0.0.0"}}}
	for _, request := range cases {
		if _, err := h.gssWorkerCall(context.Background(), "ad-apply", request, true); err == nil {
			t.Fatal("unsafe input accepted")
		}
	}
	if _, err := helperKeaGSS(t.Context(), h, "kea.gss.ad.apply", KeaRequest{}); err == nil {
		t.Fatal("unconfirmed AD change")
	}
	if _, err := h.gssJobStatus(t.Context(), "../../etc/passwd"); err == nil {
		t.Fatal("unsafe job ID accepted")
	}
}

func TestKeaGSSProfileDoesNotExposeKeyFingerprint(t *testing.T) {
	h, _ := testKeaDDNS(t)
	path := filepath.Join(filepath.Dir(h.cfg.Helper.KeaDDNSConfig), "sambaadm-gss-profile.json")
	if err := os.WriteFile(path, []byte(`{"principal":"kea@EXAMPLE.TEST","keytabSHA256":"private-fingerprint","state":"needs-review"}`), 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(h.gssProfile())
	if strings.Contains(string(raw), "private-fingerprint") || !strings.Contains(string(raw), "needs-review") {
		t.Fatalf("unsafe profile: %s", raw)
	}
	if err := os.WriteFile(path, []byte(`broken`), 0600); err != nil {
		t.Fatal(err)
	}
	if h.gssProfile() != nil {
		t.Fatal("invalid profile exposed")
	}
}

func TestKeaGSSKeytabFingerprintDetectsReplacement(t *testing.T) {
	h, _ := testKeaDDNS(t)
	directory := filepath.Dir(h.cfg.Helper.KeaDDNSConfig)
	keytab := filepath.Join(directory, "ddns.keytab")
	key := []byte("test-keytab-content")
	hash := sha256.Sum256(key)
	profile, _ := json.Marshal(map[string]string{"keytabSHA256": hex.EncodeToString(hash[:])})
	os.WriteFile(keytab, key, 0600)
	os.WriteFile(filepath.Join(directory, "sambaadm-gss-profile.json"), profile, 0600)
	if !h.gssKeytabMatches(keytab) {
		t.Fatal("matching keytab rejected")
	}
	os.WriteFile(keytab, []byte("replaced-keytab"), 0600)
	if h.gssKeytabMatches(keytab) {
		t.Fatal("replacement accepted")
	}
}
