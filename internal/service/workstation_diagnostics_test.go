package service

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestWorkstationConfigAllowlistIncludesAndSecrets(t *testing.T) {
	root := t.TempDir()
	sssd := filepath.Join(root, "sssd.conf")
	krb := filepath.Join(root, "krb5.conf")
	child := filepath.Join(root, "realm.conf")
	write := func(p, text string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(sssd, "[domain/example.test]\nid_provider = ad\nad_server = dc1.example.test\nad_backup_server = \"dc2.example.test, dc3.example.test\"\nldap_default_authtok = TOP_SECRET\n# MORE_SECRET\nad_site = site1\n")
	write(krb, "include "+child+"\n[libdefaults]\ndefault_realm = EXAMPLE.TEST\ndns_lookup_kdc = true\n[domain_realm]\n.example.test = EXAMPLE.TEST\n")
	write(child, "include "+krb+"\n[realms]\nEXAMPLE.TEST = {\nkdc = dc1.example.test:88\npassword = ANOTHER_SECRET\n}\n")
	files, warnings := collectWorkstationConfigs(sssd, krb, nil)
	if len(files) != 3 || len(warnings) != 0 {
		t.Fatalf("files/warnings: %+v %+v", files, warnings)
	}
	b, _ := json.Marshal(files)
	for _, secret := range []string{"TOP_SECRET", "MORE_SECRET", "ANOTHER_SECRET", "ldap_default_authtok", "password"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("secret or forbidden key exported: %s", secret)
		}
	}
	if len(files[0].Settings) != 3 || files[0].Omitted != 2 || !strings.Contains(strings.Join(files[0].Issues, " "), "кавычки") {
		t.Fatalf("bad SSSD analysis: %+v", files[0])
	}
	found := false
	for _, f := range files {
		for _, s := range f.Settings {
			if s.Section == "realms/EXAMPLE.TEST" && s.Key == "kdc" && s.Value == "dc1.example.test:88" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("included realm KDC missing")
	}
	w := &WorkstationDiagnostics{Format: 1, Configs: files}
	if err := validateWorkstationDiagnostics(w, "alt-workstation"); err != nil {
		t.Fatal(err)
	}
	// Imports cannot smuggle raw credential fields into the typed snapshot.
	w.Configs[0].Settings = append(w.Configs[0].Settings, SurveySetting{"domain/example.test", "ldap_default_authtok", "TOP_SECRET"})
	if validateWorkstationDiagnostics(w, "alt-workstation") == nil {
		t.Fatal("credential accepted on import")
	}
}
func TestWorkstationConfigLimitsAndMissingSources(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "krb5.conf")
	if e := os.WriteFile(path, []byte("includedir "+root+"\n[libdefaults]\ndefault_realm = EXAMPLE.TEST\n"), 0600); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 20; i++ {
		p := filepath.Join(root, string(rune('a'+i))+".conf")
		if e := os.WriteFile(p, []byte("[libdefaults]\ndns_lookup_kdc = true\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	files, warnings := collectWorkstationConfigs(filepath.Join(root, "missing"), path, nil)
	if len(files) != 16 || len(warnings) == 0 || files[0].Status != "unknown" {
		t.Fatalf("limits/missing not explicit: %d %v", len(files), warnings)
	}
	symlink := filepath.Join(root, "link")
	if e := os.Symlink(path, symlink); e != nil {
		t.Fatal(e)
	}
	r := configSurveyReader{visited: map[string]bool{}}
	r.read(symlink, "krb5")
	if r.files[0].Status != "unknown" || len(r.files[0].Settings) > 0 {
		t.Fatal("symlink followed")
	}
}
func TestSurveyDNSValidatesTargetsAndSeparatesNegativeTimeoutAndTruncation(t *testing.T) {
	in := WorkstationSurveyOptions{Resolvers: []string{"192.0.2.53", "2001:db8::53"}, Queries: []string{"app.example.test/A", "_kerberos._tcp.example.test/SRV"}}
	if err := validateSurveyDNSOptions(in); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []WorkstationSurveyOptions{{Resolvers: []string{"dns.example.test"}, Queries: in.Queries}, {Resolvers: in.Resolvers}, {Resolvers: in.Resolvers, Queries: []string{"-x/A"}}, {Resolvers: in.Resolvers, Queries: []string{"foo.test/AXFR"}}} {
		if validateSurveyDNSOptions(bad) == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	exchange := func(_ context.Context, m *dns.Msg, addr, transport string) (*dns.Msg, time.Duration, error) {
		if strings.HasPrefix(addr, "[2001:") {
			return nil, 0, errors.New("unreachable")
		}
		reply := new(dns.Msg)
		reply.SetReply(m)
		if m.Question[0].Qtype == dns.TypeA {
			reply.Rcode = dns.RcodeNameError
		} else if transport == "udp" {
			reply.Truncated = true
		}
		return reply, 3 * time.Millisecond, nil
	}
	rows := collectSurveyDNS(context.Background(), in, exchange)
	if len(rows) != 8 {
		t.Fatal(len(rows))
	}
	if rows[0].RCode != "NXDOMAIN" || rows[0].Status != "observed" || rows[2].Status != "partial" || rows[4].Status != "unknown" {
		t.Fatalf("incorrect DNS semantics: %+v", rows)
	}
	if err := validateWorkstationDiagnostics(&WorkstationDiagnostics{Format: 1, DNS: rows}, "alt-workstation"); err != nil {
		t.Fatal(err)
	}
}
func TestWorkstationSnapshotRoundTripAndLegacy(t *testing.T) {
	now := time.Now().UTC()
	s := NodeSurvey{Format: SurveyFormat, Profile: "alt-workstation", Node: "ws.example.test", Started: now, Finished: now, Checks: []SurveyObservation{{Source: "rpm -q sssd", Observed: now, Status: "observed", Detail: "sssd-test"}}, Workstation: &WorkstationDiagnostics{Format: 1}}
	for _, legacy := range []bool{false, true} {
		if legacy {
			s.Workstation = nil
		}
		b, _ := json.Marshal(s)
		m, err := ParseSurvey(context.Background(), "helper", "", "", b)
		if err != nil || m.Snapshot == nil {
			t.Fatalf("roundtrip legacy=%v: %v", legacy, err)
		}
	}
	s.Profile = "node"
	s.Workstation = &WorkstationDiagnostics{Format: 1}
	b, _ := json.Marshal(s)
	if _, err := ParseSurvey(context.Background(), "helper", "", "", b); err == nil {
		t.Fatal("wrong profile accepted")
	}
}

func TestSurveyDNSOverRealUDPAndTCP(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}, A: net.ParseIP("192.0.2.10")}}
		_ = w.WriteMsg(response)
	})
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		packet.Close()
		t.Fatal(err)
	}
	udp := &dns.Server{PacketConn: packet, Handler: handler}
	tcp := &dns.Server{Listener: listener, Handler: handler}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	t.Cleanup(func() { _ = udp.Shutdown(); _ = tcp.Shutdown() })
	exchange := func(ctx context.Context, m *dns.Msg, _ string, transport string) (*dns.Msg, time.Duration, error) {
		addr := packet.LocalAddr().String()
		if transport == "tcp" {
			addr = listener.Addr().String()
		}
		return exchangeSurveyDNS(ctx, m, addr, transport)
	}
	rows := collectSurveyDNS(context.Background(), WorkstationSurveyOptions{Resolvers: []string{"127.0.0.1"}, Queries: []string{"app.example.test/A"}}, exchange)
	for _, row := range rows {
		if row.Status != "observed" || row.RCode != "NOERROR" || len(row.Answers) != 1 || !strings.Contains(row.Answers[0], "192.0.2.10") {
			t.Fatalf("%s exchange failed: %+v", row.Transport, row)
		}
	}
}
