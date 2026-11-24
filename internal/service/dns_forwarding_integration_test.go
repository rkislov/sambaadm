package service

import (
	"context"
	"github.com/miekg/dns"
	"os"
	"sambaadm/internal/config"
	"testing"
)

func TestIntegrationDNSForwardingHost(t *testing.T) {
	if os.Getenv("SAMBAADM_DNS_FORWARD_IT") != "1" {
		t.Skip("disposable BIND fixture only")
	}
	ctx := context.Background()
	cfg := &config.Config{}
	cfg.Helper.Node = "test-dc"
	h, e := newDNSForwardHost(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	in := DNSForwardRequest{Rules: []DNSForwardRule{{Domain: "app.sambaadm.test", Servers: []string{os.Getenv("SAMBAADM_DNS_UPSTREAM")}, Mode: "only"}}, Confirm: true}
	p, e := h.plan(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	in.Revision = p.Revision
	in.ProposedRevision = p.ProposedRevision
	out, e := h.apply(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Status.Rules) != 1 {
		t.Fatal(out)
	}
	q := new(dns.Msg)
	q.SetQuestion("proof.app.sambaadm.test.", dns.TypeA)
	response, _, e := new(dns.Client).ExchangeContext(ctx, q, "127.0.0.1:53")
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, rr := range response.Answer {
		if a, ok := rr.(*dns.A); ok && a.A.String() == "198.51.100.24" {
			found = true
		}
	}
	if !found {
		t.Fatalf("conditional forwarding did not win over AD parent: %s", response)
	}
	in.Rules = []DNSForwardRule{}
	in.Revision = ""
	p, e = h.plan(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	in.Revision = p.Revision
	in.ProposedRevision = p.ProposedRevision
	if _, e = h.apply(ctx, in); e != nil {
		t.Fatal(e)
	}
}
