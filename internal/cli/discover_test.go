package cli

import (
	"context"
	"net"
	"testing"
)

func TestResolveCandidates(t *testing.T) {
	lookup := func(_ context.Context, service, proto, name string) (string, []*net.SRV, error) {
		if service != "ldap" || proto != "tcp" {
			t.Fatal(service, proto)
		}
		switch name {
		case "dc._msdcs.corp.example", "dc._msdcs.lab.example":
			return "", []*net.SRV{{Target: "DC1." + name[len("dc._msdcs."):] + "."}}, nil
		}
		return "", nil, nil
	}
	candidates := resolverDomains("domain previous.example\nsearch unrelated.example CORP.EXAMPLE # search suffixes")
	domain, dc, err := resolveCandidates(context.Background(), candidates, "", "", lookup)
	if err != nil || domain != "corp.example" || dc != "dc1.corp.example" {
		t.Fatal(domain, dc, err)
	}
	if _, _, err := resolveCandidates(context.Background(), append(candidates, "lab.example"), "", "", lookup); err == nil {
		t.Fatal("ambiguous domains accepted")
	}
}
