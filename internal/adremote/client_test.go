package adremote

import (
	"context"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
	"github.com/oiweiwei/go-msrpc/ndr"
	"os"
	"strconv"
	"testing"
)

func TestIntegrationDNSRead(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_RPC") == "" {
		t.Skip("set SAMBAADM_IT_RPC")
	}
	port, _ := strconv.Atoi(os.Getenv("SAMBAADM_IT_SMB_PORT"))
	c := Client{SMBPort: port, Host: os.Getenv("SAMBAADM_IT_RPC"), User: os.Getenv("SAMBAADM_IT_USER"), Password: func() string { return os.Getenv("SAMBAADM_PASSWORD") }}
	ctx, cc, err := c.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close(ctx)
	rpc, err := dnsserver.NewDNSServerClient(ctx, cc, dcerpc.WithSeal())
	if err != nil {
		t.Fatal(err)
	}
	resp, err := rpc.EnumRecords2(ctx, &dnsserver.EnumRecords2Request{ServerName: c.Host, Zone: "sambaadm.test", NodeName: "@", RecordType: 255, SelectFlag: 0x1f})
	if err != nil {
		t.Fatal(err)
	}
	var nodes record.NodeList
	if err = ndr.Unmarshal(resp.Buffer, &nodes, ndr.Opaque); err != nil {
		t.Fatal(err)
	}
	if len(nodes.DNSNodes) == 0 {
		t.Fatal("empty DNS response")
	}
	for _, n := range nodes.DNSNodes {
		for _, r := range n.RRs() {
			t.Log(r.String())
		}
	}
}

func TestIntegrationDRS(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_RPC") == "" {
		t.Skip("set SAMBAADM_IT_RPC")
	}
	port, _ := strconv.Atoi(os.Getenv("SAMBAADM_IT_SMB_PORT"))
	c := Client{SMBPort: port, Host: os.Getenv("SAMBAADM_IT_RPC"), User: os.Getenv("SAMBAADM_IT_USER"), Password: func() string { return os.Getenv("SAMBAADM_PASSWORD") }}
	neighbors, err := c.Neighbors(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("neighbors: %d", len(neighbors))
	if os.Getenv("SAMBAADM_IT_MUTATE") == "SAMBAADM.TEST" {
		if err := c.KCC(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegrationTrustLifecycle(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_RPC") == "" || os.Getenv("SAMBAADM_IT_MUTATE") != "SAMBAADM.TEST" {
		t.Skip("disposable domain only")
	}
	port, _ := strconv.Atoi(os.Getenv("SAMBAADM_IT_SMB_PORT"))
	c := Client{SMBPort: port, Host: os.Getenv("SAMBAADM_IT_RPC"), User: os.Getenv("SAMBAADM_IT_USER"), Password: func() string { return os.Getenv("SAMBAADM_PASSWORD") }}
	sid := "S-1-5-21-1900000001-1900000002-1900000003"
	if err := c.CreateTrust(context.Background(), "synthetic-trust.invalid", "SYNTHETIC", sid, "Synthetic-Trust-Pass1!", 3, false); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ValidateTrust(context.Background(), "synthetic-trust.invalid"); err == nil {
		t.Error("unreachable trust reported healthy")
	}
	t.Cleanup(func() {
		if err := c.DeleteTrust(context.Background(), sid); err != nil {
			t.Error(err)
		}
	})
}
