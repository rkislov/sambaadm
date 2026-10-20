package adremote

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/dnsserver/v5"
	"github.com/oiweiwei/go-msrpc/msrpc/dnsp/record"
	"github.com/oiweiwei/go-msrpc/ndr"
)

func (c *Client) dns(ctx context.Context, fn func(context.Context, dnsserver.DNSServerClient) error) error {
	ctx, cc, err := c.Connect(ctx)
	if err != nil {
		return err
	}
	defer cc.Close(ctx)
	client, err := dnsserver.NewDNSServerClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithEndpoint("ncacn_ip_tcp:"))
	if err != nil {
		return err
	}
	return fn(ctx, client)
}
func (c *Client) DNSZone(ctx context.Context, zone string, remove bool) error {
	if _, ok := dns.IsDomainName(zone); !ok || strings.TrimSpace(zone) == "" {
		return fmt.Errorf("invalid DNS zone")
	}
	return c.dns(ctx, func(ctx context.Context, client dnsserver.DNSServerClient) error {
		req := &dnsserver.Operation2Request{ServerName: c.Host, Operation: "ZoneCreate", TypeID: uint32(dnsp.TypeIDZoneCreateW2K), Data: &dnsp.Union{Value: &dnsp.Union_ZoneCreateW2K{ZoneCreateW2K: &dnsp.ZoneCreateInfoW2K{ZoneName: zone, ZoneType: 1, AllowUpdate: 2, DSIntegrated: 1, Flags: 0x1000}}}}
		if remove {
			req = &dnsserver.Operation2Request{ServerName: c.Host, Zone: zone, Operation: "DeleteZoneFromDs", TypeID: uint32(dnsp.TypeIDDword), Data: &dnsp.Union{Value: &dnsp.Union_Dword{Dword: 0}}}
		}
		_, err := client.Operation2(ctx, req)
		return err
	})
}
func DNSRecord(typ, data string) (*dnsp.Record, error) {
	code, ok := dns.StringToType[strings.ToUpper(typ)]
	if !ok {
		return nil, fmt.Errorf("unsupported DNS type %q", typ)
	}
	// Preserve the existing UI's Samba-style SRV (target port priority weight)
	// and MX (target preference) input while encoding standard DNS wire data.
	fields := strings.Fields(data)
	switch strings.ToUpper(typ) {
	case "SRV":
		if len(fields) != 4 {
			return nil, fmt.Errorf("SRV: expected target port priority weight")
		}
		data = fields[2] + " " + fields[3] + " " + fields[1] + " " + fields[0]
	case "MX":
		if len(fields) != 2 {
			return nil, fmt.Errorf("MX: expected target preference")
		}
		data = fields[1] + " " + fields[0]
	}
	rec, err := record.NewRecordFromString(code, 900, data)
	if err != nil {
		return nil, err
	}
	return &dnsp.Record{Type: code, DataLength: rec.DataLength, TTLSeconds: rec.TTLSeconds, Flags: 0xf0, Buffer: rec.Buffer}, nil
}
func (c *Client) DNSUpdate(ctx context.Context, zone, name, typ, oldData, newData string) error {
	req := &dnsserver.UpdateRecord2Request{ServerName: c.Host, Zone: zone, NodeName: name}
	var err error
	if oldData != "" {
		req.DeleteRecord, err = DNSRecord(typ, oldData)
		if err != nil {
			return err
		}
	}
	if newData != "" {
		req.AddRecord, err = DNSRecord(typ, newData)
		if err != nil {
			return err
		}
	}
	return c.dns(ctx, func(ctx context.Context, client dnsserver.DNSServerClient) error {
		_, err := client.UpdateRecord2(ctx, req)
		return err
	})
}

type DNSResult struct{ Name, Type, Data, Raw string }

func (c *Client) DNSQuery(ctx context.Context, zone, name, typ string) ([]DNSResult, error) {
	if name == "" {
		name = "@"
	}
	code := uint16(255)
	if typ != "" && !strings.EqualFold(typ, "ALL") {
		var ok bool
		code, ok = dns.StringToType[strings.ToUpper(typ)]
		if !ok {
			return nil, fmt.Errorf("unsupported DNS type")
		}
	}
	out := []DNSResult{}
	err := c.dns(ctx, func(ctx context.Context, client dnsserver.DNSServerClient) error {
		resp, err := client.EnumRecords2(ctx, &dnsserver.EnumRecords2Request{ServerName: c.Host, Zone: zone, NodeName: name, RecordType: code, SelectFlag: 0x1f})
		if err != nil {
			return err
		}
		var nodes record.NodeList
		if err := ndr.Unmarshal(resp.Buffer, &nodes, ndr.Opaque); err != nil {
			return err
		}
		for _, node := range nodes.DNSNodes {
			for _, rr := range node.RRs() {
				data := strings.TrimPrefix(rr.String(), rr.Header().String())
				switch r := rr.(type) {
				case *dns.SRV:
					data = fmt.Sprintf("%s %d %d %d", r.Target, r.Port, r.Priority, r.Weight)
				case *dns.MX:
					data = fmt.Sprintf("%s %d", r.Mx, r.Preference)
				}
				nodeName := string(node.DNSNodeName.DNSName)
				if nodeName == "" {
					nodeName = name
				}
				out = append(out, DNSResult{Name: nodeName, Type: dns.TypeToString[rr.Header().Rrtype], Data: data, Raw: rr.String()})
			}
		}
		return nil
	})
	return out, err
}
