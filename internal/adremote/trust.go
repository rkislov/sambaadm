package adremote

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/lsad/lsarpc/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/nrpc/logon/v1"
)

func (c *Client) lsa(ctx context.Context, fn func(context.Context, lsarpc.LsarpcClient, *lsarpc.Handle) error) error {
	ctx, cc, err := c.Connect(ctx)
	if err != nil {
		return err
	}
	defer cc.Close(ctx)
	client, err := lsarpc.NewLsarpcClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithEndpoint("ncacn_np:[lsarpc]"))
	if err != nil {
		return err
	}
	policy, err := client.OpenPolicy2(ctx, &lsarpc.OpenPolicy2Request{SystemName: c.Host, ObjectAttributes: &lsarpc.ObjectAttributes{}, DesiredAccess: 0x02000000})
	if err != nil {
		return err
	}
	defer client.Close(ctx, &lsarpc.CloseRequest{Object: policy.Policy})
	return fn(ctx, client, policy.Policy)
}
func (c *Client) CreateTrust(ctx context.Context, domain, flat, sid, password string, direction uint32, forest bool) error {
	parsed, err := dtyp.ParseSID(sid)
	if err != nil {
		return fmt.Errorf("invalid remote domain SID: %w", err)
	}
	if strings.TrimSpace(domain) == "" || strings.TrimSpace(flat) == "" || password == "" {
		return fmt.Errorf("domain, NetBIOS name, SID and shared trust password are required")
	}
	if direction < 1 || direction > 3 {
		return fmt.Errorf("invalid trust direction")
	}
	words := utf16.Encode([]rune(password))
	secret := make([]byte, len(words)*2)
	for i, w := range words {
		binary.LittleEndian.PutUint16(secret[2*i:], w)
	}
	auth := &lsarpc.AuthInformation{LastUpdateTime: &dtyp.LargeInteger{QuadPart: time.Now().Unix()*10000000 + 116444736000000000}, AuthType: 2, AuthInfo: secret}
	authentication := &lsarpc.TrustedDomainAuthInformation{}
	if direction&1 != 0 {
		authentication.IncomingAuthInfos = 1
		authentication.IncomingAuthenticationInformation = auth
	}
	if direction&2 != 0 {
		authentication.OutgoingAuthInfos = 1
		authentication.OutgoingAuthenticationInformation = auth
	}
	attributes := uint32(4)
	if forest {
		attributes = 8
	}
	return c.lsa(ctx, func(ctx context.Context, client lsarpc.LsarpcClient, h *lsarpc.Handle) error {
		resp, err := client.CreateTrustedDomainEx(ctx, &lsarpc.CreateTrustedDomainExRequest{Policy: h, TrustedDomainInformation: &lsarpc.TrustedDomainInformationEx{Name: &dtyp.UnicodeString{Buffer: domain}, FlatName: &dtyp.UnicodeString{Buffer: flat}, SID: parsed, TrustDirection: direction, TrustType: 2, TrustAttributes: attributes}, AuthenticationInformation: authentication, DesiredAccess: 0x02000000})
		if err != nil {
			return err
		}
		_, err = client.Close(ctx, &lsarpc.CloseRequest{Object: resp.TrustedDomain})
		return err
	})
}
func (c *Client) DeleteTrust(ctx context.Context, sid string) error {
	parsed, err := dtyp.ParseSID(sid)
	if err != nil {
		return err
	}
	return c.lsa(ctx, func(ctx context.Context, client lsarpc.LsarpcClient, h *lsarpc.Handle) error {
		_, err := client.DeleteTrustedDomain(ctx, &lsarpc.DeleteTrustedDomainRequest{Policy: h, TrustedDomainSID: parsed})
		return err
	})
}

func (c *Client) ValidateTrust(ctx context.Context, domain string) (string, error) {
	ctx, cc, err := c.Connect(ctx)
	if err != nil {
		return "", err
	}
	defer cc.Close(ctx)
	client, err := logon.NewLogonClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithEndpoint("ncacn_np:[netlogon]"))
	if err != nil {
		return "", err
	}
	resp, err := client.Control2Ex(ctx, &logon.Control2ExRequest{ServerName: "\\\\" + c.Host, FunctionCode: 10, QueryLevel: 2, Data: &logon.ControlDataInformation{Value: &logon.ControlDataInformation_TrustedDomainName{TrustedDomainName: domain}}})
	if err != nil {
		return "", err
	}
	if resp.Buffer == nil {
		return "", fmt.Errorf("empty trust validation response")
	}
	info, ok := resp.Buffer.GetValue().(*logon.Info2)
	if !ok {
		return "", fmt.Errorf("unexpected trust validation response")
	}
	result := fmt.Sprintf("DC=%s channel=%d verification=%d", info.TrustedDCName, info.TCConnectionStatus, info.PDCConnectionStatus)
	if info.TCConnectionStatus != 0 || info.PDCConnectionStatus != 0 {
		return result, fmt.Errorf("trust validation failed: %s", result)
	}
	return result, nil
}
