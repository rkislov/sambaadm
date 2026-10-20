// Package adremote implements authenticated native domain administration protocols.
package adremote

import (
	"context"
	"fmt"
	smb2 "github.com/oiweiwei/go-smb2.fork"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

type Client struct {
	SMBPort    int
	Host, User string
	Password   func() string
}

func (c *Client) Connect(ctx context.Context) (context.Context, dcerpc.Conn, error) {
	if c.User == "" || c.Password == nil {
		return ctx, nil, fmt.Errorf("RPC service credentials are required")
	}
	password := c.Password()
	if password == "" {
		return ctx, nil, fmt.Errorf("RPC service password is required")
	}
	ctx = gssapi.NewSecurityContext(ctx, gssapi.WithCredential(credential.NewFromPassword(c.User, password)), gssapi.WithMechanismFactory(ssp.SPNEGO), gssapi.WithMechanismFactory(ssp.NTLM))
	user, domain := c.User, ""
	if d, u, ok := strings.Cut(user, "\\"); ok {
		user, domain = u, d
	} else if u, d, ok := strings.Cut(user, "@"); ok {
		user, domain = u, d
	}
	smbDialer := &smb2.Dialer{Negotiator: smb2.Negotiator{RequireMessageSigning: true}, Initiator: &smb2.NTLMInitiator{User: user, Domain: domain, Password: password}}
	port := c.SMBPort
	if port == 0 {
		port = 445
	}
	cc, err := dcerpc.Dial(ctx, c.Host, dcerpc.WithTimeout(15*time.Second), epm.EndpointMapper(ctx, c.Host, dcerpc.WithTimeout(15*time.Second)), dcerpc.WithSMBPort(port), dcerpc.WithSMBDialer(smbDialer))
	return ctx, cc, err
}
