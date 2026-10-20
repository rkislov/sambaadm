package adremote

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
)

func (c *Client) SYSVOL(ctx context.Context, port int, fn func(*smb2.Share) error) error {
	if c.Password == nil || c.User == "" {
		return fmt.Errorf("SMB service credentials are required")
	}
	if port == 0 {
		port = 445
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	user, domain := c.User, ""
	if d, u, ok := strings.Cut(user, "\\"); ok {
		domain, user = d, u
	} else if u, d, ok := strings.Cut(user, "@"); ok {
		domain, user = d, u
	}
	d := smb2.Dialer{Negotiator: smb2.Negotiator{RequireMessageSigning: true}, Initiator: &smb2.NTLMInitiator{User: user, Domain: domain, Password: c.Password()}}
	session, err := d.Dial(ctx, net.JoinHostPort(c.Host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	defer session.Logoff()
	share, err := session.WithContext(ctx).Mount("SYSVOL")
	if err != nil {
		return err
	}
	defer share.Umount()
	return fn(share.WithContext(ctx))
}
