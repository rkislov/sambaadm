package ldap

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// BindSimple performs a simple bind with DN/username and password.
// Prefer ldaps:// or ldapi:// — never send credentials over plain ldap:// in production.
func (c *Client) BindSimple(ctx context.Context, user, password string) error {
	conn, err := c.Conn(ctx)
	if err != nil {
		return err
	}
	if err := conn.Bind(user, password); err != nil {
		return fmt.Errorf("ldap bind: %w", err)
	}
	return nil
}

// BindAnonymous binds anonymously (useful for health checks / public reads).
func (c *Client) BindAnonymous(ctx context.Context) error {
	conn, err := c.Conn(ctx)
	if err != nil {
		return err
	}
	if err := conn.UnauthenticatedBind(""); err != nil {
		return fmt.Errorf("anonymous bind: %w", err)
	}
	return nil
}

// WhoAmI returns the authz ID of the current bind (RFC 4532) when supported.
func (c *Client) WhoAmI(ctx context.Context) (string, error) {
	conn, err := c.Conn(ctx)
	if err != nil {
		return "", err
	}
	req := ldap.NewExtendedRequest("1.3.6.1.4.1.4203.1.11.3", nil)
	res, err := conn.Extended(req)
	if err != nil {
		return "", fmt.Errorf("whoami: %w", err)
	}
	if res.Value == nil {
		return "", nil
	}
	if s, ok := res.Value.Value.(string); ok {
		return s, nil
	}
	if b, ok := res.Value.Value.([]byte); ok {
		return string(b), nil
	}
	return fmt.Sprint(res.Value.Value), nil
}
