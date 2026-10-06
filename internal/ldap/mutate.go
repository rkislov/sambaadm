package ldap

import (
	"context"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// Add creates a new LDAP entry.
func (c *Client) Add(ctx context.Context, dn string, attrs []ldap.Attribute) error {
	conn, err := c.Conn(ctx)
	if err != nil {
		return err
	}
	req := ldap.NewAddRequest(dn, nil)
	req.Attributes = attrs
	if err := conn.Add(req); err != nil {
		return fmt.Errorf("ldap add %s: %w", dn, err)
	}
	return nil
}

// Modify applies attribute changes to an entry.
func (c *Client) Modify(ctx context.Context, req *ldap.ModifyRequest) error {
	conn, err := c.Conn(ctx)
	if err != nil {
		return err
	}
	if err := conn.Modify(req); err != nil {
		return fmt.Errorf("ldap modify %s: %w", req.DN, err)
	}
	return nil
}

// Delete removes an entry by DN.
func (c *Client) Delete(ctx context.Context, dn string) error {
	conn, err := c.Conn(ctx)
	if err != nil {
		return err
	}
	req := ldap.NewDelRequest(dn, nil)
	if err := conn.Del(req); err != nil {
		return fmt.Errorf("ldap delete %s: %w", dn, err)
	}
	return nil
}

// ModifyDN renames and/or moves an entry.
func (c *Client) ModifyDN(ctx context.Context, dn, newRDN string, deleteOld bool, newSuperior string) error {
	conn, err := c.Conn(ctx)
	if err != nil {
		return err
	}
	req := ldap.NewModifyDNRequest(dn, newRDN, deleteOld, newSuperior)
	if err := conn.ModifyDN(req); err != nil {
		return fmt.Errorf("ldap modifydn %s: %w", dn, err)
	}
	return nil
}

// ReplaceAttr is a helper for a single attribute replace.
func (c *Client) ReplaceAttr(ctx context.Context, dn, attr string, values ...string) error {
	req := ldap.NewModifyRequest(dn, nil)
	req.Replace(attr, values)
	return c.Modify(ctx, req)
}

// AddAttrValues adds values to a multi-valued attribute.
func (c *Client) AddAttrValues(ctx context.Context, dn, attr string, values ...string) error {
	req := ldap.NewModifyRequest(dn, nil)
	req.Add(attr, values)
	return c.Modify(ctx, req)
}

// DeleteAttrValues removes values from a multi-valued attribute.
func (c *Client) DeleteAttrValues(ctx context.Context, dn, attr string, values ...string) error {
	req := ldap.NewModifyRequest(dn, nil)
	req.Delete(attr, values)
	return c.Modify(ctx, req)
}
