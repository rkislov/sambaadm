package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"sambaadm/internal/config"
)

// Client wraps an LDAP connection with reconnect and basic pooling.
type Client struct {
	cfg  config.LDAPConfig
	mu   sync.Mutex
	conn *ldap.Conn
}

// NewClient creates an LDAP client from config. Connection is lazy.
func NewClient(cfg config.LDAPConfig) *Client {
	return &Client{cfg: cfg}
}

// Connect dials LDAP (ldap://, ldaps://, or ldapi:// Unix socket).
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connectLocked(ctx)
}

func (c *Client) connectLocked(ctx context.Context) error {
	if c.conn != nil && !c.conn.IsClosing() {
		return nil
	}

	uri := c.cfg.URI
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("parse ldap uri: %w", err)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn *ldap.Conn

	switch strings.ToLower(u.Scheme) {
	case "ldapi":
		path, err := url.PathUnescape(u.Path)
		if err != nil {
			path = u.Path
		}
		if path == "" {
			path = "/var/run/samba/ldapi"
		}
		raw, err := dialer.DialContext(ctx, "unix", path)
		if err != nil {
			return fmt.Errorf("ldapi dial %s: %w", path, err)
		}
		conn = ldap.NewConn(raw, false)
		conn.Start()
	case "ldaps":
		host := u.Host
		if !strings.Contains(host, ":") {
			host += ":636"
		}
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		raw, err := tls.DialWithDialer(dialer, "tcp", host, tlsCfg)
		if err != nil {
			return fmt.Errorf("ldaps dial %s: %w", host, err)
		}
		conn = ldap.NewConn(raw, true)
		conn.Start()
	case "ldap", "":
		host := u.Host
		if host == "" {
			host = "localhost:389"
		} else if !strings.Contains(host, ":") {
			host += ":389"
		}
		raw, err := dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			return fmt.Errorf("ldap dial %s: %w", host, err)
		}
		conn = ldap.NewConn(raw, false)
		conn.Start()
	default:
		return fmt.Errorf("unsupported ldap scheme: %s", u.Scheme)
	}

	c.conn = conn
	return nil
}

// Close closes the underlying connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	return nil
}

// Conn returns a live connection, reconnecting if needed.
func (c *Client) Conn(ctx context.Context) (*ldap.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.connectLocked(ctx); err != nil {
		return nil, err
	}
	return c.conn, nil
}

// BaseDN returns the configured search base.
func (c *Client) BaseDN() string {
	return c.cfg.BaseDN
}

// URI returns the configured LDAP URI.
func (c *Client) URI() string {
	return c.cfg.URI
}
