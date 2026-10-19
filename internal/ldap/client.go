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

// Client owns one LDAP connection. Service clients bind before publishing any
// connection and never allow callers to change its authentication identity.
type Client struct {
	cfg      config.LDAPConfig
	mu       sync.Mutex
	conn     *ldap.Conn
	service  bool
	password func() string
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
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.conn != nil && !c.conn.IsClosing() {
		return nil
	}

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	var servicePassword string
	if c.service {
		if c.cfg.Bind.Type != "" && c.cfg.Bind.Type != "simple" {
			return fmt.Errorf("unsupported LDAP service bind type %q", c.cfg.Bind.Type)
		}
		if strings.TrimSpace(c.cfg.Bind.User) == "" || c.password == nil {
			return fmt.Errorf("LDAP service account is not configured")
		}
		servicePassword = c.password()
		if servicePassword == "" {
			return fmt.Errorf("LDAP service account password is not configured")
		}
	}
	conn, err := dial(ctx, c.cfg.URI)
	if err != nil {
		return err
	}
	if c.service {
		if err := conn.Bind(c.cfg.Bind.User, servicePassword); err != nil {
			conn.Close()
			return fmt.Errorf("LDAP service bind: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		return err
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

// NewServiceClient creates an immutable service identity with lazy connection.
// password is resolved anew on reconnect; browser credentials never enter it.
func NewServiceClient(cfg config.LDAPConfig, password func() string) *Client {
	return &Client{cfg: cfg, service: true, password: password}
}

func dial(ctx context.Context, uri string) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var raw net.Conn
	var err error
	secure := false
	if strings.HasPrefix(strings.ToLower(uri), "ldapi://") {
		path, e := url.PathUnescape(uri[len("ldapi://"):])
		if e != nil {
			return nil, fmt.Errorf("parse ldapi path: %w", e)
		}
		if path == "" {
			path = "/var/run/samba/ldapi"
		}
		if !strings.HasPrefix(path, "/") {
			return nil, fmt.Errorf("ldapi requires an absolute socket path")
		}
		raw, err = dialer.DialContext(ctx, "unix", path)
	} else {
		u, e := url.Parse(uri)
		if e != nil {
			return nil, fmt.Errorf("parse LDAP URI: %w", e)
		}
		host := u.Hostname()
		if host == "" {
			host = "localhost"
		}
		port := u.Port()
		switch strings.ToLower(u.Scheme) {
		case "ldap", "":
			if port == "" {
				port = "389"
			}
			raw, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		case "ldaps":
			if port == "" {
				port = "636"
			}
			secure = true
			tlsDialer := &tls.Dialer{NetDialer: dialer, Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}}
			raw, err = tlsDialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
		default:
			return nil, fmt.Errorf("unsupported LDAP scheme: %s", u.Scheme)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("LDAP dial: %w", err)
	}
	conn := ldap.NewConn(raw, secure)
	conn.SetTimeout(10 * time.Second)
	conn.Start()
	return conn, nil
}
