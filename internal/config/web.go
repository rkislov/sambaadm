package config

import (
	"fmt"
	"net"
	"net/url"
)

// ValidateWeb checks explicit listener and redirect settings without reading keys.
func (c *Config) ValidateWeb() error {
	if (c.Server.TLS.Cert == "") != (c.Server.TLS.Key == "") {
		return fmt.Errorf("HTTP TLS requires both server.tls.cert and server.tls.key")
	}
	if c.Server.PublicURL != "" {
		u, err := url.Parse(c.Server.PublicURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return fmt.Errorf("server.public_url must be https://FQDN[:port]")
		}
	}
	if c.Server.HTTPRedirect != "" {
		host, _, err := net.SplitHostPort(c.Server.HTTPRedirect)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() || c.Server.PublicURL == "" || c.Server.TLS.Cert == "" {
			return fmt.Errorf("server.http_redirect requires HTTPS, public_url and an explicit loopback address")
		}
	}
	if c.Auth.SSO.Enabled {
		u, err := url.Parse(c.LDAP.URI)
		if err != nil || (u.Scheme != "ldaps" && u.Scheme != "ldapi") {
			return fmt.Errorf("SSO requires verified LDAPS or a local ldapi socket for account lookup")
		}
	}
	if c.Auth.SSO.Enabled && (c.Server.TLS.Cert == "" || c.Server.PublicURL == "" || len(c.Auth.Roles.Admins) == 0) {
		return fmt.Errorf("SSO requires HTTPS, server.public_url and auth.roles.admins")
	}
	return nil
}
