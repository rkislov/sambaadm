package cli

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sambaadm/internal/auth"
	"strings"
	"time"
)

func init() {
	sso := &cobra.Command{Use: "sso", Short: "Kerberos SSO keytab checks"}
	var path, principal, realm string
	check := &cobra.Command{Use: "check", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		cfg := rootCfg.Auth.SSO
		if path != "" {
			cfg.Keytab = path
		}
		if principal != "" {
			cfg.Principal = principal
		}
		if realm != "" {
			cfg.Realm = realm
		}
		kt, err := auth.LoadSSOKeytab(cfg)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "HTTP keytab проверен: %s@%s (ключей: %d)\n", cfg.Principal, cfg.Realm, len(kt.Entries))
		return nil
	}}
	check.Flags().StringVar(&path, "keytab", "", "HTTP keytab path")
	check.Flags().StringVar(&principal, "principal", "", "HTTP/FQDN")
	check.Flags().StringVar(&realm, "sso-realm", "", "Kerberos realm")
	sso.AddCommand(check)
	rootCmd.AddCommand(sso)
}
func verifyHTTPS(ctx context.Context) error {
	cfg := rootCfg
	u, err := url.Parse(cfg.Server.PublicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("HTTPS public_url is not configured")
	}
	raw, err := os.ReadFile(cfg.Server.TLS.Cert)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return fmt.Errorf("invalid HTTPS certificate")
	}
	ca, err := os.ReadFile(filepath.Join(filepath.Dir(cfg.Server.TLS.Cert), "ca.pem"))
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return fmt.Errorf("invalid HTTPS CA")
	}
	host, port, err := net.SplitHostPort(cfg.Server.Listen)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if host == "::" {
		host = "::1"
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 8 * time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: u.Hostname(), VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, block.Bytes) {
			return fmt.Errorf("server is not serving the renewed HTTPS certificate")
		}
		return nil
	}}}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(strings.Trim(host, "[]"), port))
	if err != nil {
		return err
	}
	return conn.Close()
}
