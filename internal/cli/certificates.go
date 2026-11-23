package cli

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"sambaadm/internal/auth"
	"sambaadm/internal/pki"
)

var httpsNameRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

func configNodeSet(root *yaml.Node, value any, path ...string) error {
	node := root
	if node.Kind == yaml.DocumentNode {
		node = node.Content[0]
	}
	for i, name := range path {
		if node.Kind != yaml.MappingNode {
			return fmt.Errorf("configuration %s must be a mapping", strings.Join(path[:i], "."))
		}
		var child *yaml.Node
		for n := 0; n < len(node.Content); n += 2 {
			if node.Content[n].Value == name {
				child = node.Content[n+1]
				break
			}
		}
		if child == nil {
			child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name}, child)
		}
		if i == len(path)-1 {
			var encoded yaml.Node
			if err := encoded.Encode(value); err != nil {
				return err
			}
			encoded.HeadComment = child.HeadComment
			encoded.LineComment = child.LineComment
			encoded.FootComment = child.FootComment
			*child = encoded
			return nil
		}
		node = child
	}
	return nil
}
func init() {
	certificates := &cobra.Command{Use: "certificates", Short: "HTTPS certificate configuration and renewal"}
	for _, mode := range []string{"configure", "renew"} {
		mode := mode
		var dns, listen, output, keytab, realm, redirect string
		var years int
		cmd := &cobra.Command{Use: mode, Short: "Issue a domain-named HTTPS certificate and write a reviewed configuration candidate", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			cfg := *rootCfg
			if cfg.Source == "" || output == "" {
				return fmt.Errorf("existing --config and a new --output file are required")
			}
			source, err := filepath.Abs(cfg.Source)
			if err != nil {
				return err
			}
			target, err := filepath.Abs(output)
			if err != nil {
				return err
			}
			if source == target {
				return fmt.Errorf("output must differ from the live configuration")
			}
			if _, err = os.Lstat(target); !os.IsNotExist(err) {
				return fmt.Errorf("output already exists or cannot be inspected")
			}
			raw, err := os.ReadFile(source)
			if err != nil {
				return err
			}
			var document yaml.Node
			if err = yaml.Unmarshal(raw, &document); err != nil {
				return err
			}
			if len(document.Content) != 1 {
				return fmt.Errorf("one YAML document is required")
			}
			if dns == "" && cfg.Server.PublicURL != "" {
				u, e := url.Parse(cfg.Server.PublicURL)
				if e == nil {
					dns = u.Hostname()
				}
			}
			if dns == "" {
				var labels []string
				for _, part := range strings.Split(cfg.LDAP.BaseDN, ",") {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(strings.ToUpper(part), "DC=") {
						labels = append(labels, part[3:])
					}
				}
				if len(labels) > 1 {
					dns = "sambaadm." + strings.Join(labels, ".")
				}
			}
			dns = strings.ToLower(strings.TrimSuffix(dns, "."))
			if !httpsNameRE.MatchString(dns) || len(dns) > 253 || net.ParseIP(dns) != nil {
				return fmt.Errorf("--dns must be a full DNS name")
			}
			for _, label := range strings.Split(dns, ".") {
				if len(label) > 63 {
					return fmt.Errorf("DNS label exceeds 63 characters")
				}
			}
			if mode == "renew" && cfg.Server.TLS.Cert == "" {
				return fmt.Errorf("HTTPS is not configured; use certificates configure")
			}
			if years != 1 && years != 3 && years != 5 && years != 10 {
				return fmt.Errorf("--years must be 1, 3, 5 or 10")
			}
			if listen == "" {
				if mode == "renew" && cfg.Server.TLS.Cert != "" {
					listen = cfg.Server.Listen
				} else {
					listen = "0.0.0.0:443"
				}
			}
			_, port, err := net.SplitHostPort(listen)
			if err != nil {
				return err
			}
			number, e := strconv.Atoi(port)
			if e != nil || number < 1 || number > 65535 {
				return fmt.Errorf("HTTPS listen port must be 1..65535")
			}
			publicURL := "https://" + dns
			if port != "443" {
				publicURL = "https://" + net.JoinHostPort(dns, port)
			}
			cfg.Server.PublicURL = publicURL
			cfg.Server.Listen = listen
			if mode == "configure" {
				cfg.Server.HTTPRedirect = redirect
			}
			if keytab != "" {
				cfg.Auth.SSO.Enabled = true
				cfg.Auth.SSO.Keytab = keytab
				cfg.Auth.SSO.Principal = "HTTP/" + dns
				if realm == "" {
					var labels []string
					for _, part := range strings.Split(cfg.LDAP.BaseDN, ",") {
						part = strings.TrimSpace(part)
						if strings.HasPrefix(strings.ToUpper(part), "DC=") {
							labels = append(labels, part[3:])
						}
					}
					realm = strings.Join(labels, ".")
				}
				cfg.Auth.SSO.Realm = strings.ToUpper(realm)
			}
			if cfg.Auth.SSO.Enabled {
				if cfg.Auth.SSO.Principal != "HTTP/"+dns {
					return fmt.Errorf("HTTPS name differs from the configured SSO principal")
				}
				if _, err = auth.LoadSSOKeytab(cfg.Auth.SSO); err != nil {
					return err
				}
			}
			if err = pki.EnsureDir(cfg.Server.CertificateDir); err != nil {
				return err
			}
			httpsDir := filepath.Join(cfg.Server.CertificateDir, "https")
			if err = pki.EnsureDir(httpsDir); err != nil {
				return err
			}
			dir, err := os.MkdirTemp(httpsDir, "server-")
			if err != nil {
				return err
			}
			keep := false
			defer func() {
				if !keep {
					os.RemoveAll(dir)
				}
			}()
			ca, caKey, caPEM, err := pki.LoadAuthority(cfg.Server.CertificateDir)
			if err != nil {
				return err
			}
			if mode == "renew" {
				current, e := os.ReadFile(cfg.Server.TLS.Cert)
				if e != nil {
					return e
				}
				block, _ := pem.Decode(current)
				if block == nil {
					return fmt.Errorf("current HTTPS certificate is invalid")
				}
				leaf, e := x509.ParseCertificate(block.Bytes)
				if e != nil {
					return e
				}
				if e = leaf.CheckSignatureFrom(ca); e != nil {
					return fmt.Errorf("HTTPS was issued by another CA; renew it with that CA instead of replacing trust")
				}
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return err
			}
			der, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				return err
			}
			cert, err := pki.SignServerCertificate(ca, caKey, dns, &key.PublicKey, years)
			if err != nil {
				return err
			}
			for name, data := range map[string][]byte{"server.crt": cert, "server.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), "ca.pem": caPEM} {
				if err = pki.SaveFile(filepath.Join(dir, name), data); err != nil {
					return err
				}
			}
			cfg.Server.TLS.Cert = filepath.Join(dir, "server.crt")
			cfg.Server.TLS.Key = filepath.Join(dir, "server.key")
			if err = cfg.ValidateWeb(); err != nil {
				return err
			}
			updates := []struct {
				path  []string
				value any
			}{{[]string{"server", "listen"}, cfg.Server.Listen}, {[]string{"server", "public_url"}, publicURL}, {[]string{"server", "http_redirect"}, cfg.Server.HTTPRedirect}, {[]string{"server", "tls", "cert"}, cfg.Server.TLS.Cert}, {[]string{"server", "tls", "key"}, cfg.Server.TLS.Key}}
			if keytab != "" {
				updates = append(updates, struct {
					path  []string
					value any
				}{[]string{"auth", "sso", "enabled"}, true}, struct {
					path  []string
					value any
				}{[]string{"auth", "sso", "keytab"}, cfg.Auth.SSO.Keytab}, struct {
					path  []string
					value any
				}{[]string{"auth", "sso", "principal"}, cfg.Auth.SSO.Principal}, struct {
					path  []string
					value any
				}{[]string{"auth", "sso", "realm"}, cfg.Auth.SSO.Realm})
			}
			for _, change := range updates {
				if err = configNodeSet(&document, change.value, change.path...); err != nil {
					return err
				}
			}
			var buf bytes.Buffer
			encoder := yaml.NewEncoder(&buf)
			encoder.SetIndent(2)
			if err = encoder.Encode(&document); err != nil {
				return err
			}
			encoder.Close()
			file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			if _, err = file.Write(buf.Bytes()); err != nil {
				file.Close()
				os.Remove(target)
				return err
			}
			if err = file.Sync(); err != nil {
				file.Close()
				os.Remove(target)
				return err
			}
			if err = file.Close(); err != nil {
				os.Remove(target)
				return err
			}
			keep = true
			block, _ := pem.Decode(cert)
			leaf, _ := x509.ParseCertificate(block.Bytes)
			fmt.Fprintf(cmd.OutOrStdout(), "HTTPS %s; действует до %s; сертификат ЦС: %s; кандидат конфигурации: %s\n", publicURL, leaf.NotAfter.Format("2006-01-02"), filepath.Join(dir, "ca.pem"), target)
			return nil
		}}
		cmd.Flags().StringVar(&dns, "dns", "", "HTTPS DNS name (default: current URL or sambaadm.DOMAIN)")
		cmd.Flags().StringVar(&listen, "listen", "", "HTTPS bind address (default 0.0.0.0:443)")
		cmd.Flags().IntVar(&years, "years", 10, "certificate lifetime: 1, 3, 5 or 10 years")
		cmd.Flags().StringVar(&output, "output", "", "new configuration candidate; never overwrites an existing file")
		cmd.Flags().StringVar(&keytab, "keytab", "", "enable SSO using a dedicated HTTP/FQDN keytab")
		cmd.Flags().StringVar(&realm, "sso-realm", "", "Kerberos realm for SSO")
		cmd.Flags().StringVar(&redirect, "http-redirect", "127.0.0.1:8080", "loopback HTTP redirect address (configure only)")
		certificates.AddCommand(cmd)
	}
	certificates.AddCommand(&cobra.Command{Use: "verify", Short: "Verify the running HTTPS listener against the configured certificate", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if err := verifyHTTPS(cmd.Context()); err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Сертификат HTTPS, DNS-имя и доверие: ОК")
		return nil
	}})
	rootCmd.AddCommand(certificates)
}
