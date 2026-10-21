package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/version"
)

// Only an explicit allowlist is logged. Never dump argv, environment or Config.
func diagnosticURI(raw string) string {
	if strings.HasPrefix(raw, "ldapi://") {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid LDAP URI>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
func startupDiagnostics(cfg *config.Config, client *ldapproto.Client) error {
	source := cfg.Source
	if source == "" {
		source = "defaults + environment (no config file)"
	}
	cwd, _ := os.Getwd()
	slog.Debug("startup configuration", "version", version.String(), "platform", runtime.GOOS+"/"+runtime.GOARCH, "config", source, "cwd", cwd, "pid", os.Getpid(), "listen", cfg.Server.Listen, "log_level", cfg.Logging.Level, "http_tls", cfg.Server.TLS.Cert != "" && cfg.Server.TLS.Key != "", "tls_cert", cfg.Server.TLS.Cert, "tls_key_configured", cfg.Server.TLS.Key != "", "audit_file", cfg.Audit.File)
	slog.Debug("LDAP configuration", "uri", diagnosticURI(cfg.LDAP.URI), "base_dn", cfg.LDAP.BaseDN, "ca_cert", cfg.LDAP.CACert, "bind_type", cfg.LDAP.Bind.Type, "bind_user", cfg.LDAP.Bind.User, "password_env", cfg.LDAP.Bind.PasswordEnv, "password_set", cfg.BindPassword() != "")
	slog.Debug("feature configuration", "smb_conf", cfg.Samba.SMBConf, "gpo_transport", "SMB", "smb_port", cfg.GPO.SMBPort, "gpo_editor", cfg.GPO.EditorEnabled, "admx", cfg.GPO.ADMXPath, "gpo_sync_mode", cfg.GPO.SyncMode, "session_ttl", cfg.Auth.SessionTTL)

	var problems []string
	if cfg.LDAP.BaseDN == "" {
		problems = append(problems, "LDAP base DN missing: set ldap.base_dn or SAMBAADM_LDAP_BASE_DN")
	}
	if cfg.LDAP.Bind.User == "" {
		problems = append(problems, "LDAP service account missing: set ldap.bind.user or --user")
	}
	if cfg.BindPassword() == "" {
		problems = append(problems, "LDAP service password missing: set the environment variable named by ldap.bind.password_env")
	}
	if cfg.LDAP.Bind.Type != "" && cfg.LDAP.Bind.Type != "simple" {
		problems = append(problems, "LDAP service bind supports only type simple")
	}
	if len(problems) > 0 {
		for _, p := range problems {
			slog.Error("startup check failed", "reason", p)
		}
		return fmt.Errorf("startup LDAP configuration checks failed (%d problems)", len(problems))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		// Replace configured secrets even if a remote LDAP error echoes them.
		reason := strings.ReplaceAll(err.Error(), cfg.BindPassword(), "<redacted>")
		reason = strings.ReplaceAll(reason, cfg.LDAP.URI, diagnosticURI(cfg.LDAP.URI))
		slog.Error("LDAP connect/bind failed", "reason", reason, "hint", "check DNS, port/socket, certificate trust and service credentials")
		return fmt.Errorf("LDAP connect/bind failed: %s", reason)
	}
	_, err := client.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: cfg.LDAP.BaseDN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"dn"}})
	if err != nil {
		reason := strings.ReplaceAll(err.Error(), cfg.BindPassword(), "<redacted>")
		slog.Error("LDAP base DN check failed", "reason", reason, "hint", "check base DN and service account read permissions")
		return fmt.Errorf("LDAP base DN check failed: %s", reason)
	}
	slog.Info("startup LDAP checks passed", "base_dn", cfg.LDAP.BaseDN)
	return nil
}
