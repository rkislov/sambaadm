package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
	"sambaadm/internal/web"
)

var (
	listen       string
	tlsCert      string
	tlsKey       string
	checkStartup bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the web UI and REST API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := rootCfg
		if listen != "" {
			cfg.Server.Listen = listen
		}
		if tlsCert != "" {
			cfg.Server.TLS.Cert = tlsCert
		}
		if tlsKey != "" {
			cfg.Server.TLS.Key = tlsKey
		}

		if checkStartup {
			cfg.Logging.Level = "debug"
		}
		level := slog.LevelInfo
		switch strings.ToLower(cfg.Logging.Level) {
		case "", "info":
		case "debug":
			level = slog.LevelDebug
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		default:
			return fmt.Errorf("invalid logging.level %q (debug, info, warn, error)", cfg.Logging.Level)
		}
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

		ldapClient := ldapproto.NewServiceClient(cfg.LDAP, cfg.BindPassword)
		defer ldapClient.Close()
		if level == slog.LevelDebug {
			diagnosticErr := startupDiagnostics(cfg, ldapClient)
			if checkStartup {
				return diagnosticErr
			}
			if diagnosticErr != nil {
				slog.Warn("web server will start with unavailable domain operations", "hint", "correct configuration and retry; --check exits with failure for these errors")
			}
		}
		if (cfg.Server.TLS.Cert == "") != (cfg.Server.TLS.Key == "") {
			return fmt.Errorf("HTTP TLS requires both --tls-cert and --tls-key")
		}
		auditLog, err := audit.New(cfg.Audit.File)
		if err != nil {
			return fmt.Errorf("audit logger: %w", err)
		}
		defer auditLog.Close()

		svcs := service.NewWithOptions(ldapClient, auditLog, service.ServiceOptions{ToolUser: cfg.LDAP.Bind.User, ToolPassword: cfg.BindPassword, GPO: cfg.GPO, Samba: cfg.Samba})
		sessions := auth.NewStore(cfg.Auth.SessionTTL)
		rbac := auth.NewRBAC(cfg.Auth.Roles)

		srv, err := web.New(web.Options{
			Config:   cfg,
			Services: svcs,
			Sessions: sessions,
			RBAC:     rbac,
			LDAP:     ldapClient,
			Audit:    auditLog,
		})
		if err != nil {
			return err
		}

		httpSrv := &http.Server{
			Addr:              cfg.Server.Listen,
			Handler:           srv.Router(),
			ReadHeaderTimeout: 10 * time.Second,
		}

		// Bind before announcing readiness: an occupied port must never look healthy.
		var tlsConfig *tls.Config
		if cfg.Server.TLS.Cert != "" {
			cert, e := tls.LoadX509KeyPair(cfg.Server.TLS.Cert, cfg.Server.TLS.Key)
			if e != nil {
				return fmt.Errorf("load HTTP TLS certificate: %w", e)
			}
			tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		}
		listener, err := net.Listen("tcp", cfg.Server.Listen)
		if err != nil {
			return fmt.Errorf("listen %s: %w", cfg.Server.Listen, err)
		}
		defer listener.Close()
		scheme := "http"
		if tlsConfig != nil {
			listener = tls.NewListener(listener, tlsConfig)
			scheme = "https"
		}
		slog.Info("sambaadm listening", "addr", listener.Addr().String(), "scheme", scheme)
		errCh := make(chan error, 1)
		go func() {
			serveErr := httpSrv.Serve(listener)
			if serveErr != nil && serveErr != http.ErrServerClosed {
				errCh <- serveErr
			}
			close(errCh)
		}()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigCh)

		select {
		case sig := <-sigCh:
			slog.Info("shutdown signal", "signal", sig.String())
		case err := <-errCh:
			if err != nil {
				return err
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = ldapClient.Close()
		return httpSrv.Shutdown(ctx)
	},
}

func init() {
	serveCmd.Flags().BoolVar(&checkStartup, "check", false, "check configuration, dependencies and LDAP then exit without starting HTTP")
	serveCmd.Flags().StringVar(&listen, "listen", "", "listen address (default :8080)")
	serveCmd.Flags().StringVar(&tlsCert, "tls-cert", "", "TLS certificate file")
	serveCmd.Flags().StringVar(&tlsKey, "tls-key", "", "TLS private key file")
}
