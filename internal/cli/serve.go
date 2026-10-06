package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
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
	listen  string
	tlsCert string
	tlsKey  string
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

		level := slog.LevelInfo
		switch cfg.Logging.Level {
		case "debug":
			level = slog.LevelDebug
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

		auditLog, err := audit.New(cfg.Audit.File)
		if err != nil {
			return fmt.Errorf("audit logger: %w", err)
		}
		defer auditLog.Close()

		ldapClient := ldapproto.NewClient(cfg.LDAP)
		svcs := service.NewWithOptions(ldapClient, auditLog, service.ServiceOptions{GPO: cfg.GPO, Samba: cfg.Samba})
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

		errCh := make(chan error, 1)
		go func() {
			slog.Info("sambaadm listening", "addr", cfg.Server.Listen)
			var serveErr error
			if cfg.Server.TLS.Cert != "" && cfg.Server.TLS.Key != "" {
				serveErr = httpSrv.ListenAndServeTLS(cfg.Server.TLS.Cert, cfg.Server.TLS.Key)
			} else {
				serveErr = httpSrv.ListenAndServe()
			}
			if serveErr != nil && serveErr != http.ErrServerClosed {
				errCh <- serveErr
			}
			close(errCh)
		}()

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

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
	serveCmd.Flags().StringVar(&listen, "listen", "", "listen address (default :8080)")
	serveCmd.Flags().StringVar(&tlsCert, "tls-cert", "", "TLS certificate file")
	serveCmd.Flags().StringVar(&tlsKey, "tls-key", "", "TLS private key file")
}
