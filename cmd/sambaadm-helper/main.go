package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/service"
	"sambaadm/internal/version"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: sambaadm-helper stdio|serve|keygen|collect|domain-restore-plan|domain-restore|domain-restore-status [options]")
	}
	mode := os.Args[1]
	if mode == "version" {
		fmt.Println(version.String())
		return nil
	}
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	filename := flags.String("config", "/etc/sambaadm-helper/config.yaml", "root-owned helper configuration")
	private := flags.String("private", "", "new signing private key path")
	public := flags.String("public", "", "new trusted public key path")
	out := flags.String("out", "", "new survey JSON file")
	profile := flags.String("profile", "node", "node or alt-workstation")
	dnsResolvers := flags.String("dns-resolvers", "", "comma-separated resolver IPs (up to 4, workstation only)")
	dnsQueries := flags.String("dns-queries", "", "comma-separated FQDN/TYPE queries (up to 8, workstation only)")
	account := flags.String("account", "", "optional cached SSSD account for alt-workstation")
	restoreBackup := flags.String("backup-id", "", "cold backup UUID for domain recovery")
	restoreName := flags.String("new-name", "", "new DC NetBIOS name for forest recovery")
	restoreAddress := flags.String("address", "", "new DC IPv4 address")
	restoreID := flags.String("id", "", "prepared recovery UUID")
	restoreRevision := flags.String("revision", "", "reviewed recovery plan revision")
	confirmLost := flags.Bool("confirm-domain-lost", false, "confirm full domain loss and shutdown of all former DCs")
	confirmIsolated := flags.Bool("confirm-isolated", false, "confirm recovery host is isolated and compatible Samba is installed")
	site := flags.String("site", "", "operator-supplied site label")
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected helper arguments")
	}
	if mode == "keygen" {
		if *private == "" || *public == "" {
			return fmt.Errorf("keygen requires --private and --public")
		}
		return agent.GenerateKey(*private, *public)
	}
	recoveryMode := mode == "domain-restore-plan" || mode == "domain-restore" || mode == "domain-restore-status"
	if mode != "stdio" && mode != "serve" && mode != "collect" && !recoveryMode {
		return fmt.Errorf("unsupported helper command")
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("privileged sambaadm-helper host operations require Linux")
	}
	cfg, e := config.Load(*filename)
	if e != nil {
		return e
	}
	if cfg.Source == "" {
		return fmt.Errorf("explicit helper configuration required")
	}
	if e = checkHelperConfig(cfg.Source); e != nil {
		return e
	}
	if recoveryMode {
		if os.Geteuid() != 0 {
			return fmt.Errorf("local domain recovery requires root")
		}
		logger, err := audit.New(cfg.Audit.File)
		if err != nil {
			return err
		}
		defer logger.Close()
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		input := service.DomainRestoreInput{BackupID: *restoreBackup, NewName: *restoreName, Address: *restoreAddress, ID: *restoreID, Revision: *restoreRevision, ConfirmDomainLost: *confirmLost, ConfirmIsolated: *confirmIsolated}
		method := "domain.restore.plan"
		if mode == "domain-restore" {
			method = "domain.restore.start"
		}
		if mode == "domain-restore-status" {
			method = "domain.restore.status"
		}
		raw, err := json.Marshal(input)
		if err != nil {
			return err
		}
		operation, err := json.Marshal(service.HostOperation{Name: *restoreID, Input: raw})
		if err != nil {
			return err
		}
		result, err := (&service.Services{Audit: logger}).HelperDispatch(ctx, cfg, method, operation)
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	if mode == "collect" {
		if *out == "" {
			return fmt.Errorf("collect requires --out FILE")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		var survey *service.NodeSurvey
		var err error
		switch *profile {
		case "alt-workstation":
			survey, err = service.CollectWorkstationSurveyWithOptions(ctx, cfg, *site, *account, service.WorkstationSurveyOptions{Resolvers: commaList(*dnsResolvers), Queries: commaList(*dnsQueries)})
		case "node":
			if *account != "" || *dnsResolvers != "" || *dnsQueries != "" {
				return fmt.Errorf("--account and DNS survey options require --profile alt-workstation")
			}
			survey, err = service.CollectNodeSurvey(ctx, cfg, *site)
		default:
			return fmt.Errorf("unknown survey profile %q", *profile)
		}
		if err != nil {
			return err
		}
		blob, err := json.MarshalIndent(survey, "", "  ")
		if err != nil {
			return err
		}
		if len(blob) > service.SurveyLimit {
			return fmt.Errorf("survey exceeds import limit")
		}
		f, err := os.CreateTemp(filepath.Dir(*out), ".survey-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		_, err = f.Write(blob)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		return os.Link(f.Name(), *out)
	}
	v, e := agent.NewVerifier(cfg.Helper.Node, cfg.Helper.TrustedKeys)
	if e != nil {
		return e
	}
	if e = v.UseStateDir(cfg.Helper.StateDir); e != nil {
		return e
	}
	logger, e := audit.New(cfg.Audit.File)
	if e != nil {
		return e
	}
	defer logger.Close()
	password := cfg.BindPassword
	if cfg.Helper.PasswordFile != "" {
		st, e := os.Lstat(cfg.Helper.PasswordFile)
		if e != nil {
			return e
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
			return fmt.Errorf("helper domain password file must be private (0600)")
		}
		raw, e := os.ReadFile(cfg.Helper.PasswordFile)
		if e != nil {
			return e
		}
		secret := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
		password = func() string { return secret }
	}
	client := ldapproto.NewServiceClient(cfg.LDAP, password)
	defer client.Close()
	services := service.NewWithOptions(client, logger, service.ServiceOptions{Username: cfg.LDAP.Bind.User, Password: password, GPO: cfg.GPO, Samba: cfg.Samba})
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	handler := func(ctx context.Context, method string, raw json.RawMessage) (any, error) {
		return services.HelperDispatch(ctx, cfg, method, raw)
	}
	if mode == "stdio" {
		return agent.Stdio(ctx, os.Stdin, os.Stdout, v, handler)
	}
	if cfg.Helper.Listen == "" || cfg.Helper.TLS.Cert == "" || cfg.Helper.TLS.Key == "" {
		return fmt.Errorf("HTTPS helper requires helper.listen, tls.cert and tls.key")
	}
	srv := &http.Server{Addr: cfg.Helper.Listen, Handler: agent.API(v, handler), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	slog.Info("sambaadm-helper listening", "node", cfg.Helper.Node, "address", cfg.Helper.Listen)
	e = srv.ListenAndServeTLS(cfg.Helper.TLS.Cert, cfg.Helper.TLS.Key)
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}

func commaList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
