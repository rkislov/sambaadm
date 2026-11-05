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
		return fmt.Errorf("usage: sambaadm-helper stdio|serve|keygen|collect [options]")
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
	if mode != "stdio" && mode != "serve" && mode != "collect" {
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
	if mode == "collect" {
		if *out == "" {
			return fmt.Errorf("collect requires --out FILE")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		survey, err := service.CollectNodeSurvey(ctx, cfg, *site)
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
