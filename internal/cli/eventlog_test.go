package cli

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sambaadm/internal/config"
)

func TestEventLogAppendLevelAndSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.log")
	t.Setenv("EVENT_LOG_TEST_SECRET", "private-bind-password")
	cfg := &config.Config{Logging: config.LoggingConfig{File: path}, LDAP: config.LDAPConfig{Bind: config.BindConfig{PasswordEnv: "EVENT_LOG_TEST_SECRET"}}}
	var stderr bytes.Buffer
	for i := 0; i < 2; i++ {
		logger, closeLog, err := newEventLogger(cfg, slog.LevelInfo, &stderr)
		if err != nil {
			t.Fatal(err)
		}
		logger.Info("started")
		logger.Debug("hidden-debug")
		logger.Error("failed", "err", errors.New("remote echoed private-bind-password"))
		if err := closeLog(); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != stderr.String() || strings.Count(string(data), "msg=started") != 2 || strings.Contains(string(data), "hidden-debug") || strings.Contains(string(data), "private-bind-password") || !strings.Contains(string(data), "<redacted>") {
		t.Fatalf("bad log: %s", data)
	}
	info, _ := os.Stat(path)
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v", info.Mode())
	}
}

func TestEventLogRejectsAuditAliasesAndInvalidDestination(t *testing.T) {
	dir := t.TempDir()
	audit := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(audit, []byte("audit stays intact\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{audit, dir, filepath.Join(dir, "missing", "events.log")} {
		cfg := &config.Config{Audit: config.AuditConfig{File: audit}, Logging: config.LoggingConfig{File: path}}
		if _, closeLog, err := newEventLogger(cfg, slog.LevelInfo, &bytes.Buffer{}); err == nil {
			closeLog()
			t.Fatalf("accepted %s", path)
		}
	}
	alias := filepath.Join(dir, "alias.log")
	if err := os.Link(audit, alias); err == nil {
		cfg := &config.Config{Audit: config.AuditConfig{File: audit}, Logging: config.LoggingConfig{File: alias}}
		if _, closeLog, err := newEventLogger(cfg, slog.LevelInfo, &bytes.Buffer{}); err == nil {
			closeLog()
			t.Fatal("accepted audit alias")
		}
	}
	data, _ := os.ReadFile(audit)
	if string(data) != "audit stays intact\n" {
		t.Fatal("audit was changed")
	}
}

type failingEventSink struct{}

func (failingEventSink) Write(p []byte) (int, error) { return 0, errors.New("disk full") }
func TestEventLogDiskFailurePreservesStderr(t *testing.T) {
	var stderr bytes.Buffer
	w := &eventWriter{stderr: &stderr, file: failingEventSink{}}
	for i := 0; i < 2; i++ {
		if _, err := w.Write([]byte("event\n")); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Count(stderr.String(), "event\n") != 2 || strings.Count(stderr.String(), "event log write failed") != 1 {
		t.Fatal(stderr.String())
	}
}

func TestServeStartupErrorWrittenToFile(t *testing.T) {
	oldCfg := rootCfg
	oldCheck := checkStartup
	oldListen, oldCert, oldKey := listen, tlsCert, tlsKey
	defer func() {
		rootCfg = oldCfg
		checkStartup = oldCheck
		listen, tlsCert, tlsKey = oldListen, oldCert, oldKey
	}()
	checkStartup = false
	listen = ""
	tlsCert = ""
	tlsKey = ""
	path := filepath.Join(t.TempDir(), "events.log")
	rootCfg = &config.Config{Logging: config.LoggingConfig{File: path}, Server: config.ServerConfig{TLS: config.TLSConfig{Cert: "missing-cert"}}}
	if err := serveCmd.RunE(serveCmd, nil); err == nil {
		t.Fatal("expected TLS config error")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "sambaadm starting") || !strings.Contains(string(data), "server stopped with error") || !strings.Contains(string(data), "HTTP TLS requires both") {
		t.Fatal(string(data))
	}
}

func TestEventLogRejectsDanglingAuditSymlink(t *testing.T) {
	dir := t.TempDir()
	event := filepath.Join(dir, "events.log")
	audit := filepath.Join(dir, "audit.log")
	if err := os.Symlink(event, audit); err != nil {
		t.Skip(err)
	}
	cfg := &config.Config{Logging: config.LoggingConfig{File: event}, Audit: config.AuditConfig{File: audit}}
	if _, closeLog, err := newEventLogger(cfg, slog.LevelInfo, &bytes.Buffer{}); err == nil {
		closeLog()
		t.Fatal("mixed log destinations")
	}
}
