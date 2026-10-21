package cli

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"sambaadm/internal/config"
)

// eventWriter keeps stderr available even when the disk becomes unwritable.
// TextHandler serializes writes; the mutex also protects direct concurrent use.
type eventWriter struct {
	mu     sync.Mutex
	stderr io.Writer
	file   io.Writer
	failed bool
}

func (w *eventWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.stderr.Write(p)
	if w.file != nil {
		_, fileErr := w.file.Write(p)
		if fileErr != nil && !w.failed {
			fmt.Fprintf(w.stderr, "sambaadm: event log write failed: %v\n", fileErr)
		}
		w.failed = fileErr != nil
	}
	return n, err
}

func newEventLogger(cfg *config.Config, level slog.Level, stderr io.Writer) (*slog.Logger, func() error, error) {
	w := &eventWriter{stderr: stderr}
	closeLog := func() error { return nil }
	if cfg.Logging.File != "" {
		path, err := filepath.Abs(cfg.Logging.File)
		if err != nil {
			return nil, nil, err
		}
		if cfg.Audit.File != "" {
			auditPath, err := filepath.Abs(cfg.Audit.File)
			if err != nil {
				return nil, nil, err
			}
			if path == auditPath {
				return nil, nil, fmt.Errorf("logging.file and audit.file must be different")
			}
		}
		// Check existing aliases before opening; do not mix event text into audit JSON.
		info, err := os.Stat(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, nil, err
		}
		if info != nil {
			if !info.Mode().IsRegular() {
				return nil, nil, fmt.Errorf("logging.file must be a regular file")
			}
			if auditInfo, e := os.Stat(cfg.Audit.File); e == nil && os.SameFile(info, auditInfo) {
				return nil, nil, fmt.Errorf("logging.file and audit.file refer to the same file")
			}
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, nil, fmt.Errorf("open event log: %w", err)
		}
		// Opening may resolve a previously dangling audit symlink.
		openedInfo, statErr := f.Stat()
		if statErr != nil {
			f.Close()
			return nil, nil, statErr
		}
		if auditInfo, e := os.Stat(cfg.Audit.File); e == nil && os.SameFile(openedInfo, auditInfo) {
			f.Close()
			return nil, nil, fmt.Errorf("logging.file and audit.file refer to the same file")
		}
		w.file = f
		closeLog = f.Close
	}
	// Defense in depth for service errors which may echo the bind password.
	opts := &slog.HandlerOptions{Level: level, ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		secret := cfg.BindPassword()
		if secret == "" {
			return a
		}
		if a.Value.Kind() == slog.KindString {
			a.Value = slog.StringValue(strings.ReplaceAll(a.Value.String(), secret, "<redacted>"))
		} else if e, ok := a.Value.Any().(error); ok {
			a.Value = slog.StringValue(strings.ReplaceAll(e.Error(), secret, "<redacted>"))
		}
		return a
	}}
	return slog.New(slog.NewTextHandler(w, opts)), closeLog, nil
}
