package audit

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Event is a single audited action.
type Event struct {
	Time     time.Time `json:"time"`
	Actor    string    `json:"actor"`
	Action   string    `json:"action"`
	Target   string    `json:"target,omitempty"`
	IP       string    `json:"ip,omitempty"`
	Result   string    `json:"result"` // success | failure
	Error    string    `json:"error,omitempty"`
	Details  any       `json:"details,omitempty"`
}

// Logger writes audit events as JSON lines.
type Logger struct {
	mu     sync.Mutex
	w      io.Writer
	closer io.Closer
	slog   *slog.Logger
}

// New creates an audit logger. If path is empty, events go to stderr via slog.
func New(path string) (*Logger, error) {
	l := &Logger{slog: slog.Default()}
	if path == "" {
		l.w = os.Stderr
		return l, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	l.w = f
	l.closer = f
	return l, nil
}

// Close closes the underlying file if any.
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// Log writes an audit event.
func (l *Logger) Log(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	enc := json.NewEncoder(l.w)
	if err := enc.Encode(e); err != nil {
		l.slog.Error("audit write failed", "err", err)
	}
}

// Success is a convenience for successful mutating ops.
func (l *Logger) Success(actor, action, target, ip string) {
	l.Log(Event{Actor: actor, Action: action, Target: target, IP: ip, Result: "success"})
}

// Failure is a convenience for failed mutating ops.
func (l *Logger) Failure(actor, action, target, ip string, err error) {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	l.Log(Event{Actor: actor, Action: action, Target: target, IP: ip, Result: "failure", Error: msg})
}
