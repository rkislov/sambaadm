package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Event is a single audited action.
type Event struct {
	Time       time.Time `json:"time"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Target     string    `json:"target,omitempty"`
	IP         string    `json:"ip,omitempty"`
	Result     string    `json:"result"` // success | failure
	Error      string    `json:"error,omitempty"`
	Details    any       `json:"details,omitempty"`
	Role       string    `json:"role,omitempty"`
	Method     string    `json:"method,omitempty"`
	HTTPStatus int       `json:"http_status,omitempty"`
	DurationMS int64     `json:"duration_ms,omitempty"`
}

// Logger writes audit events as JSON lines.
type Logger struct {
	mu           sync.Mutex
	w            io.Writer
	closer       io.Closer
	path         string
	slog         *slog.Logger
	syslog       *cefSyslog
	host         string
	closed       bool
	lastOverflow time.Time
	// mem keeps recent events when writing to stderr (no file).
	mem []Event
}

// New creates an audit logger. If path is empty, events go to stderr via slog.
func New(path string) (*Logger, error) {
	return NewWithSyslog(path, SyslogConfig{})
}

// NewWithSyslog keeps the local journal and optionally forwards CEF events.
func NewWithSyslog(path string, config SyslogConfig) (*Logger, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	l := &Logger{slog: slog.Default(), path: path}
	if path == "" {
		l.w = os.Stderr
	} else {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		l.w = f
		l.closer = f
	}
	if config.Enabled {
		l.host = cefHost()
		l.syslog = newCEFSyslog(config, l.slog)
	}
	return l, nil
}

// Path returns the configured audit file path (may be empty).
func (l *Logger) Path() string { return l.path }

// Close closes the underlying file if any.
func (l *Logger) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()
	if l.syslog != nil {
		l.syslog.close()
	}
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

	if l.closed {
		return
	}

	if l.path == "" {
		l.mem = append(l.mem, e)
		if len(l.mem) > 500 {
			l.mem = l.mem[len(l.mem)-500:]
		}
	}

	enc := json.NewEncoder(l.w)
	if err := enc.Encode(e); err != nil {
		l.slog.Error("audit write failed", "err", err)
	}
	if l.syslog != nil {
		select {
		case l.syslog.queue <- cefMessage(e, l.syslog.config.Network, l.host):
		default:
			if time.Since(l.lastOverflow) >= time.Minute {
				l.slog.Warn("audit syslog queue full")
				l.lastOverflow = time.Now()
			}
		}
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

// Recent returns up to limit newest events (newest last).
func (l *Logger) Recent(limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.path == "" {
		if len(l.mem) <= limit {
			out := make([]Event, len(l.mem))
			copy(out, l.mem)
			return out, nil
		}
		out := make([]Event, limit)
		copy(out, l.mem[len(l.mem)-limit:])
		return out, nil
	}

	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	end := info.Size()
	var all []Event
	start := end
	var chunk [64 * 1024]byte
	lines := 0
	for start > 0 {
		offset := max(0, start-int64(len(chunk)))
		b := chunk[:start-offset]
		if _, err := f.ReadAt(b, offset); err != nil {
			return nil, err
		}
		lines += bytes.Count(b, []byte{'\n'})
		start = offset
		if offset > 0 && lines > limit {
			start += int64(bytes.IndexByte(b, '\n')) + 1
			break
		}
	}
	sc := bufio.NewScanner(io.NewSectionReader(f, start, end-start))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		all = append(all, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, nil
}
