package audit

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"sambaadm/internal/version"
)

// SyslogConfig controls optional delivery of audit events as CEF.
type SyslogConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Network string `mapstructure:"network"`
	Address string `mapstructure:"address"`
}

func (c SyslogConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	switch c.Network {
	case "unixgram":
		if !filepath.IsAbs(c.Address) {
			return fmt.Errorf("audit.syslog.address must be an absolute socket path for unixgram")
		}
	case "udp", "tcp", "tls":
		host, port, err := net.SplitHostPort(c.Address)
		n, parseErr := strconv.Atoi(port)
		if err != nil || parseErr != nil || host == "" || n < 1 || n > 65535 {
			return fmt.Errorf("audit.syslog.address must contain a host and port for %s", c.Network)
		}
	default:
		return fmt.Errorf("audit.syslog.network must be unixgram, udp, tcp or tls")
	}
	return nil
}

type cefSyslog struct {
	config SyslogConfig
	queue  chan string
	done   chan struct{}
	cancel context.CancelFunc
	warn   func(string, error)
}

func newCEFSyslog(config SyslogConfig, log *slog.Logger) *cefSyslog {
	ctx, cancel := context.WithCancel(context.Background())
	var last time.Time
	s := &cefSyslog{
		config: config,
		queue:  make(chan string, 1024),
		done:   make(chan struct{}),
		cancel: cancel,
		warn: func(message string, err error) {
			log.Warn(message, "error", err)
		},
	}
	go s.run(ctx, func(err error) {
		if time.Since(last) >= time.Minute {
			s.warn("audit syslog delivery failed", err)
			last = time.Now()
		}
	})
	return s
}

func (s *cefSyslog) close() {
	close(s.queue)
	defer s.cancel()
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		s.warn("audit syslog flush timed out", context.DeadlineExceeded)
	}
}

func (s *cefSyslog) run(ctx context.Context, deliveryError func(error)) {
	defer close(s.done)
	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	var nextDial time.Time
	for message := range s.queue {
		if ctx.Err() != nil {
			return
		}
		if conn == nil {
			if time.Now().Before(nextDial) {
				continue
			}
			var err error
			conn, err = s.dial(ctx)
			if err != nil {
				deliveryError(err)
				nextDial = time.Now().Add(time.Second)
				continue
			}
		}
		if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			deliveryError(err)
		} else if _, err := io.WriteString(conn, message); err == nil {
			continue
		} else {
			deliveryError(err)
		}
		_ = conn.Close()
		conn = nil
	}
}

func (s *cefSyslog) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: time.Second}
	if s.config.Network == "tls" {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{MinVersion: tls.VersionTLS12},
		}
		return tlsDialer.DialContext(ctx, "tcp", s.config.Address)
	}
	return dialer.DialContext(ctx, s.config.Network, s.config.Address)
}

var cefHeaderEscape = strings.NewReplacer("\\", "\\\\", "|", "\\|", "\r", " ", "\n", " ")
var cefFieldEscape = strings.NewReplacer("\\", "\\\\", "=", "\\=", "\r", "\\r", "\n", "\\n")

func cefText(value string, maxBytes int) string {
	var clean strings.Builder
	for _, ch := range value {
		if unicode.IsControl(ch) && ch != '\r' && ch != '\n' {
			continue
		}
		if clean.Len()+utf8.RuneLen(ch) > maxBytes {
			break
		}
		clean.WriteRune(ch)
	}
	return clean.String()
}

func cefHost() string {
	name, _ := os.Hostname()
	if len(name) == 0 || len(name) > 255 || strings.ContainsFunc(name, func(ch rune) bool {
		return ch < 33 || ch > 126
	}) {
		return "-"
	}
	return name
}

func cefMessage(e Event, network, hostname string) string {
	severity, syslogSeverity := 1, 6
	if e.Result == "failure" {
		severity, syslogSeverity = 5, 4
	}
	if e.HTTPStatus >= 500 {
		severity, syslogSeverity = 7, 3
	}

	var extension strings.Builder
	field := func(key, value string) {
		if value == "" {
			return
		}
		if extension.Len() != 0 {
			extension.WriteByte(' ')
		}
		extension.WriteString(key)
		extension.WriteByte('=')
		extension.WriteString(cefFieldEscape.Replace(cefText(value, 255)))
	}
	field("rt", strconv.FormatInt(e.Time.UnixMilli(), 10))
	field("suser", e.Actor)
	field("act", e.Action)
	field("outcome", e.Result)
	peer := e.IP
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	if ip, err := netip.ParseAddr(peer); err == nil {
		key := "src"
		if ip.Unmap().Is6() {
			key = "c6a1"
			field("c6a1Label", "Source IPv6")
		}
		field(key, ip.Unmap().WithZone("").String())
	}
	if e.Role != "" {
		field("cs1Label", "Role")
		field("cs1", e.Role)
	}
	if e.Method != "" {
		field("requestMethod", e.Method)
	}
	if e.HTTPStatus > 0 {
		field("cn1Label", "HTTP Status")
		field("cn1", strconv.Itoa(e.HTTPStatus))
		field("cn2Label", "Duration ms")
		field("cn2", strconv.FormatInt(e.DurationMS, 10))
	}
	if e.Action == "web.request" {
		field("request", e.Target)
	}

	action := cefHeaderEscape.Replace(cefText(e.Action, 63))
	release := cefHeaderEscape.Replace(cefText(version.Version, 31))
	cef := fmt.Sprintf("CEF:0|sambaadm|sambaadm|%s|%s|%s|%d|%s", release, action, action, severity, extension.String())
	priority := 16*8 + syslogSeverity // local0
	if network == "unixgram" {
		// The local /dev/log socket accepts the legacy syslog application tag.
		return fmt.Sprintf("<%d>sambaadm[%d]: %s", priority, os.Getpid(), cef)
	}
	message := fmt.Sprintf("<%d>1 %s %s sambaadm %d - - %s", priority,
		e.Time.UTC().Format("2006-01-02T15:04:05.000000Z"), hostname, os.Getpid(), cef)
	if network == "tcp" || network == "tls" {
		return strconv.Itoa(len(message)) + " " + message
	}
	return message
}
