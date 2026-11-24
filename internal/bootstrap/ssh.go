// Package bootstrap performs explicitly approved, host-key-pinned SSH setup.
package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func dial(ctx context.Context, host string, port int, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	conn, e := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if e != nil {
		return nil, e
	}
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	cc, ch, req, e := ssh.NewClientConn(conn, net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if e != nil {
		conn.Close()
		return nil, e
	}
	conn.SetDeadline(time.Time{})
	return ssh.NewClient(cc, ch, req), nil
}
func Probe(ctx context.Context, host string, port int) (string, error) {
	fingerprint := ""
	_, e := dial(ctx, host, port, &ssh.ClientConfig{User: "sambaadm-key-check", HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fingerprint = ssh.FingerprintSHA256(key)
		return fmt.Errorf("host key collected")
	}})
	if fingerprint != "" {
		return fingerprint, nil
	}
	return "", e
}
func Dial(ctx context.Context, host string, port int, user, password, fingerprint string) (*ssh.Client, error) {
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return nil, fmt.Errorf("не подтверждён ключ SSH")
	}
	return dial(ctx, host, port, &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(password), ssh.KeyboardInteractive(func(_, _ string, questions []string, echo []bool) ([]string, error) {
		if len(questions) > 2 {
			return nil, fmt.Errorf("неподдерживаемый запрос SSH")
		}
		answers := make([]string, len(questions))
		for i, q := range questions {
			if echo[i] || !strings.Contains(strings.ToLower(q), "password") {
				return nil, fmt.Errorf("нужна интерактивная аутентификация SSH")
			}
			answers[i] = password
		}
		return answers, nil
	})}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != fingerprint {
			return fmt.Errorf("ключ SSH изменился; проверьте контроллер заново")
		}
		return nil
	}})
}

type capped struct {
	bytes.Buffer
	mu    sync.Mutex
	limit int
}

func (b *capped) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Len()+len(p) > b.limit {
		return 0, fmt.Errorf("вывод команды превышает лимит")
	}
	return b.Buffer.Write(p)
}
func run(ctx context.Context, client *ssh.Client, command string, input io.Reader) (string, error) {
	s, e := client.NewSession()
	if e != nil {
		return "", e
	}
	defer s.Close()
	out := &capped{limit: 512 << 10}
	s.Stdout = out
	s.Stderr = out
	s.Stdin = input
	done := make(chan error, 1)
	go func() { done <- s.Run(command) }()
	select {
	case e = <-done:
	case <-ctx.Done():
		client.Close()
		s.Close()
		<-done
		e = ctx.Err()
	}
	return out.String(), e
}
func Run(ctx context.Context, client *ssh.Client, command string) (string, error) {
	return run(ctx, client, command, nil)
}
func Copy(ctx context.Context, client *ssh.Client, path string, data []byte) error {
	_, e := run(ctx, client, "umask 077; cat > "+Quote(path), bytes.NewReader(data))
	return e
}

type suOutput struct {
	mu       sync.Mutex
	output   bytes.Buffer
	pending  string
	sent     bool
	input    io.Writer
	password string
	log      func(string)
}

func (b *suOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.output.Len()+len(p) > 512<<10 {
		return 0, fmt.Errorf("вывод установки превышает лимит")
	}
	b.output.Write(p)
	b.pending += string(p)
	if !b.sent && strings.Contains(strings.ToLower(b.pending), "password:") {
		b.sent = true
		b.pending = strings.ReplaceAll(b.pending, "Password:", "")
		b.pending = strings.ReplaceAll(b.pending, "password:", "")
		if _, e := io.WriteString(b.input, b.password+"\n"); e != nil {
			return 0, e
		}
	}
	for {
		i := strings.IndexByte(b.pending, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSpace(b.pending[:i])
		b.pending = b.pending[i+1:]
		if b.log != nil && line != "" {
			b.log(line)
		}
	}
	return len(p), nil
}

// Su sends the password over the PTY input after the prompt, never in argv or
// the script. Raw output must be redacted by the caller before recording it.
func Su(ctx context.Context, client *ssh.Client, script, password string, log func(string)) (string, error) {
	s, e := client.NewSession()
	if e != nil {
		return "", e
	}
	defer s.Close()
	if e = s.RequestPty("dumb", 40, 120, ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}); e != nil {
		return "", fmt.Errorf("не удалось отключить эхо терминала: %w", e)
	}
	in, e := s.StdinPipe()
	if e != nil {
		return "", e
	}
	out := &suOutput{input: in, password: password, log: log}
	s.Stdout = out
	s.Stderr = out
	done := make(chan error, 1)
	go func() { done <- s.Run("LC_ALL=C su - -c " + Quote(script)) }()
	select {
	case e = <-done:
	case <-ctx.Done():
		client.Close()
		s.Close()
		<-done
		e = ctx.Err()
	}
	out.mu.Lock()
	defer out.mu.Unlock()
	if out.pending != "" && log != nil {
		log(strings.TrimSpace(out.pending))
	}
	return strings.ReplaceAll(strings.ReplaceAll(out.output.String(), "Password: ", ""), "Password:", ""), e
}
