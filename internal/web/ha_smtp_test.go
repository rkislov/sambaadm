package web

import (
	"bytes"
	"context"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

type capturedHAMail struct {
	To        string `json:"to"`
	Subject   string `json:"subject"`
	MessageID string `json:"messageID"`
	Body      string `json:"body"`
}

type haSMTPSink struct {
	port     int
	mu       sync.Mutex
	received []capturedHAMail
}

func (sink *haSMTPSink) snapshot() []capturedHAMail {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]capturedHAMail{}, sink.received...)
}

func startHASMTPSink(t *testing.T, dropAck bool) *haSMTPSink {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	sink := &haSMTPSink{port: listener.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			wire, err := listener.Accept()
			if err != nil {
				return
			}
			go sink.receive(wire, dropAck)
		}
	}()
	return sink
}

func (sink *haSMTPSink) receive(wire net.Conn, dropAck bool) {
	defer wire.Close()
	_ = wire.SetDeadline(time.Now().Add(8 * time.Second))
	conn := textproto.NewConn(wire)
	_ = conn.PrintfLine("220 capture.invalid SMTP")
	var to string
	for {
		line, err := conn.ReadLine()
		if err != nil {
			return
		}
		command, value, _ := strings.Cut(line, " ")
		response := "250 OK"
		switch strings.ToUpper(command) {
		case "EHLO", "HELO":
			response = "250 capture.invalid"
		case "MAIL":
		case "RCPT":
			to = strings.Trim(strings.TrimPrefix(value, "TO:"), "<>")
			if to == "reject@ha.invalid" {
				response = "550 Test recipient rejected"
			}
		case "DATA":
			if conn.PrintfLine("354 End with a dot") != nil {
				return
			}
			raw, err := conn.ReadDotBytes()
			if err != nil {
				return
			}
			msg, err := mail.ReadMessage(bytes.NewReader(raw))
			if err != nil {
				return
			}
			subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
			body, _ := io.ReadAll(quotedprintable.NewReader(msg.Body))
			sink.mu.Lock()
			sink.received = append(sink.received, capturedHAMail{to, subject, msg.Header.Get("Message-ID"), string(body)})
			sink.mu.Unlock()
			if dropAck {
				return
			}
		case "QUIT":
			_ = conn.PrintfLine("221 Goodbye")
			return
		default:
			response = "500 Unknown command"
		}
		if conn.PrintfLine("%s", response) != nil {
			return
		}
	}
}

func TestHAMailOutboxSurvivesPollsAndAmbiguousSMTP(t *testing.T) {
	for _, dropAck := range []bool{false, true} {
		name := "acknowledged"
		if dropAck {
			name = "ambiguous"
		}
		t.Run(name, func(t *testing.T) {
			sink := startHASMTPSink(t, dropAck)
			s := testWorkspaceServer(t)
			s.cfg.Server.SettingsDir = t.TempDir()
			at := time.Now().UTC().Add(-time.Second)
			config := haMailConfig{Enabled: true, haSMTPConfig: haSMTPConfig{Host: "127.0.0.1", Port: sink.port, Security: "local", From: "panel@ha.invalid"},
				Recipients: []haMailRecipient{{"oncall@ha.invalid", []string{"node-down"}}, {"dhcp@ha.invalid", []string{"dhcp-moved"}}}}
			state := haMailState{Config: config, Since: at.Add(-time.Minute), Outbox: map[string]haMailDelivery{}}
			if err := s.haMail.save(s.haMailPath(), state); err != nil {
				t.Fatal(err)
			}
			key := "files@" + strings.Repeat("a", 64)
			observe := func(server *Server, timeAt time.Time, owner, first string) {
				server.recordHAHistory(timeAt, dashboardServices{Observed: timeAt, Clusters: []dashboardCluster{{Key: key, Owner: owner,
					Nodes: []dashboardClusterNode{{Name: "fs1", Membership: first}, {Name: "fs2", Membership: "up"}}}}})
			}
			observe(s, at, "fs1", "up")
			observe(s, at.Add(time.Millisecond), "fs2", "down")
			for range 4 {
				if err := s.processHAMail(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			reopened := testWorkspaceServer(t)
			reopened.cfg.Server.SettingsDir = s.cfg.Server.SettingsDir
			if err := reopened.processHAMail(context.Background()); err != nil {
				t.Fatal(err)
			}
			got := sink.snapshot()
			if len(got) != 1 || got[0].To != "oncall@ha.invalid" || !strings.Contains(got[0].Subject, "Узел недоступен") || got[0].MessageID == "" {
				t.Fatalf("unexpected SMTP capture: %+v", got)
			}
			want := "sent"
			if dropAck {
				want = "uncertain"
			}
			if view := reopened.haMail.view(); view.Counts[want] != 1 || len(view.Recent) != 1 {
				t.Fatalf("unexpected delivery state: %+v", view)
			}
		})
	}
}

func TestHAMailRequiresSelectedSTARTTLS(t *testing.T) {
	sink := startHASMTPSink(t, false)
	outcome := sendHAMail(context.Background(),
		haSMTPConfig{Host: "127.0.0.1", Port: sink.port, Security: "starttls", From: "panel@ha.invalid"},
		haMailDelivery{To: "ops@ha.invalid"}, "test-id", "")
	if outcome.state == "sent" || len(sink.snapshot()) != 0 {
		t.Fatalf("STARTTLS was bypassed: %+v", outcome)
	}
}
