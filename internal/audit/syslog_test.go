package audit

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCEFOverTCP(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	log, err := NewWithSyslog(filepath.Join(t.TempDir(), "audit.log"), SyslogConfig{Enabled: true, Network: "tcp", Address: listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	log.Log(Event{
		Actor: "Иван=Петров\\\nИ", Role: "helpdesk", Action: "web.request",
		Target: "/api/v1/users/{dn}", Method: "POST", HTTPStatus: 403, DurationMS: 7,
		IP: "[2001:db8::42]:1234", Result: "failure", Error: "secret", Details: "sensitive",
	})
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	var size int
	if _, err := fmt.Fscanf(reader, "%d ", &size); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, size)
	if _, err := io.ReadFull(reader, received); err != nil {
		t.Fatal(err)
	}
	message := string(received)
	for _, part := range []string{
		"<132>1 ", " CEF:0|sambaadm|sambaadm|", "|web.request|web.request|5|",
		`suser=Иван\=Петров\\\nИ`, "outcome=failure", "c6a1=2001:db8::42", "cs1=helpdesk",
		"requestMethod=POST", "cn1=403", "cn2=7", "request=/api/v1/users/{dn}",
	} {
		if !strings.Contains(message, part) {
			t.Errorf("missing %q in %q", part, message)
		}
	}
	for _, forbidden := range []string{"secret", "sensitive", "\n", "\r"} {
		if strings.Contains(message, forbidden) {
			t.Errorf("leaked %q in %q", forbidden, message)
		}
	}
}

func TestSyslogOutagePreservesLocalAudit(t *testing.T) {
	dir := t.TempDir()
	log, err := NewWithSyslog(filepath.Join(dir, "audit.log"), SyslogConfig{Enabled: true, Network: "unixgram", Address: filepath.Join(dir, "missing.sock")})
	if err != nil {
		t.Fatal(err)
	}
	log.Success("operator", "login", "", "192.0.2.5")
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	audit, err := log.Recent(1)
	if err != nil || len(audit) != 1 || audit[0].Actor != "operator" {
		t.Fatalf("local audit = %+v, %v", audit, err)
	}
}

func TestRecentReadsAcrossLogTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	for range 1300 {
		_, _ = fmt.Fprintln(f, `{"actor":"old","action":"login","result":"success"}`)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	log.Success("recent", "login", "", "192.0.2.6")
	events, err := log.Recent(200)
	if err != nil || len(events) != 200 || events[199].Actor != "recent" {
		t.Fatalf("recent events: count=%d err=%v", len(events), err)
	}
}
