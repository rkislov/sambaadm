package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sambaadm/internal/auth"
)

func TestHAMailDiagnosticUsesOneAttemptAndDoesNotChangeSettings(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.SettingsDir = t.TempDir()
	admin, _ := s.sessions.Create("admin", "CN=admin", auth.RoleAdmin)
	helpdesk, _ := s.sessions.Create("helpdesk", "CN=helpdesk", auth.RoleHelpdesk)
	sink := startHASMTPSink(t, false)
	lostAck := startHASMTPSink(t, true)
	smtp := haSMTPConfig{Host: "127.0.0.1", Port: sink.port, Security: "local", From: "panel@ha.invalid"}
	send := func(session *auth.Session, withCSRF bool, recipient string, expected int) map[string]string {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"smtp": smtp, "recipient": recipient})
		request := httptest.NewRequest(http.MethodPost, "/api/v1/services/ha-mail/test", bytes.NewReader(payload))
		if session != nil {
			request.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: session.ID})
			if withCSRF {
				request.Header.Set(csrfHeader, session.CSRFToken)
			}
		}
		recorder := httptest.NewRecorder()
		s.Router().ServeHTTP(recorder, request)
		if recorder.Code != expected {
			t.Fatalf("status %d, want %d: %s", recorder.Code, expected, recorder.Body.String())
		}
		var result map[string]string
		if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	send(nil, false, "ops@ha.invalid", http.StatusUnauthorized)
	send(helpdesk, true, "ops@ha.invalid", http.StatusForbidden)
	send(admin, false, "ops@ha.invalid", http.StatusForbidden)
	send(admin, true, "invalid", http.StatusBadRequest)
	s.haMail.testMu.Lock()
	send(admin, true, "ops@ha.invalid", http.StatusConflict)
	s.haMail.testMu.Unlock()
	if result := send(admin, true, "ops@ha.invalid", http.StatusOK); result["recipient"] != "ops@ha.invalid" || result["state"] != "sent" {
		t.Fatalf("unexpected success response: %#v", result)
	}
	if result := send(admin, true, "reject@ha.invalid", http.StatusBadGateway); result["state"] != "failed" ||
		result["error"] != "SMTP отклонил получателя · SMTP 550" {
		t.Fatalf("unexpected rejection response: %#v", result)
	}
	smtp.Port = lostAck.port
	if result := send(admin, true, "ops@ha.invalid", http.StatusBadGateway); result["state"] != "uncertain" {
		t.Fatalf("lost final reply was not identified: %#v", result)
	}
	if err := s.processHAMail(context.Background()); err != nil {
		t.Fatal(err)
	}
	captured := sink.snapshot()
	if len(captured) != 1 || captured[0].Subject != "Samba Admin · Тестовое письмо" || len(lostAck.snapshot()) != 1 {
		t.Fatalf("unexpected captures: %+v %+v", captured, lostAck.snapshot())
	}
	if _, err := os.Stat(s.haMailPath()); !os.IsNotExist(err) {
		t.Fatalf("SMTP diagnostics modified HA settings or the outbox: %v", err)
	}
}

func TestHAMailDiagnosticBrowserHarness(t *testing.T) {
	dir := os.Getenv("SAMBAADM_SMTP_BROWSER_DIR")
	if dir == "" {
		t.Skip("browser harness")
	}
	s := testWorkspaceServer(t)
	s.cfg.Server.SettingsDir = t.TempDir()
	session, _ := s.sessions.Create("lab-admin", "CN=lab-admin", auth.RoleAdmin)
	sink := startHASMTPSink(t, false)
	mux := http.NewServeMux()
	mux.Handle("/", s.Router())
	mux.HandleFunc("GET /__ha_mail_test_sink", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, sink.snapshot())
	})
	server := httptest.NewUnstartedServer(mux)
	if port := os.Getenv("SAMBAADM_SMTP_BROWSER_PORT"); port != "" {
		server.Listener.Close()
		listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			t.Fatal(err)
		}
		server.Listener = listener
	}
	server.Start()
	defer server.Close()
	data, _ := json.Marshal(map[string]any{"url": server.URL, "session": session.ID, "smtpPort": sink.port})
	if err := os.WriteFile(filepath.Join(dir, "browser.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, "done")); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("browser did not finish")
}
