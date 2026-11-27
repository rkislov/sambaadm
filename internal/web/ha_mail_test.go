package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sambaadm/internal/auth"
)

func TestHAMailSettingsRequiresAdminAndCSRF(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.SettingsDir = t.TempDir()
	admin, _ := s.sessions.Create("admin", "CN=admin", auth.RoleAdmin)
	helpdesk, _ := s.sessions.Create("helpdesk", "CN=helpdesk", auth.RoleHelpdesk)
	input := haMailConfig{Enabled: true, haSMTPConfig: haSMTPConfig{Host: "127.0.0.1", Port: 2525, Security: "local",
		From: "panel@ha.invalid"}, Recipients: []haMailRecipient{{"ops@ha.invalid", []string{"node-down"}}}}
	body, _ := json.Marshal(input)
	check := func(method string, session *auth.Session, csrf bool, expected int) {
		t.Helper()
		req := httptest.NewRequest(method, "/api/v1/services/ha-mail", bytes.NewReader(body))
		if session != nil {
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: session.ID})
			if csrf {
				req.Header.Set(csrfHeader, session.CSRFToken)
			}
		}
		record := httptest.NewRecorder()
		s.Router().ServeHTTP(record, req)
		if record.Code != expected {
			t.Fatalf("got %d want %d: %s", record.Code, expected, record.Body.String())
		}
	}
	check(http.MethodGet, nil, false, 401)
	check(http.MethodGet, helpdesk, false, 403)
	check(http.MethodPut, helpdesk, true, 403)
	check(http.MethodPut, admin, false, 403)
	check(http.MethodPut, admin, true, 200)
	since := s.haMail.state.Since
	input.Port++
	body, _ = json.Marshal(input)
	check(http.MethodPut, admin, true, 200)
	if !s.haMail.state.Since.Equal(since) {
		t.Fatal("changing the relay lost the cutoff for unchanged routing")
	}
	input.Recipients = append(input.Recipients, haMailRecipient{"OPS@ha.invalid", []string{"smb-moved"}})
	body, _ = json.Marshal(input)
	check(http.MethodPut, admin, true, 400)
	input.Recipients = input.Recipients[:1]
	input.Host = "smtp.example.org"
	body, _ = json.Marshal(input)
	check(http.MethodPut, admin, true, 400)
}

func TestHAMailQueuesOnlyNewMatchingEvents(t *testing.T) {
	at := time.Now().UTC()
	state := haMailState{Since: at, Outbox: map[string]haMailDelivery{},
		Config: haMailConfig{Enabled: true, Recipients: []haMailRecipient{
			{"ops@ha.invalid", []string{"node-down"}},
			{"smb@ha.invalid", []string{"smb-moved"}},
			{"dhcp@ha.invalid", []string{"dhcp-moved"}},
		}}}
	items := []haNotification{
		{ID: "old", At: at.Add(-time.Second), Type: "node-down"},
		{ID: "new", At: at.Add(time.Second), Type: "node-down"},
		{ID: "smb", At: at.Add(time.Second), Type: "service-moved", Sources: []haNotificationSource{{Kind: "smb"}}},
		{ID: "dhcp", At: at.Add(time.Second), Type: "service-moved", Sources: []haNotificationSource{{Kind: "dhcp4"}, {Kind: "dhcp6"}}},
	}
	if !enqueueHAMail(&state, items, at.Add(2*time.Second)) || len(state.Outbox) != 3 {
		t.Fatalf("unexpected outbox: %+v", state.Outbox)
	}
	for _, item := range state.Outbox {
		if !strings.HasPrefix(item.To, map[string]string{"new": "ops", "smb": "smb", "dhcp": "dhcp"}[item.Event.ID]+"@") {
			t.Fatalf("wrong selection: %+v", item)
		}
	}
	if enqueueHAMail(&state, items, at.Add(3*time.Second)) {
		t.Fatal("a repeated poll staged another delivery")
	}
}
