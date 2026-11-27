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

func TestHANotificationsGroupOutageAcrossPolls(t *testing.T) {
	start := time.Date(2026, 11, 26, 18, 0, 0, 0, time.UTC)
	event := func(seconds int, kind, node string) haHistoryEvent {
		return haHistoryEvent{At: start.Add(time.Duration(seconds) * time.Second), Type: kind, Node: node,
			Previous: []string{"a"}, Serving: []string{"b"}, Reserve: []string{"a"}}
	}
	journal := func(events ...haHistoryEvent) *haHistoryState {
		return &haHistoryState{haHistory: haHistory{Events: events, Members: map[string]string{"a": "fs1.example.test", "b": "fs2.example.test"}}}
	}
	smb := "smb/files@" + strings.Repeat("a", 64)
	dhcp4 := "dhcp4/" + strings.Repeat("b", 64)
	dhcp6 := "dhcp6/" + strings.Repeat("c", 64)
	groups := map[string]*haHistoryState{smb: journal(event(0, "node-down", "a"))}
	original := makeHANotifications(groups)[0]
	groups[dhcp4] = journal(event(10, "node-down", "a"), event(10, "service-moved", ""))
	groups[dhcp6] = journal(event(20, "node-down", "a"), event(10, "service-moved", ""))
	groups[smb].Events = append(groups[smb].Events, event(10, "service-moved", ""))
	got := makeHANotifications(groups)
	if len(got) != 3 || got[2].ID != original.ID || len(got[2].Sources) != 3 {
		t.Fatalf("related outage did not retain a single identity: %+v", got)
	}
	if len(got[0].Sources) != 1 || len(got[1].Sources) != 2 {
		t.Fatalf("DHCP families should combine while SMB remains separate: %+v", got)
	}
	for _, group := range groups {
		group.Events = append(group.Events, event(30, "reserve-restored", "a"), event(40, "node-down", "a"))
	}
	got = makeHANotifications(groups)
	if len(got) != 5 || len(got[1].Sources) != 3 || got[0].Type != "node-down" || got[0].ID == original.ID || len(got[0].Sources) != 3 {
		t.Fatalf("a new outage after recovery needs a new notification: %+v", got)
	}
}

func TestHANotificationsReadIsIdempotentAndPerUser(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.SettingsDir = t.TempDir()
	key := "smb/files@" + strings.Repeat("a", 64)
	stamp := time.Now().UTC()
	observe := func(server *Server, seconds int, serving, health string) {
		at := stamp.Add(time.Duration(seconds) * time.Second)
		server.recordHAHistory(at, dashboardServices{Observed: at, Clusters: []dashboardCluster{{
			Key: strings.TrimPrefix(key, "smb/"), Owner: serving, State: "degraded",
			Nodes: []dashboardClusterNode{{Name: "a", Membership: health}, {Name: "b", Membership: "up"}},
		}}})
	}
	alice, _ := s.sessions.Create("alice", "CN=alice", auth.RoleReadonly)
	bob, _ := s.sessions.Create("bob", "CN=bob", auth.RoleHelpdesk)
	call := func(server *Server, session *auth.Session, method string, ids []string, token bool, want int) notificationFeed {
		t.Helper()
		path := "/api/v1/services/ha-notifications"
		var raw []byte
		if method == http.MethodPost {
			path += "/read"
			raw, _ = json.Marshal(map[string][]string{"ids": ids})
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, bytes.NewBuffer(raw))
		if session != nil {
			r.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: session.ID})
			if token {
				r.Header.Set(csrfHeader, session.CSRFToken)
			}
		}
		server.Router().ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %d: %s", method, w.Code, w.Body.String())
		}
		var feed notificationFeed
		if want == http.StatusOK && json.Unmarshal(w.Body.Bytes(), &feed) != nil {
			t.Fatalf("invalid feed: %s", w.Body.String())
		}
		return feed
	}
	observe(s, 0, "a", "up")
	observe(s, 1, "", "down")
	first := call(s, alice, http.MethodGet, nil, false, 200)
	if first.Unread != 1 {
		t.Fatalf("unexpected initial feed: %+v", first)
	}
	ids := []string{first.Items[0].ID}
	observe(s, 2, "b", "down") // A notification appeared while the previous view was open.
	call(s, alice, http.MethodPost, ids, false, 403)
	for i := 0; i < 2; i++ {
		feed := call(s, alice, http.MethodPost, ids, true, 200)
		if feed.Unread != 1 || feed.Items[0].Read || !feed.Items[1].Read {
			t.Fatalf("wrong acknowledgement: %+v", feed)
		}
	}
	if feed := call(s, bob, http.MethodGet, nil, false, 200); feed.Unread != 2 {
		t.Fatalf("acknowledgement leaked to another role: %+v", feed)
	}
	call(s, nil, http.MethodGet, nil, false, 401)

	reopened := testWorkspaceServer(t)
	reopened.cfg.Server.SettingsDir = s.cfg.Server.SettingsDir
	again, _ := reopened.sessions.Create("alice", "CN=alice", auth.RoleReadonly)
	if feed := call(reopened, again, http.MethodGet, nil, false, 200); feed.Unread != 1 || !feed.Items[1].Read {
		t.Fatalf("acknowledgement lost after reload: %+v", feed)
	}
}
