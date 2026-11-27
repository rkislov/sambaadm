package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func TestHAHistoryPersistsObservedTransitions(t *testing.T) {
	s := testWorkspaceServer(t)
	s.cfg.Server.SettingsDir = t.TempDir()
	key := "files@" + strings.Repeat("a", 64)
	at := time.Date(2026, 11, 26, 18, 10, 0, 0, time.UTC)
	apply := func(server *Server, state, active, firstHealth, secondHealth string, seconds int) {
		stamp := at.Add(time.Duration(seconds) * time.Second)
		dashboard := dashboardServices{Observed: stamp, Clusters: []dashboardCluster{{
			Key: key, State: state, Owner: active, Nodes: []dashboardClusterNode{
				{Name: "fs1", Membership: firstHealth}, {Name: "fs2", Membership: secondHealth},
			},
		}}}
		server.recordHAHistory(stamp, dashboard)
	}
	apply(s, "active", "fs1", "up", "up", 0)
	apply(s, "unknown", "", "", "", 10)
	state := s.haHistory.groups["smb/"+key]
	if len(state.Events) != 0 {
		t.Fatalf("missing observations logged as outage: %+v", state.Events)
	}
	apply(s, "no-owner", "", "down", "up", 20)
	apply(s, "degraded", "fs2", "down", "up", 30)

	reopened := testWorkspaceServer(t)
	reopened.cfg.Server.SettingsDir = s.cfg.Server.SettingsDir
	apply(reopened, "degraded", "fs2", "down", "up", 35)
	apply(reopened, "degraded", "fs2", "up", "up", 40)
	apply(reopened, "active", "fs2", "up", "up", 50)
	apply(reopened, "active", "fs1", "up", "up", 45) // Late, older result.
	got := reopened.haHistory.groups["smb/"+key].Events
	if len(got) != 3 || got[0].Type != "node-down" || got[0].Node != "fs1" ||
		got[1].Type != "service-moved" || len(got[1].Previous) != 1 || got[1].Previous[0] != "fs1" ||
		len(got[1].Serving) != 1 || got[1].Serving[0] != "fs2" ||
		got[2].Type != "reserve-restored" || !got[2].At.Equal(at.Add(50*time.Second)) ||
		len(got[2].Reserve) != 1 || got[2].Reserve[0] != "fs1" {
		t.Fatalf("unexpected persisted events: %+v", got)
	}
	for _, role := range []auth.Role{auth.RoleReadonly, auth.RoleHelpdesk, auth.RoleAdmin, ""} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/services/ha-history?kind=smb&id="+key, nil)
		want := http.StatusUnauthorized
		if role != "" {
			session, _ := reopened.sessions.Create("test", "CN=test", role)
			req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: session.ID})
			want = http.StatusOK
		}
		w := httptest.NewRecorder()
		reopened.Router().ServeHTTP(w, req)
		if w.Code != want || (want == http.StatusOK && !strings.Contains(w.Body.String(), `"reserve-restored"`)) {
			t.Fatalf("role %q: %d %s", role, w.Code, w.Body.String())
		}
	}
}

func TestDHCPHAHistoryRequiresNativeEvidence(t *testing.T) {
	yes, no := true, false
	first := service.KeaHAHealth{PairID: "pair", Name: "a", Peer: "b", Mode: "hot-standby",
		State: "hot-standby", PeerState: "hot-standby", InTouch: &yes, Interrupted: &no, Serving: &yes}
	second := first
	second.Name, second.Peer, second.Serving = "b", "a", &no
	host := func(name string, ha service.KeaHAHealth) dashboardServer {
		return dashboardServer{Name: name, Services: []service.ServiceUnit{{
			ID: "dhcp4", State: "active", DHCP: &service.DHCPHealth{Source: "runtime", Relationships: []service.KeaHAHealth{ha}},
		}}}
	}
	active, standby := host("host-a", first), host("host-b", second)
	obs := func(hosts ...dashboardServer) haObservation {
		return haObservations(dashboardServices{Servers: hosts})["dhcp4/pair"]
	}
	if probe := obs(active, standby); !probe.ready || len(probe.serving) != 1 || probe.serving[0] != "a" {
		t.Fatalf("healthy pair not recognized: %+v", probe)
	}
	if probe := obs(standby); len(probe.serving) != 0 || probe.health["a"] != "" {
		t.Fatalf("partial response interpreted as takeover or loss: %+v", probe)
	}
	second.State, second.Serving, second.Interrupted = "partner-down", &yes, &yes
	standby = host("host-b", second)
	if probe := obs(standby); probe.ready || probe.health["a"] != "down" || len(probe.serving) != 1 || probe.serving[0] != "b" {
		t.Fatalf("native takeover not recognized: %+v", probe)
	}
	standby.Services[0].DHCP.SocketState = "failed"
	if probe := obs(standby); len(probe.serving) != 0 || probe.health["a"] != "down" {
		t.Fatalf("Kea with failed sockets reported as serving: %+v", probe)
	}
}
