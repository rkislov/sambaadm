package web

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"sambaadm/internal/auth"
)

const haHistoryLimit = 100

type haHistoryEvent struct {
	At       time.Time `json:"at"`
	Type     string    `json:"type"`
	Node     string    `json:"node,omitempty"`
	Previous []string  `json:"previous,omitempty"`
	Serving  []string  `json:"serving,omitempty"`
	Reserve  []string  `json:"reserve,omitempty"`
}

type haHistory struct {
	Since   time.Time         `json:"since"`
	Members map[string]string `json:"members"`
	Events  []haHistoryEvent  `json:"events"`
}

type haHistoryState struct {
	haHistory
	Health  map[string]string `json:"health"`
	Missing map[string]bool   `json:"missing"`
	Serving []string          `json:"serving"`
}

type haHistoryStore struct {
	mu            sync.Mutex
	lastProbe     time.Time
	groups        map[string]*haHistoryState
	notifications []haNotification
	dirty         bool
	writeErr      error
}

type haObservation struct {
	members map[string]string
	health  map[string]string
	serving []string
	ready   bool
}

func (s *Server) historyPath() string {
	if s.cfg.Server.SettingsDir == "" {
		return ""
	}
	return filepath.Join(s.cfg.Server.SettingsDir, "ha-history.json")
}

func (h *haHistoryStore) load(path string) error {
	if h.groups != nil {
		return nil
	}
	groups := map[string]*haHistoryState{}
	if path != "" {
		raw, err := os.ReadFile(path)
		if err == nil {
			if err := json.Unmarshal(raw, &groups); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if groups == nil {
		groups = map[string]*haHistoryState{}
	}
	for key, group := range groups {
		if group == nil {
			delete(groups, key)
			continue
		}
		if group.Members == nil {
			group.Members = map[string]string{}
		}
		if group.Health == nil {
			group.Health = map[string]string{}
		}
		if group.Missing == nil {
			group.Missing = map[string]bool{}
		}
	}
	h.groups = groups
	return nil
}

func (h *haHistoryStore) save(path string) error {
	return saveHAJSON(path, h.groups)
}

func saveHAJSON(path string, value any) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".ha-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := json.NewEncoder(file).Encode(value); err != nil {
		file.Close()
		return err
	}
	err = file.Sync()
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func (g *haHistoryState) apply(now time.Time, probe haObservation) bool {
	changed := false
	for name, label := range probe.members {
		if label != "" && g.Members[name] != label {
			g.Members[name] = label
			changed = true
		}
	}
	add := func(e haHistoryEvent) {
		e.At = now
		g.Events = append(g.Events, e)
		changed = true
	}
	names := slices.Sorted(maps.Keys(probe.health))
	for _, name := range names {
		health := probe.health[name]
		if g.Health[name] == health {
			continue
		}
		if health == "down" && !g.Missing[name] {
			if g.Health[name] == "up" {
				add(haHistoryEvent{Type: "node-down", Node: name})
			}
			g.Missing[name] = true
		}
		g.Health[name] = health
		changed = true
	}
	if len(probe.serving) > 0 && !slices.Equal(probe.serving, g.Serving) {
		if len(g.Serving) > 0 {
			add(haHistoryEvent{Type: "service-moved", Previous: g.Serving, Serving: probe.serving})
		}
		g.Serving = probe.serving
		changed = true
	}
	if probe.ready && len(probe.serving) > 0 {
		var reserve []string
		for _, name := range names {
			if !slices.Contains(probe.serving, name) {
				reserve = append(reserve, name)
			}
		}
		for _, name := range names {
			if g.Missing[name] && probe.health[name] == "up" {
				add(haHistoryEvent{Type: "reserve-restored", Node: name, Serving: probe.serving, Reserve: reserve})
				delete(g.Missing, name)
			}
		}
	}
	if len(g.Events) > haHistoryLimit {
		g.Events = slices.Clone(g.Events[len(g.Events)-haHistoryLimit:])
	}
	return changed
}

func haObservations(dashboard dashboardServices) map[string]haObservation {
	result := map[string]haObservation{}
	for _, cluster := range dashboard.Clusters {
		probe := haObservation{members: map[string]string{}, health: map[string]string{}}
		for _, node := range cluster.Nodes {
			probe.members[node.Name] = node.Name
			if node.Membership != "" {
				probe.health[node.Name] = node.Membership
			}
		}
		if cluster.Owner != "" {
			probe.serving = []string{cluster.Owner}
			probe.ready = cluster.State == "active" && len(probe.health) == 2
			for _, health := range probe.health {
				probe.ready = probe.ready && health == "up"
			}
		}
		result["smb/"+cluster.Key] = probe
	}

	type keaPair struct {
		probe          haObservation
		healthyServing map[string]bool
		failedOver     []string
	}
	pairs := map[string]*keaPair{}
	for _, server := range dashboard.Servers {
		for _, unit := range server.Services {
			if (unit.ID != "dhcp4" && unit.ID != "dhcp6") || unit.DHCP == nil {
				continue
			}
			for _, ha := range unit.DHCP.Relationships {
				if ha.PairID == "" || ha.Name == "" || ha.Peer == "" || ha.Name == ha.Peer {
					continue
				}
				key := unit.ID + "/" + ha.PairID
				pair := pairs[key]
				if pair == nil {
					pair = &keaPair{
						probe:          haObservation{members: map[string]string{}, health: map[string]string{}},
						healthyServing: map[string]bool{},
					}
					pairs[key] = pair
				}
				pair.probe.members[ha.Name] = server.Name
				if _, ok := pair.probe.members[ha.Peer]; !ok {
					pair.probe.members[ha.Peer] = ""
				}
				if unit.DHCP.Source != "runtime" || unit.State != "active" {
					continue
				}
				if ha.State == "partner-down" || (ha.Interrupted != nil && *ha.Interrupted) {
					pair.probe.health[ha.Peer] = "down"
				}
				usable := ha.Serving != nil && unit.DHCP.SocketState != "failed" && unit.DHCP.SocketState != "retrying"
				if ha.State == "partner-down" && usable && *ha.Serving {
					pair.failedOver = append(pair.failedOver, ha.Name)
				}
				if ha.State == ha.Mode && ha.PeerState == ha.Mode && ha.InTouch != nil && *ha.InTouch &&
					(ha.Interrupted == nil || !*ha.Interrupted) {
					if pair.probe.health[ha.Name] != "down" {
						pair.probe.health[ha.Name] = "up"
					}
					if usable {
						pair.healthyServing[ha.Name] = *ha.Serving
					}
				}
			}
		}
	}
	for key, pair := range pairs {
		probe := pair.probe
		switch {
		case len(pair.failedOver) == 1 && probe.health[pair.failedOver[0]] != "down":
			probe.serving = pair.failedOver
		case len(pair.healthyServing) == 2:
			probe.ready = true
			for name, serving := range pair.healthyServing {
				probe.ready = probe.ready && probe.health[name] == "up"
				if serving {
					probe.serving = append(probe.serving, name)
				}
			}
			if !probe.ready {
				probe.serving = nil
			}
			slices.Sort(probe.serving)
		}
		result[key] = probe
	}
	return result
}

func (s *Server) recordHAHistory(started time.Time, dashboard dashboardServices) {
	h := &s.haHistory
	path := s.historyPath()
	observed := haObservations(dashboard)
	h.mu.Lock()
	defer h.mu.Unlock()
	if !started.After(h.lastProbe) {
		return
	}
	if err := h.load(path); err != nil {
		h.writeErr = err
		return
	}
	h.lastProbe = started
	for key, observation := range observed {
		group := h.groups[key]
		if group == nil {
			if len(observation.health) == 0 && len(observation.serving) == 0 {
				continue
			}
			group = &haHistoryState{
				haHistory: haHistory{Since: dashboard.Observed, Members: map[string]string{}, Events: []haHistoryEvent{}},
				Health:    map[string]string{}, Missing: map[string]bool{},
			}
			h.groups[key] = group
			h.dirty = true
		}
		h.dirty = group.apply(dashboard.Observed, observation) || h.dirty
	}
	if h.dirty {
		h.notifications = nil
		h.writeErr = h.save(path)
		h.dirty = h.writeErr != nil
	}
}

// MonitorHA records at the panel even while no browser is open.
func (s *Server) MonitorHA(ctx context.Context) {
	if s.svcs == nil || s.svcs.Helpers == nil {
		return
	}
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for ctx.Err() == nil {
		started := time.Now()
		probeCtx, cancel := context.WithTimeout(ctx, 14*time.Second)
		dashboard := s.observeServices(probeCtx, clusterRPC{s, "sambaadm-monitor"}, false)
		if probeCtx.Err() == nil {
			s.recordHAHistory(started, dashboard)
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

var haHistoryID = regexp.MustCompile(`^(?:[a-zA-Z0-9-]{1,63}@)?[a-f0-9]{64}$`)

func (s *Server) handleHAHistory(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanRead) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	kind, id := r.URL.Query().Get("kind"), r.URL.Query().Get("id")
	if (kind != "smb" && kind != "dhcp4" && kind != "dhcp6") || !haHistoryID.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Неверная служба HA"})
		return
	}
	h := &s.haHistory
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.load(s.historyPath()); err != nil || h.writeErr != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Журнал переключений недоступен"})
		return
	}
	if group := h.groups[kind+"/"+id]; group != nil {
		writeJSON(w, http.StatusOK, group.haHistory)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": []haHistoryEvent{}})
}
