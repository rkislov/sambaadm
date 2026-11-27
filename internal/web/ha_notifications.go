package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"sambaadm/internal/auth"
)

const haNotificationLimit = 50

type haNotificationSource struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Label string `json:"label"`
}

type haNotification struct {
	ID       string                 `json:"id"`
	At       time.Time              `json:"at"`
	Type     string                 `json:"type"`
	Node     string                 `json:"node,omitempty"`
	Previous []string               `json:"previous,omitempty"`
	Serving  []string               `json:"serving,omitempty"`
	Reserve  []string               `json:"reserve,omitempty"`
	Sources  []haNotificationSource `json:"sources"`
	Read     bool                   `json:"read"`
}

type notificationFeed struct {
	Items  []haNotification `json:"items"`
	Unread int              `json:"unread"`
}

type haJournalEntry struct {
	key   string
	group *haHistoryState
	event haHistoryEvent
}

func notificationNode(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func notificationSource(key string) (haNotificationSource, bool) {
	kind, id, found := strings.Cut(key, "/")
	if !found || !haHistoryID.MatchString(id) {
		return haNotificationSource{}, false
	}
	source := haNotificationSource{Kind: kind, ID: id}
	switch kind {
	case "smb":
		name, _, _ := strings.Cut(id, "@")
		source.Label = "SMB HA · " + name
	case "dhcp4":
		source.Label = "DHCPv4 HA"
	case "dhcp6":
		source.Label = "DHCPv6 HA"
	default:
		return haNotificationSource{}, false
	}
	return source, true
}

func notificationDigest(value any) string {
	raw, _ := json.Marshal(value)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func makeHANotifications(groups map[string]*haHistoryState) []haNotification {
	var entries []haJournalEntry
	for key, group := range groups {
		for _, event := range group.Events {
			entries = append(entries, haJournalEntry{key, group, event})
		}
	}
	slices.SortStableFunc(entries, func(a, b haJournalEntry) int {
		if cmp := a.event.At.Compare(b.event.At); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.key, b.key)
	})
	type outage struct {
		index    int
		services map[string]bool
	}
	outages := map[string]*outage{}
	// Group confirmations from the same observation without erasing service boundaries.
	batches := map[string][]int{}
	notifications := make([]haNotification, 0, len(entries))
	for _, entry := range entries {
		source, valid := notificationSource(entry.key)
		if !valid {
			continue
		}
		event := entry.event
		name := func(id string) string {
			if entry.group.Members[id] != "" {
				return entry.group.Members[id]
			}
			return id
		}
		names := func(nodes []string) []string {
			result := make([]string, 0, len(nodes))
			for _, node := range nodes {
				result = append(result, name(node))
			}
			slices.Sort(result)
			return result
		}
		item := haNotification{
			At: event.At, Type: event.Type, Node: name(event.Node), Previous: names(event.Previous),
			Serving: names(event.Serving), Reserve: names(event.Reserve), Sources: []haNotificationSource{source},
		}
		item.ID = notificationDigest([]any{entry.key, event})
		node := notificationNode(item.Node)
		switch event.Type {
		case "node-down":
			if node == "" {
				continue
			}
			if open := outages[node]; open != nil {
				if open.services[entry.key] {
					continue
				}
				existing := &notifications[open.index]
				if !slices.Contains(existing.Sources, source) {
					open.services[entry.key] = true
					existing.Sources = append(existing.Sources, source)
					continue
				}
			}
			outages[node] = &outage{index: len(notifications), services: map[string]bool{entry.key: true}}
		case "reserve-restored":
			if open := outages[node]; open != nil {
				delete(open.services, entry.key)
				if len(open.services) == 0 {
					delete(outages, node)
				}
			}
		case "service-moved":
		default:
			continue
		}
		batch := ""
		switch {
		case event.Type == "reserve-restored" && node != "":
			batch = notificationDigest([]any{item.At, item.Type, node})
		case event.Type == "service-moved" && source.Kind != "smb":
			members := make([]string, 0, len(entry.group.Members))
			for localName := range entry.group.Members {
				members = append(members, notificationNode(name(localName)))
			}
			slices.Sort(members)
			batch = notificationDigest([]any{item.At, item.Type, item.Previous, item.Serving, members})
		}
		if batch != "" {
			match := -1
			for _, index := range batches[batch] {
				existing := notifications[index].Sources
				if (event.Type == "reserve-restored" && !slices.Contains(existing, source)) ||
					(event.Type == "service-moved" && !slices.ContainsFunc(existing, func(other haNotificationSource) bool { return other.Kind == source.Kind })) {
					match = index
					break
				}
			}
			if match >= 0 {
				existing := &notifications[match]
				existing.Sources = append(existing.Sources, source)
				if event.Type == "reserve-restored" {
					// A returning node can be active for one service and standby for another.
					existing.Serving, existing.Reserve = nil, nil
				}
				continue
			}
			batches[batch] = append(batches[batch], len(notifications))
		}
		notifications = append(notifications, item)
	}
	slices.Reverse(notifications)
	return notifications
}

func notificationReadPath(dir string, session *auth.Session) string {
	identity := session.ObjectGUID
	if identity == "" {
		identity = session.Username
	}
	return filepath.Join(dir, "ha-notification-reads", notificationDigest(strings.ToLower(identity))+".json")
}

func loadNotificationReads(path string) (map[string]bool, error) {
	read := map[string]bool{}
	if path == "" {
		return read, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return read, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &read); err != nil {
		return nil, err
	}
	if read == nil {
		read = map[string]bool{}
	}
	return read, nil
}

func (s *Server) handleHANotifications(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanRead) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var request struct {
		IDs []string `json:"ids"`
	}
	if r.Method == http.MethodPost {
		if !topologyJSON(w, r, &request) {
			return
		}
		if len(request.IDs) > haNotificationLimit || slices.ContainsFunc(request.IDs, func(id string) bool {
			return len(id) != 64 || !haHistoryID.MatchString(id)
		}) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Неверные уведомления"})
			return
		}
	}

	unavailable := func() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Уведомления недоступны"})
	}
	h := &s.haHistory
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.load(s.historyPath()); err != nil || h.writeErr != nil {
		unavailable()
		return
	}
	path := ""
	if s.cfg.Server.SettingsDir != "" {
		path = notificationReadPath(s.cfg.Server.SettingsDir, sessionFrom(r))
	}
	seen, err := loadNotificationReads(path)
	if err != nil {
		unavailable()
		return
	}
	if h.notifications == nil {
		h.notifications = makeHANotifications(h.groups)
	}
	items := h.notifications
	if len(request.IDs) > 0 {
		if path == "" {
			unavailable()
			return
		}
		// Keep acknowledgements for retained entries and only accept IDs that exist.
		next := map[string]bool{}
		for _, item := range items {
			if seen[item.ID] || slices.Contains(request.IDs, item.ID) {
				next[item.ID] = true
			}
		}
		if err := saveHAJSON(path, next); err != nil {
			unavailable()
			return
		}
		seen = next
	}
	if len(items) > haNotificationLimit {
		items = items[:haNotificationLimit]
	}
	result := notificationFeed{Items: slices.Clone(items)}
	for index := range result.Items {
		result.Items[index].Read = seen[result.Items[index].ID]
		if !result.Items[index].Read {
			result.Unread++
		}
	}
	writeJSON(w, http.StatusOK, result)
}
