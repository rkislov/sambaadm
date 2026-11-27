package web

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"sambaadm/internal/auth"
)

const (
	haSMTPPassword  = "SAMBAADM_HA_SMTP_PASSWORD"
	haMailRetention = 30 * 24 * time.Hour
)

type haMailRecipient struct {
	Address string   `json:"address"`
	Events  []string `json:"events"`
}

type haSMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"`
	From     string `json:"from"`
	Username string `json:"username"`
}

type haMailConfig struct {
	haSMTPConfig
	Enabled    bool              `json:"enabled"`
	Recipients []haMailRecipient `json:"recipients"`
}

type haMailDelivery struct {
	To       string         `json:"to"`
	Event    haNotification `json:"event"`
	State    string         `json:"state"`
	StatusAt time.Time      `json:"statusAt"`
	Next     time.Time      `json:"next"`
	Attempts int            `json:"attempts"`
	Reason   string         `json:"reason,omitempty"`
}

type haMailState struct {
	Config haMailConfig              `json:"config"`
	Since  time.Time                 `json:"since"`
	Outbox map[string]haMailDelivery `json:"outbox"`
}

type haMailStore struct {
	mu     sync.Mutex
	testMu sync.Mutex
	state  *haMailState
}

var haMailEvents = []string{"node-down", "smb-moved", "dhcp-moved", "reserve-restored"}
var smtpHostname = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

func mailAddress(value string) bool {
	address, err := mail.ParseAddress(value)
	return err == nil && address.Address == value && len(value) <= 254 && strings.Contains(value, "@") &&
		strings.IndexFunc(value, func(r rune) bool { return r <= 32 || r >= 127 || strings.ContainsRune("<>\"", r) }) == -1
}

func (c *haSMTPConfig) normalize() error {
	c.Host = strings.TrimSpace(c.Host)
	c.From = strings.TrimSpace(c.From)
	c.Username = strings.TrimSpace(c.Username)
	if c.Security == "" {
		c.Security = "starttls"
	}
	if c.Port == 0 {
		switch c.Security {
		case "tls":
			c.Port = 465
		case "local":
			c.Port = 25
		default:
			c.Port = 587
		}
	}
	if c.Port < 1 || c.Port > 65535 || (c.Host != "" && net.ParseIP(c.Host) == nil && !smtpHostname.MatchString(c.Host)) {
		return errors.New("Укажите имя или IP SMTP-сервера и корректный порт.")
	}
	switch c.Security {
	case "starttls", "tls":
	case "local":
		if (c.Host != "" && !net.ParseIP(c.Host).IsLoopback()) || c.Username != "" {
			return errors.New("Локальный SMTP доступен только по loopback-адресу, без аутентификации.")
		}
	default:
		return errors.New("Выберите способ подключения к SMTP.")
	}
	if c.From != "" && !mailAddress(c.From) {
		return errors.New("Укажите адрес отправителя в формате user@example.org.")
	}
	if len(c.Username) > 254 || strings.ContainsAny(c.Username, "\x00\r\n") {
		return errors.New("Некорректное имя пользователя SMTP.")
	}
	return nil
}

func (c *haMailConfig) normalize() error {
	if err := c.haSMTPConfig.normalize(); err != nil {
		return err
	}
	if len(c.Recipients) > 32 {
		return errors.New("Добавьте не более 32 получателей.")
	}
	seen := map[string]bool{}
	for i := range c.Recipients {
		r := &c.Recipients[i]
		r.Address = strings.TrimSpace(r.Address)
		key := strings.ToLower(r.Address)
		if !mailAddress(r.Address) || seen[key] {
			return errors.New("Укажите уникальные адреса получателей.")
		}
		seen[key] = true
		slices.Sort(r.Events)
		r.Events = slices.Compact(r.Events)
		if len(r.Events) == 0 || slices.ContainsFunc(r.Events, func(event string) bool { return !slices.Contains(haMailEvents, event) }) {
			return errors.New("Выберите события для каждого получателя.")
		}
	}
	slices.SortFunc(c.Recipients, func(a, b haMailRecipient) int {
		return strings.Compare(strings.ToLower(a.Address), strings.ToLower(b.Address))
	})
	if c.Enabled && (c.Host == "" || c.From == "" || len(c.Recipients) == 0) {
		return errors.New("Для отправки укажите SMTP-сервер, отправителя и хотя бы одного получателя.")
	}
	return nil
}

func haMailEvent(n haNotification) string {
	if n.Type != "service-moved" {
		return n.Type
	}
	for _, source := range n.Sources {
		if source.Kind == "smb" {
			return "smb-moved"
		}
	}
	return "dhcp-moved"
}

func (c haMailConfig) accepts(address, event string) bool {
	return c.Enabled && slices.ContainsFunc(c.Recipients, func(r haMailRecipient) bool {
		return strings.EqualFold(r.Address, address) && slices.Contains(r.Events, event)
	})
}

func (s *Server) haMailPath() string {
	if s.cfg.Server.SettingsDir == "" {
		return ""
	}
	return filepath.Join(s.cfg.Server.SettingsDir, "ha-mail.json")
}

func (m *haMailStore) load(path string) error {
	if m.state != nil {
		return nil
	}
	if path == "" {
		return errors.New("settings directory missing")
	}
	state := haMailState{Config: haMailConfig{haSMTPConfig: haSMTPConfig{Port: 587, Security: "starttls"}, Recipients: []haMailRecipient{}}, Outbox: map[string]haMailDelivery{}}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &state); err != nil {
			return err
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return err
	}
	if state.Outbox == nil {
		state.Outbox = map[string]haMailDelivery{}
	}
	changed := false
	for id, item := range state.Outbox {
		if item.State == "sending" {
			item.State, item.Reason = "uncertain", "Сеанс SMTP прерван до сохранения результата."
			state.Outbox[id] = item
			changed = true
		}
	}
	if changed {
		return m.save(path, state)
	}
	m.state = &state
	return nil
}

func (m *haMailStore) save(path string, state haMailState) error {
	if path == "" {
		return errors.New("settings directory missing")
	}
	if err := saveHAJSON(path, state); err != nil {
		// An error after the rename can still leave the new state on disk.
		m.state = nil
		return err
	}
	m.state = &state
	return nil
}

type haMailView struct {
	Config          haMailConfig   `json:"config"`
	PasswordPresent bool           `json:"passwordPresent"`
	Counts          map[string]int `json:"counts"`
	Recent          []haMailStatus `json:"recent"`
}

type haMailStatus struct {
	At     time.Time `json:"at"`
	To     string    `json:"to"`
	Event  string    `json:"event"`
	State  string    `json:"state"`
	Reason string    `json:"reason,omitempty"`
}

func (m *haMailStore) view() haMailView {
	state := m.state
	result := haMailView{Config: state.Config, Counts: map[string]int{}, Recent: []haMailStatus{}, PasswordPresent: os.Getenv(haSMTPPassword) != ""}
	for _, item := range state.Outbox {
		result.Counts[item.State]++
		result.Recent = append(result.Recent, haMailStatus{item.StatusAt, item.To, haMailEvent(item.Event), item.State, item.Reason})
	}
	slices.SortFunc(result.Recent, func(a, b haMailStatus) int { return b.At.Compare(a.At) })
	if len(result.Recent) > 12 {
		result.Recent = result.Recent[:12]
	}
	return result
}

func (s *Server) haMailPage(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "settings/ha-mail.html", s.page(r, "Почтовые уведомления HA", nil))
}

func (s *Server) handleHAMail(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input haMailConfig
	if r.Method == http.MethodPut {
		if !topologyJSON(w, r, &input) {
			return
		}
		if err := input.normalize(); err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
	}
	path, store := s.haMailPath(), &s.haMail
	store.mu.Lock()
	defer store.mu.Unlock()
	unavailable := func() {
		writeJSON(w, 503, map[string]string{"error": "Хранилище почтовых уведомлений недоступно."})
	}
	if err := store.load(path); err != nil {
		unavailable()
		return
	}
	if r.Method == http.MethodPut && !reflect.DeepEqual(input, store.state.Config) {
		state := *store.state
		now := time.Now().UTC()
		if state.Config.Enabled != input.Enabled || !reflect.DeepEqual(state.Config.Recipients, input.Recipients) {
			state.Since = now
		}
		state.Config, state.Outbox = input, maps.Clone(state.Outbox)
		for id, item := range state.Outbox {
			if item.State == "queued" && !input.accepts(item.To, haMailEvent(item.Event)) {
				item.State, item.StatusAt = "cancelled", now
				state.Outbox[id] = item
			}
		}
		if err := store.save(path, state); err != nil {
			unavailable()
			return
		}
		if s.audit != nil {
			s.audit.Success(sessionFrom(r).Username, "ha-mail.settings", "SMTP", r.RemoteAddr)
		}
	}
	writeJSON(w, 200, store.view())
}

func (s *Server) handleHAMailTest(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var input struct {
		SMTP      haSMTPConfig `json:"smtp"`
		Recipient string       `json:"recipient"`
	}
	if !topologyJSON(w, r, &input) {
		return
	}
	if err := input.SMTP.normalize(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	input.Recipient = strings.TrimSpace(input.Recipient)
	if input.SMTP.Host == "" || input.SMTP.From == "" || !mailAddress(input.Recipient) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Укажите SMTP-сервер, отправителя и корректный адрес получателя."})
		return
	}
	if !s.haMail.testMu.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "Дождитесь результата предыдущей проверки SMTP."})
		return
	}
	defer s.haMail.testMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	item := haMailDelivery{
		To: input.Recipient, Event: haNotification{Type: "smtp-test", At: time.Now().UTC()},
	}
	result := sendHAMail(ctx, input.SMTP, item, rand.Text(), "")
	if result.state != "sent" {
		state := "failed"
		if result.state == "uncertain" {
			state = result.state
		}
		if s.audit != nil {
			s.audit.Failure(sessionFrom(r).Username, "ha-mail.test", item.To, r.RemoteAddr, errors.New(result.reason))
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"state": state, "error": result.reason})
		return
	}
	if s.audit != nil {
		s.audit.Success(sessionFrom(r).Username, "ha-mail.test", item.To, r.RemoteAddr)
	}
	writeJSON(w, http.StatusOK, map[string]string{"state": "sent", "recipient": item.To})
}

func (s *Server) emailNotifications() []haNotification {
	h := &s.haHistory
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := h.load(s.historyPath()); err != nil || h.writeErr != nil {
		return nil
	}
	if h.notifications == nil {
		h.notifications = makeHANotifications(h.groups)
	}
	return slices.Clone(h.notifications)
}

func enqueueHAMail(state *haMailState, items []haNotification, now time.Time) bool {
	changed := false
	cutoff := now.Add(-haMailRetention)
	for id, entry := range state.Outbox {
		if entry.Event.At.Before(cutoff) {
			delete(state.Outbox, id)
			changed = true
		}
	}
	if !state.Config.Enabled {
		return changed
	}
	for _, item := range items {
		if item.At.Before(cutoff) || !item.At.After(state.Since) {
			continue
		}
		event := haMailEvent(item)
		for _, recipient := range state.Config.Recipients {
			if !slices.Contains(recipient.Events, event) {
				continue
			}
			id := notificationDigest([]string{item.ID, strings.ToLower(recipient.Address)})
			if _, ok := state.Outbox[id]; !ok {
				state.Outbox[id] = haMailDelivery{To: recipient.Address, Event: item, State: "queued", Next: now, StatusAt: now}
				changed = true
			}
		}
	}
	return changed
}

func (s *Server) stageHAMail() error {
	path, store := s.haMailPath(), &s.haMail
	store.mu.Lock()
	if err := store.load(path); err != nil {
		store.mu.Unlock()
		return err
	}
	enabled := store.state.Config.Enabled
	store.mu.Unlock()
	if !enabled {
		return nil
	}
	items := s.emailNotifications()
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.load(path); err != nil {
		return err
	}
	state := *store.state
	state.Outbox = maps.Clone(state.Outbox)
	if enqueueHAMail(&state, items, time.Now().UTC()) {
		return store.save(path, state)
	}
	return nil
}

func (s *Server) claimHAMail() (string, haMailDelivery, haMailConfig, error) {
	store, path := &s.haMail, s.haMailPath()
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.load(path); err != nil {
		return "", haMailDelivery{}, haMailConfig{}, err
	}
	state := *store.state
	now := time.Now().UTC()
	var id string
	var next haMailDelivery
	for key, item := range state.Outbox {
		if item.State == "queued" && !item.Next.After(now) && state.Config.accepts(item.To, haMailEvent(item.Event)) &&
			(id == "" || item.Event.At.Before(next.Event.At) || (item.Event.At.Equal(next.Event.At) && key < id)) {
			id, next = key, item
		}
	}
	if id == "" {
		return "", haMailDelivery{}, haMailConfig{}, nil
	}
	next.State, next.StatusAt, next.Attempts = "sending", now, next.Attempts+1
	state.Outbox = maps.Clone(state.Outbox)
	state.Outbox[id] = next
	return id, next, state.Config, store.save(path, state)
}

func (s *Server) finishHAMail(id string, result smtpOutcome) error {
	store, path := &s.haMail, s.haMailPath()
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.load(path); err != nil {
		return err
	}
	state := *store.state
	item, exists := state.Outbox[id]
	if !exists {
		return nil
	}
	now := time.Now().UTC()
	item.StatusAt, item.Reason = now, result.reason
	switch {
	case result.state == "retry" && !state.Config.accepts(item.To, haMailEvent(item.Event)):
		item.State = "cancelled"
	case result.state == "retry" && item.Attempts < 8:
		item.State, item.Next = "queued", now.Add(min(15*time.Second<<(item.Attempts-1), 10*time.Minute))
	case result.state == "retry":
		item.State = "failed"
	default:
		item.State = result.state
	}
	state.Outbox = maps.Clone(state.Outbox)
	state.Outbox[id] = item
	return store.save(path, state)
}

func (s *Server) processHAMail(ctx context.Context) error {
	if err := s.stageHAMail(); err != nil {
		return err
	}
	for range 16 {
		if ctx.Err() != nil {
			return nil
		}
		id, item, config, err := s.claimHAMail()
		if err != nil || id == "" {
			return err
		}
		result := sendHAMail(ctx, config.haSMTPConfig, item, id, s.cfg.Server.PublicURL)
		if err := s.finishHAMail(id, result); err != nil {
			return err
		}
	}
	return nil
}

// MonitorHAMail delivers claimed entries independently of dashboard requests.
func (s *Server) MonitorHAMail(ctx context.Context) {
	if s.haMailPath() == "" {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var reported string
	for ctx.Err() == nil {
		err := s.processHAMail(ctx)
		if err != nil {
			msg := fmt.Sprint(err)
			if msg != reported {
				slog.Warn("HA mail queue unavailable", "error", err)
				reported = msg
			}
		} else {
			reported = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
