package web

import (
	"github.com/go-chi/chi/v5"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
	"time"
)

func (s *Server) handleAPIRODC(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ctx := r.Context()
	name := chi.URLParam(r, "name")
	if r.Method == http.MethodGet {
		out, e := s.svcs.RODC.State(ctx, name)
		topologyResult(w, out, e)
		return
	}
	var in service.RODCInput
	if !topologyJSON(w, r, &in) {
		return
	}
	if r.Method == http.MethodPost {
		out, e := s.svcs.RODC.Preview(ctx, name, in)
		topologyResult(w, out, e)
		return
	}
	sess := sessionFrom(r)
	out, e := s.svcs.RODC.Apply(ctx, name, in, sess.Username, r.RemoteAddr)
	topologyResult(w, out, e)
}
func (s *Server) handleAPIRODCAuth(w http.ResponseWriter, r *http.Request) {
	s.handleControllerAuth(w, r, true)
}

func (s *Server) handleAPIControllerAuth(w http.ResponseWriter, r *http.Request) {
	s.handleControllerAuth(w, r, false)
}

func (s *Server) handleControllerAuth(w http.ResponseWriter, r *http.Request, rodcOnly bool) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var after time.Time
	if raw := r.URL.Query().Get("after"); raw != "" {
		var e error
		after, e = time.Parse(time.RFC3339, raw)
		if e != nil {
			writeJSON(w, 400, map[string]string{"error": "after must be RFC3339"})
			return
		}
	}
	account := r.URL.Query().Get("account")
	if len(account) > 256 {
		writeJSON(w, 400, map[string]string{"error": "account filter too long"})
		return
	}
	var before time.Time
	if raw := r.URL.Query().Get("before"); raw != "" {
		var e error
		before, e = time.Parse(time.RFC3339, raw)
		if e != nil || (!after.IsZero() && before.Before(after)) {
			writeJSON(w, 400, map[string]string{"error": "invalid before time or interval"})
			return
		}
	}
	fetch := s.svcs.RODC.ControllerAuthentications
	if rodcOnly {
		fetch = s.svcs.RODC.Authentications
	}
	out, e := fetch(r.Context(), chi.URLParam(r, "name"), after, account)
	if e == nil && out != nil && !before.IsZero() {
		events := []service.RODCAuthEvent{}
		for _, event := range out.Events {
			if !event.Time.After(before) {
				events = append(events, event)
			}
		}
		out.Events = events
	}
	topologyResult(w, out, e)
}

func (s *Server) handleAPIControllerInventory(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	out, e := s.svcs.RODC.Inventory(r.Context(), chi.URLParam(r, "name"))
	topologyResult(w, out, e)
}
