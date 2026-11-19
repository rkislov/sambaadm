package web

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) fullBackupClient() *service.FullBackupService {
	var sites *service.SiteService
	if s.svcs != nil {
		sites = s.svcs.Sites
	}
	return &service.FullBackupService{Sites: sites, Store: s.objectBackupClient()}
}
func (s *Server) fullBackupNodes() []string {
	out := []string{}
	if s.svcs != nil && s.svcs.Helpers != nil {
		for _, n := range s.svcs.Helpers.Config.Nodes {
			out = append(out, n.Name)
		}
	}
	return out
}
func (s *Server) handleAPIFullBackups(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	client := s.fullBackupClient()
	id := chi.URLParam(r, "id")
	fail := func(err error) { writeJSON(w, 400, map[string]string{"error": err.Error()}) }
	if r.Method == http.MethodGet {
		if id == "" {
			out, err := client.List()
			if err != nil {
				fail(err)
				return
			}
			writeJSON(w, 200, out)
			return
		}
		out, err := client.Status(r.Context(), id)
		if err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, out)
		return
	}
	var in struct {
		Controller     string `json:"controller"`
		Revision       string `json:"revision"`
		ConfirmStopped bool   `json:"confirmStopped"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	if id == "" {
		out, err := client.Prepare(r.Context(), in.Controller, sessionFrom(r).Username, r.RemoteAddr)
		if err != nil {
			fail(err)
			return
		}
		writeJSON(w, 201, out)
		return
	}
	if !in.ConfirmStopped || in.Revision == "" {
		writeJSON(w, 400, map[string]string{"error": "revision and confirmStopped:true required"})
		return
	}
	out, err := client.Start(r.Context(), id, in.Revision, sessionFrom(r).Username, r.RemoteAddr)
	if err != nil {
		fail(err)
		return
	}
	writeJSON(w, 202, out)
}
