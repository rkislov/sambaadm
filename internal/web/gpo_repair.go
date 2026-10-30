package web

import (
	"github.com/go-chi/chi/v5"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIGPORepair(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	id := chi.URLParam(r, "gpo")
	if r.Method == http.MethodGet {
		out, e := s.svcs.GPO.RepairHistory(r.Context(), id)
		topologyResult(w, out, e)
		return
	}
	var in service.RepairInput
	if !topologyJSON(w, r, &in) {
		return
	}
	if r.Method == http.MethodPost {
		out, e := s.svcs.GPO.RepairPreview(r.Context(), id, in)
		topologyResult(w, out, e)
		return
	}
	sess := sessionFrom(r)
	out, e := s.svcs.GPO.RepairApply(r.Context(), id, in, sess.Username, r.RemoteAddr)
	topologyResult(w, out, e)
}
