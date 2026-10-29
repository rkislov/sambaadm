package web

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIGPOConsistency(w http.ResponseWriter, r *http.Request) {
	var in service.ConsistencyInput
	if !topologyJSON(w, r, &in) {
		return
	}
	out, err := s.svcs.GPO.CheckConsistency(r.Context(), chi.URLParam(r, "gpo"), in)
	if errors.Is(err, service.ErrConsistencyBusy) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	topologyResult(w, out, err)
}
