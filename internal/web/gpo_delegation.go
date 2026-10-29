package web

import (
	"github.com/go-chi/chi/v5"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIGPODelegation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "gpo")
	if r.Method == http.MethodGet {
		v, err := s.svcs.GPO.SecurityFilter(r.Context(), id)
		topologyResult(w, v, err)
		return
	}
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.GPDelegationChange
	if !topologyJSON(w, r, &in) {
		return
	}
	if r.Method == http.MethodPost {
		v, err := s.svcs.GPO.DelegationPreview(r.Context(), id, in)
		topologyResult(w, v, err)
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.GPO.GrantDelegation(r.Context(), id, in, sess.Username, r.RemoteAddr))
}
