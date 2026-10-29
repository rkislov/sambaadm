package web

import (
	"github.com/go-chi/chi/v5"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIGPOFullDelegation(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	id := chi.URLParam(r, "gpo")
	if r.Method == http.MethodGet {
		out, err := s.svcs.GPO.FullDelegationState(r.Context(), id)
		topologyResult(w, out, err)
		return
	}
	var in service.DelegationOperation
	if !topologyJSON(w, r, &in) {
		return
	}
	if r.Method == http.MethodPost {
		out, err := s.svcs.GPO.FullDelegationPreview(r.Context(), id, in)
		topologyResult(w, out, err)
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.GPO.FullDelegationApply(r.Context(), id, in, sess.Username, r.RemoteAddr))
}
