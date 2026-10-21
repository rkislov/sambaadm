package web

import (
	"github.com/go-chi/chi/v5"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIGPOScope(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		v, e := s.svcs.GPO.Scope(r.Context())
		if e != nil {
			topologyResult(w, nil, e)
			return
		}
		if dn := r.URL.Query().Get("container"); dn != "" {
			links, e := service.ScopeInheritance(v, dn)
			topologyResult(w, links, e)
		} else {
			topologyResult(w, v, nil)
		}
		return
	}
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.ScopeChange
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.Container == "" || in.Revision == "" || in.Links == nil {
		writeJSON(w, 400, map[string]string{"error": "container, revision and links array required"})
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.GPO.SaveScope(r.Context(), in, sess.Username, r.RemoteAddr))
}
func (s *Server) handleAPIGPOFilter(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "gpo")
	if r.Method == "GET" {
		v, e := s.svcs.GPO.SecurityFilter(r.Context(), id)
		topologyResult(w, v, e)
		return
	}
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.FilterChange
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.Revision == "" || (in.Principal == "") == (in.Remove == "") {
		writeJSON(w, 400, map[string]string{"error": "revision and one operation required"})
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.GPO.SetSecurityFilter(r.Context(), id, in, sess.Username, r.RemoteAddr))
}
