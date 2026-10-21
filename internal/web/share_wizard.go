package web

import (
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIShareWizard(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.ShareWizardInput
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.Name == "" || len(in.Groups) == 0 {
		writeJSON(w, 400, map[string]string{"error": "name and groups required"})
		return
	}
	plan, e := s.svcs.PlanShare(r.Context(), in)
	if e != nil {
		topologyResult(w, nil, e)
		return
	}
	if r.URL.Query().Get("apply") != "1" {
		topologyResult(w, plan, nil)
		return
	}
	if !plan.Ready {
		writeJSON(w, 400, map[string]string{"error": "Domain groups are not resolvable on the local host; check winbind/NSS before creating the share"})
		return
	}
	sess := sessionFrom(r)
	v, e := s.svcs.Shares.Create(r.Context(), plan.Input, sess.Username, r.RemoteAddr)
	topologyResult(w, v, e)
}
func (s *Server) handleAPISambaProfile(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	if r.Method == "GET" {
		v, e := s.svcs.Shares.PlanProfile(r.Context(), r.URL.Query().Get("profile"))
		topologyResult(w, v, e)
		return
	}
	var in struct {
		Profile  string `json:"profile"`
		Revision string `json:"revision"`
	}
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.Profile == "" || in.Revision == "" {
		writeJSON(w, 400, map[string]string{"error": "profile and revision required"})
		return
	}
	sess := sessionFrom(r)
	backup, e := s.svcs.Shares.ApplyProfile(r.Context(), in.Profile, in.Revision, sess.Username, r.RemoteAddr)
	topologyResult(w, map[string]string{"backup": backup, "status": "saved", "activation": "reload-required"}, e)
}
