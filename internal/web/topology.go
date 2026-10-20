package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func topologyJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "invalid topology request"})
		return false
	}
	return true
}
func topologyResult(w http.ResponseWriter, v any, e error) {
	if e != nil {
		status := 502
		if errors.Is(e, service.ErrTopologyInput) {
			status = 400
		}
		if errors.Is(e, service.ErrTopologyConflict) {
			status = 409
		}
		writeJSON(w, status, map[string]string{"error": e.Error()})
		return
	}
	if v == nil {
		v = map[string]string{"status": "ok"}
	}
	writeJSON(w, 200, v)
}
func (s *Server) handleAPISiteLinks(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		v, e := s.svcs.Sites.Links(r.Context())
		topologyResult(w, v, e)
		return
	}
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.SiteLinkInput
	if !topologyJSON(w, r, &in) {
		return
	}
	name := chi.URLParam(r, "name")
	if r.Method == "POST" {
		name = in.Name
		if in.Revision != "" {
			writeJSON(w, 400, map[string]string{"error": "revision not allowed for creation"})
			return
		}
	} else if in.Revision == "" {
		writeJSON(w, 400, map[string]string{"error": "revision required"})
		return
	}
	if name == "" || len(in.Sites) == 0 || in.Cost < 1 || in.Interval < 15 {
		topologyResult(w, nil, service.ErrTopologyInput)
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.Sites.SaveLink(r.Context(), name, in, sess.Username, r.RemoteAddr))
}
func (s *Server) handleAPISiteLinkSchedule(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Revision string   `json:"revision"`
		Schedule []string `json:"schedule"`
	}
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.Revision == "" || len(in.Schedule) != 7 {
		topologyResult(w, nil, service.ErrTopologyInput)
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.Sites.LinkSchedule(r.Context(), chi.URLParam(r, "name"), in.Revision, in.Schedule, sess.Username, r.RemoteAddr))
}
func (s *Server) handleAPISiteLinkDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Revision string `json:"revision"`
	}
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.Revision == "" {
		topologyResult(w, nil, service.ErrTopologyInput)
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.Sites.DeleteLink(r.Context(), chi.URLParam(r, "name"), in.Revision, sess.Username, r.RemoteAddr))
}
func (s *Server) handleAPITopology(w http.ResponseWriter, r *http.Request) {
	sites, e := s.svcs.Sites.List(r.Context())
	if e != nil {
		topologyResult(w, nil, e)
		return
	}
	dcs, e := s.svcs.Sites.Controllers(r.Context())
	if e != nil {
		topologyResult(w, nil, e)
		return
	}
	subnets, e := s.svcs.Subnets.List(r.Context())
	if e != nil {
		topologyResult(w, nil, e)
		return
	}
	topologyResult(w, map[string]any{"sites": sites, "controllers": dcs, "subnets": subnets}, nil)
}
func (s *Server) handleAPIControllers(w http.ResponseWriter, r *http.Request) {
	v, e := s.svcs.Sites.Controllers(r.Context())
	topologyResult(w, v, e)
}
func (s *Server) handleAPIMoveController(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Site     string `json:"site"`
		Revision string `json:"revision"`
	}
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.Revision == "" || in.Site == "" {
		topologyResult(w, nil, service.ErrTopologyInput)
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.Sites.MoveController(r.Context(), chi.URLParam(r, "name"), in.Site, in.Revision, sess.Username, r.RemoteAddr))
}
func (s *Server) handleAPISetSubnetSite(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Subnet string `json:"subnet"`
		Site   string `json:"site"`
	}
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.Subnet == "" || in.Site == "" {
		topologyResult(w, nil, service.ErrTopologyInput)
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.Subnets.SetSite(r.Context(), in.Subnet, in.Site, sess.Username, r.RemoteAddr))
}
func (s *Server) handleAPIConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		v, e := s.svcs.Sites.Connections(r.Context())
		topologyResult(w, v, e)
		return
	}
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Source      string `json:"source"`
		Destination string `json:"destination"`
	}
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.Source == "" || in.Destination == "" {
		topologyResult(w, nil, service.ErrTopologyInput)
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.Sites.CreateConnection(r.Context(), in.Source, in.Destination, sess.Username, r.RemoteAddr))
}
func (s *Server) handleAPIConnectionUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Revision string   `json:"revision"`
		Enabled  *bool    `json:"enabled"`
		Schedule []string `json:"schedule"`
	}
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.Revision == "" || (r.Method != "DELETE" && in.Enabled == nil && in.Schedule == nil) {
		topologyResult(w, nil, service.ErrTopologyInput)
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.Sites.UpdateConnection(r.Context(), chi.URLParam(r, "id"), in.Revision, in.Enabled, in.Schedule, r.Method == "DELETE", sess.Username, r.RemoteAddr))
}
func (s *Server) handleAPIKCC(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		DC string `json:"dc"`
	}
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.DC == "" {
		topologyResult(w, nil, service.ErrTopologyInput)
		return
	}
	sess := sessionFrom(r)
	topologyResult(w, nil, s.svcs.Repl.KCC(r.Context(), in.DC, sess.Username, r.RemoteAddr))
}
