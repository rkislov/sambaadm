package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func groupResult(w http.ResponseWriter, value any, err error) {
	if err == nil {
		writeJSON(w, 200, value)
		return
	}
	switch {
	case errors.Is(err, service.ErrGroupConflict):
		writeJSON(w, 409, map[string]string{"error": err.Error()})
	case errors.Is(err, service.ErrGroupInput) || errors.Is(err, service.ErrGroupMemberInput) || errors.Is(err, service.ErrTopologyInput):
		writeJSON(w, 400, map[string]string{"error": err.Error()})
	default:
		upstreamError(w, err)
	}
}
func (s *Server) handleGroupDetails(w http.ResponseWriter, r *http.Request) {
	v, e := s.svcs.Groups.Details(r.Context(), routeParam(r, "name"))
	groupResult(w, v, e)
}
func (s *Server) handleGroupUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.UpdateGroupInput
	if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); e != nil {
		writeJSON(w, 400, map[string]string{"error": "Некорректный запрос"})
		return
	}
	sess := sessionFrom(r)
	v, e := s.svcs.Groups.Update(r.Context(), routeParam(r, "name"), in, sess.Username, r.RemoteAddr)
	groupResult(w, v, e)
}
func (s *Server) handleGroupMembershipChange(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.GroupMemberChange
	if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); e != nil {
		writeJSON(w, 400, map[string]string{"error": "Некорректный запрос"})
		return
	}
	sess := sessionFrom(r)
	v, e := s.svcs.Groups.ChangeMember(r.Context(), routeParam(r, "name"), in, r.Method == http.MethodDelete, sess.Username, r.RemoteAddr)
	groupResult(w, v, e)
}
func (s *Server) handleGroupAccess(w http.ResponseWriter, r *http.Request) {
	v, e := s.svcs.Groups.Access(r.Context(), routeParam(r, "name"))
	groupResult(w, v, e)
}
func (s *Server) handleGroupAccessChange(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		service.GPDelegationChange
		Confirm bool `json:"confirm"`
	}
	if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); e != nil {
		writeJSON(w, 400, map[string]string{"error": "Некорректный запрос"})
		return
	}
	name := routeParam(r, "name")
	if r.Method == http.MethodPost {
		v, e := s.svcs.Groups.AccessPreview(r.Context(), name, in.GPDelegationChange)
		groupResult(w, v, e)
		return
	}
	if !in.Confirm {
		writeJSON(w, 400, map[string]string{"error": "Подтвердите делегирование"})
		return
	}
	sess := sessionFrom(r)
	e := s.svcs.Groups.GrantAccess(r.Context(), name, in.GPDelegationChange, sess.Username, r.RemoteAddr)
	groupResult(w, map[string]string{"status": "ok"}, e)
}
