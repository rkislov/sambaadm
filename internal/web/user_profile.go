package web

import (
	"encoding/json"
	"errors"
	"github.com/go-chi/chi/v5"
	"io"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIUserUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.UpdateUserInput
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil || decoder.Decode(&struct{}{}) != io.EOF || in.Revision == "" {
		writeJSON(w, 400, map[string]string{"error": "valid profile attributes and revision required"})
		return
	}
	session := sessionFrom(r)
	result, e := s.svcs.Users.Update(r.Context(), chi.URLParam(r, "login"), in, session.Username, r.RemoteAddr)
	if e != nil {
		status := 502
		if errors.Is(e, service.ErrUserInput) {
			status = 400
		}
		if errors.Is(e, service.ErrUserConflict) {
			status = 409
		}
		writeJSON(w, status, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleAPIUserGroups(w http.ResponseWriter, r *http.Request) {
	result, e := s.svcs.Users.Memberships(r.Context(), chi.URLParam(r, "login"))
	if e != nil {
		writeJSON(w, 502, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, result)
}
