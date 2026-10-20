package web

import (
	"encoding/json"
	"errors"
	"github.com/go-chi/chi/v5"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func editorError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	if errors.Is(err, service.ErrPolicyConflict) {
		status = http.StatusConflict
	}
	if errors.Is(err, service.ErrEditorUnavailable) {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
func (s *Server) handleAPIGPOALT(w http.ResponseWriter, r *http.Request) {
	result, err := s.svcs.GPO.ALTSettings(r.Context(), chi.URLParam(r, "gpo"))
	if err != nil {
		editorError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleAPIGPOALTSet(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var change service.ALTChange
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&change) != nil || change.ID == "" || change.Revision == "" || (change.State != "enabled" && change.State != "disabled" && change.State != "not-configured") {
		writeJSON(w, 400, map[string]string{"error": "id, state and revision required"})
		return
	}
	sess := sessionFrom(r)
	result, err := s.svcs.GPO.SetALTSetting(r.Context(), chi.URLParam(r, "gpo"), change, sess.Username, r.RemoteAddr)
	if err != nil {
		editorError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
