package web

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/go-chi/chi/v5"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/policy"
	"sambaadm/internal/service"
	"time"
)

func editorError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	if errors.Is(err, policy.ErrInvalidValue) {
		status = http.StatusBadRequest
	}
	if errors.Is(err, service.ErrPolicyConflict) {
		status = http.StatusConflict
	}
	if errors.Is(err, service.ErrEditorUnavailable) {
		status = http.StatusServiceUnavailable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		status = http.StatusGatewayTimeout
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
func (s *Server) handleAPIGPOALT(w http.ResponseWriter, r *http.Request) {
	result, err := s.svcs.GPO.ALTSettingsScope(r.Context(), chi.URLParam(r, "gpo"), r.URL.Query().Get("scope"))
	if err != nil {
		editorError(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (s *Server) handleAPIGPOScripts(w http.ResponseWriter, r *http.Request) {
	result, err := s.svcs.GPO.Scripts(r.Context(), chi.URLParam(r, "gpo"))
	if err != nil {
		scriptError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleAPIGPOALTSet(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var change service.ALTChange
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&change) != nil || change.ID == "" || change.Revision == "" || (change.State != "enabled" && change.State != "disabled" && change.State != "not-configured") {
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

// Imports static templates only. No GPO or SYSVOL file is changed.
func (s *Server) handleAPITemplateImport(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	if s.svcs == nil || s.svcs.GPO == nil {
		writeJSON(w, 503, map[string]string{"error": "GPO service unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	count, err := s.svcs.GPO.RefreshTemplateCache(ctx)
	if err != nil {
		if s.audit != nil {
			s.audit.Failure(sessionFrom(r).Username, "gpo.templates.import", "configured source", r.RemoteAddr, err)
		}
		editorError(w, err)
		return
	}
	if s.audit != nil {
		s.audit.Success(sessionFrom(r).Username, "gpo.templates.import", "configured source", r.RemoteAddr)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"count": count, "imported": time.Now().UTC(), "maxAgeSeconds": nil, "refreshPolicy": "manual"})
}
