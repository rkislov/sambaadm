package web

import (
	"encoding/json"
	"errors"
	"github.com/go-chi/chi/v5"
	"io"
	"net/http"
	"net/url"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) loginController() string {
	u, err := url.Parse(s.cfg.LDAP.URI)
	if err != nil {
		return "Настроенный DC"
	}
	if u.Scheme == "ldapi" {
		return "Локальный DC (LDAPI)"
	}
	return u.Hostname()
}
func (s *Server) handleAPIUserLoginStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	result, err := s.svcs.Users.LoginStatus(r.Context(), chi.URLParam(r, "login"), s.loginController())
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleAPIUserUnlock(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !requireRole(w, r, auth.CanHelpdesk) {
		return
	}
	var input struct {
		Revision string `json:"revision"`
		Confirm  bool   `json:"confirm"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || !input.Confirm || input.Revision == "" {
		writeJSON(w, 400, map[string]string{"error": service.ErrUnlockInput.Error()})
		return
	}
	sess := sessionFrom(r)
	result, err := s.svcs.Users.Unlock(r.Context(), chi.URLParam(r, "login"), input.Revision, s.loginController(), sess.Username, r.RemoteAddr)
	if err != nil {
		status := 502
		if errors.Is(err, service.ErrLoginConflict) {
			status = 409
		}
		writeJSON(w, status, map[string]any{"error": err.Error(), "diagnostics": result})
		return
	}
	writeJSON(w, 200, result)
}
