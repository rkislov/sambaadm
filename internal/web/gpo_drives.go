package web

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIGPODrives(w http.ResponseWriter, r *http.Request) {
	out, e := s.svcs.GPO.Drives(r.Context(), chi.URLParam(r, "gpo"))
	if e != nil {
		editorError(w, e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
}
func (s *Server) handleAPIGPODriveSet(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.DriveChange
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(&struct{}{}) != io.EOF || in.Scope == "" || in.Revision == "" || in.Operation == "" {
		writeJSON(w, 400, map[string]string{"error": "scope, revision and operation are required"})
		return
	}
	sess := sessionFrom(r)
	out, e := s.svcs.GPO.SetDrive(r.Context(), chi.URLParam(r, "gpo"), in, sess.Username, r.RemoteAddr)
	if e != nil {
		editorError(w, e)
		return
	}
	writeJSON(w, 200, out)
}
