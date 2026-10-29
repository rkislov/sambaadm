package web

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIScriptMaintenance(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var result *service.ScriptMaintenance
	var err error
	if r.Method == "GET" {
		result, err = s.svcs.GPO.ScriptMaintenance(r.Context(), chi.URLParam(r, "gpo"))
	} else {
		var in service.ScriptMaintenanceChange
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(&struct{}{}) != io.EOF || in.Revision == "" || (in.Operation != "restore" && in.Operation != "delete" && in.Operation != "prune") {
			writeJSON(w, 400, map[string]string{"error": "valid operation and revision required"})
			return
		}
		sess := sessionFrom(r)
		result, err = s.svcs.GPO.MaintainScripts(r.Context(), chi.URLParam(r, "gpo"), in, sess.Username, r.RemoteAddr)
	}
	if err != nil {
		scriptError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleAPIScriptRestorePreview(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	result, err := s.svcs.GPO.ScriptRestorePreview(r.Context(), chi.URLParam(r, "gpo"), q.Get("source"), q.Get("mode"))
	if err != nil {
		scriptError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleAPIScriptBackup(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	q := r.URL.Query()
	data, err := s.svcs.GPO.ScriptBackupDownload(r.Context(), chi.URLParam(r, "gpo"), q.Get("name"), q.Get("revision"))
	if err != nil {
		scriptError(w, err)
		return
	}
	name := q.Get("name")
	if name == "pending" {
		name = "sambaadm-pending-recovery.json"
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}
