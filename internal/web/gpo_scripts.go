package web

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"

	"github.com/go-chi/chi/v5"
	"sambaadm/internal/auth"
	"sambaadm/internal/policy"
	"sambaadm/internal/service"
)

func scriptError(w http.ResponseWriter, err error) {
	if errors.Is(err, policy.ErrInvalidValue) || errors.Is(err, service.ErrPolicyConflict) {
		editorError(w, err)
		return
	}
	upstreamError(w, err)
}

func (s *Server) handleAPIGPOScriptsSet(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var change service.ScriptChange
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20))
	d.DisallowUnknownFields()
	if d.Decode(&change) != nil || d.Decode(&struct{}{}) != io.EOF || change.Revision == "" || change.Entries == nil || change.Scope == "" || change.Event == "" || change.Kind == "" {
		writeJSON(w, 400, map[string]string{"error": "revision, scope, event, kind and entries are required"})
		return
	}
	sess := sessionFrom(r)
	result, err := s.svcs.GPO.SetScripts(r.Context(), chi.URLParam(r, "gpo"), change, sess.Username, r.RemoteAddr)
	if err != nil {
		scriptError(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (s *Server) handleAPIGPOScriptFile(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	data, err := s.svcs.GPO.ScriptFile(r.Context(), chi.URLParam(r, "gpo"), q.Get("revision"), q.Get("scope"), q.Get("event"), q.Get("name"))
	if err != nil {
		scriptError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": path.Base(q.Get("name"))}))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(200)
	_, _ = w.Write(data)
}
