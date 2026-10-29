package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/policy"
)

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	if !auth.CanAdmin(sessionFrom(r).Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	s.render(w, "diagnostics/index.html", s.page(r, "nav.diagnostics", nil))
}
func (s *Server) handleDiagnosticsRun(w http.ResponseWriter, r *http.Request) {
	if !auth.CanAdmin(sessionFrom(r).Role) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	pd := s.page(r, "nav.diagnostics", nil)
	report, err := s.diagnostics.RunFor(r.Context(), r.FormValue("gpo"))
	if err != nil {
		pd.Error = err.Error()
	} else {
		pd.Content = report
	}
	if r.Header.Get("HX-Request") == "true" {
		s.render(w, "diagnostics/report", pd)
		return
	}
	s.render(w, "diagnostics/index.html", pd)
}
func (s *Server) handleAPIDiagnostics(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		GPO string `json:"gpo"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(&struct{}{}) != io.EOF {
			writeJSON(w, 400, map[string]string{"error": "invalid diagnostic request"})
			return
		}
	}
	report, err := s.diagnostics.RunFor(r.Context(), in.GPO)
	if err != nil {
		status := http.StatusConflict
		if errors.Is(err, policy.ErrInvalidValue) {
			status = 400
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, report)
}
