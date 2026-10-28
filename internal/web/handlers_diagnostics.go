package web

import (
	"net/http"
	"sambaadm/internal/auth"
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
	report, err := s.diagnostics.Run(r.Context())
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
	report, err := s.diagnostics.Run(r.Context())
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, report)
}
