package web

import (
	"github.com/go-chi/chi/v5"
	"net/http"
	"sambaadm/internal/auth"
)

func (s *Server) handleBulkUsers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	svc := s.employees()
	id := chi.URLParam(r, "id")
	if r.Method == "GET" {
		p, e := svc.BulkGet(id)
		if e != nil {
			employeeError(w, e)
			return
		}
		writeJSON(w, 200, p)
		return
	}
	if id == "" {
		var in struct {
			Action string   `json:"action"`
			Logins []string `json:"logins"`
		}
		if !decodeEmployee(w, r, &in) {
			return
		}
		p, e := svc.BulkPreview(r.Context(), in.Action, in.Logins, employeeActor(r))
		if e != nil {
			employeeError(w, e)
			return
		}
		writeJSON(w, 200, p)
		return
	}
	var in struct {
		Revision string `json:"revision"`
		Confirm  bool   `json:"confirm"`
	}
	if !decodeEmployee(w, r, &in) {
		return
	}
	if !in.Confirm || in.Revision == "" {
		writeJSON(w, 400, map[string]string{"error": "Подтвердите просмотренный план."})
		return
	}
	p, e := svc.BulkApply(r.Context(), id, in.Revision, employeeActor(r))
	if e != nil {
		employeeError(w, e)
		return
	}
	writeJSON(w, 200, p)
}
