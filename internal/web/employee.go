package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) employees() *service.EmployeeService {
	return service.NewEmployeeService(s.ldap, s.audit, filepath.Join(s.cfg.Server.SettingsDir, "employee-workflows"), s.cfg.LDAP.Bind.User, func(id string) error { s.sessions.RevokeIdentity(id); return nil })
}
func employeeActor(r *http.Request) service.EmployeeActor {
	sess := sessionFrom(r)
	return service.EmployeeActor{Name: sess.Username, DN: sess.DN, ID: sess.ObjectGUID, IP: r.RemoteAddr}
}
func employeeError(w http.ResponseWriter, e error) {
	status := 502
	switch {
	case errors.Is(e, service.ErrEmployeeInput):
		status = 400
	case errors.Is(e, service.ErrEmployeeConflict), errors.Is(e, service.ErrEmployeeBusy):
		status = 409
	case errors.Is(e, service.ErrEmployeeNotFound):
		status = 404
	}
	writeJSON(w, status, map[string]string{"error": e.Error()})
}
func decodeEmployee(w http.ResponseWriter, r *http.Request, v any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "Проверьте параметры мастера: нужен один JSON-объект без лишних полей."})
		return false
	}
	return true
}
func (s *Server) handleEmployee(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	svc := s.employees()
	var result any
	var err error
	switch chi.URLParam(r, "action") {
	case "choices":
		result, err = svc.Choices(r.Context(), r.URL.Query().Get("kind"), r.URL.Query().Get("q"))
	case "context":
		result, err = svc.Context(r.Context(), r.URL.Query().Get("login"), r.URL.Query().Get("id"), employeeActor(r))
	case "parent":
		result, err = svc.Parent(r.Context(), r.URL.Query().Get("dn"))
	default:
		id := chi.URLParam(r, "id")
		if r.Method == "GET" {
			if id == "" {
				result, err = svc.List()
			} else {
				result, err = svc.Get(id)
			}
		} else if id == "" {
			var in service.EmployeeInput
			if !decodeEmployee(w, r, &in) {
				return
			}
			result, err = svc.Preview(r.Context(), in, employeeActor(r))
		} else {
			var in struct {
				Revision string `json:"revision"`
				Confirm  bool   `json:"confirm"`
				Password string `json:"password"`
			}
			if !decodeEmployee(w, r, &in) {
				return
			}
			if in.Revision == "" {
				writeJSON(w, 400, map[string]string{"error": "Перечитайте актуальный план."})
				return
			}
			if chi.URLParam(r, "operation") == "review" {
				if in.Password != "" {
					writeJSON(w, 400, map[string]string{"error": "Пароль передаётся только при выполнении."})
					return
				}
				result, err = svc.Review(r.Context(), id, in.Revision, employeeActor(r))
			} else {
				if !in.Confirm {
					writeJSON(w, 400, map[string]string{"error": "Подтвердите выполнение просмотренного плана."})
					return
				}
				result, err = svc.Apply(r.Context(), id, in.Revision, in.Password, employeeActor(r))
				in.Password = ""
			}
		}
	}
	if err != nil {
		employeeError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
