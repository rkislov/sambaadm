package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/go-chi/chi/v5"
	"github.com/go-ldap/ldap/v3"
	"io"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func psoError(w http.ResponseWriter, err error) {
	status := 502
	if errors.Is(err, service.ErrPSOInput) {
		status = 400
	}
	if errors.Is(err, service.ErrPSOConflict) {
		status = 409
	}
	if errors.Is(err, service.ErrPSONotFound) {
		status = 404
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
		status = 403
	}
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
func decodePSO(w http.ResponseWriter, r *http.Request, in any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	d.DisallowUnknownFields()
	if d.Decode(in) != nil || d.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "Нужны корректные параметры PSO в одном JSON-объекте."})
		return false
	}
	return true
}
func (s *Server) handlePSOList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	result, err := s.svcs.Domain.ListPSOs(r.Context())
	if err != nil {
		psoError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handlePSOGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	result, err := s.svcs.Domain.GetPSO(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		psoError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handlePSOSubjects(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	result, err := s.svcs.Domain.PSOSubjects(r.Context(), r.URL.Query().Get("q"), r.URL.Query().Get("kind"))
	if err != nil {
		psoError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handlePSOWrite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		service.PSOChange
		Confirm bool `json:"confirm"`
	}
	var raw json.RawMessage
	if !decodePSO(w, r, &raw) {
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		writeJSON(w, 400, map[string]string{"error": "Нужен полный объект параметров PSO."})
		return
	}
	for _, key := range []string{"name", "description", "precedence", "minLength", "historyLength", "complexity", "minAgeDays", "maxAgeDays", "lockoutThreshold", "lockoutDurationMinutes", "lockoutWindowMinutes", "reversibleEncryption", "subjects", "confirm"} {
		v, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			writeJSON(w, 400, map[string]string{"error": "Для сохранения нужны все параметры PSO, назначения и подтверждение. Отсутствует поле: " + key})
			return
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&in) != nil {
		writeJSON(w, 400, map[string]string{"error": "Некорректные параметры PSO или неизвестные поля."})
		return
	}
	if !in.Confirm {
		writeJSON(w, 400, map[string]string{"error": "Подтвердите изменение PSO и её назначений."})
		return
	}
	sess := sessionFrom(r)
	var result *service.PSO
	var err error
	status := 200
	if r.Method == "POST" {
		result, err = s.svcs.Domain.CreatePSO(r.Context(), in.PSOChange, sess.Username, r.RemoteAddr)
		status = 201
	} else {
		result, err = s.svcs.Domain.UpdatePSO(r.Context(), chi.URLParam(r, "id"), in.PSOChange, sess.Username, r.RemoteAddr)
	}
	if err != nil {
		psoError(w, err)
		return
	}
	writeJSON(w, status, result)
}
func (s *Server) handlePSODelete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Revision string `json:"revision"`
		Confirm  bool   `json:"confirm"`
	}
	if !decodePSO(w, r, &in) {
		return
	}
	if !in.Confirm || in.Revision == "" {
		writeJSON(w, 400, map[string]string{"error": "Подтвердите удаление и укажите актуальную версию PSO."})
		return
	}
	sess := sessionFrom(r)
	if err := s.svcs.Domain.DeletePSO(r.Context(), chi.URLParam(r, "id"), in.Revision, sess.Username, r.RemoteAddr); err != nil {
		psoError(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "Удаление PSO подтверждено контроллером."})
}
func (s *Server) handleEffectivePasswordPolicy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	result, err := s.svcs.Domain.EffectivePasswordPolicy(r.Context(), chi.URLParam(r, "login"), s.loginController())
	if err != nil {
		psoError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
