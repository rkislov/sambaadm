package web

import (
	"encoding/json"
	"io"
	"net/http"

	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleDomainPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		out, e := s.svcs.Domain.PasswordPolicy(r.Context())
		if e != nil {
			editorError(w, e)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, out)
		return
	}
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var wire struct {
		Revision string          `json:"revision"`
		Policy   json.RawMessage `json:"policy"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&wire) != nil || dec.Decode(&struct{}{}) != io.EOF || wire.Revision == "" {
		writeJSON(w, 400, map[string]string{"error": "revision and complete policy are required"})
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(wire.Policy, &fields) != nil || len(fields) != 8 {
		writeJSON(w, 400, map[string]string{"error": "all password policy values are required"})
		return
	}
	for _, key := range []string{"minLength", "historyLength", "complexity", "minAgeDays", "maxAgeDays", "lockoutThreshold", "lockoutDurationMinutes", "lockoutWindowMinutes"} {
		if raw, ok := fields[key]; !ok || string(raw) == "null" {
			writeJSON(w, 400, map[string]string{"error": "all password policy values are required"})
			return
		}
	}
	in := service.PasswordPolicyChange{Revision: wire.Revision}
	if json.Unmarshal(wire.Policy, &in.Policy) != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid password policy values"})
		return
	}
	sess := sessionFrom(r)
	out, e := s.svcs.Domain.SetPasswordPolicy(r.Context(), in, sess.Username, r.RemoteAddr)
	if e != nil {
		editorError(w, e)
		return
	}
	writeJSON(w, 200, out)
}
