package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) callDomainRestore(r *http.Request, node, method string, in service.DomainRestoreInput, out any) error {
	if s.svcs == nil || s.svcs.Helpers == nil {
		return fmt.Errorf("registered recovery helper required")
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	err = s.svcs.Helpers.Call(r.Context(), node, method, service.HostOperation{Name: in.ID, Input: raw, Actor: sessionFrom(r).Username, IP: r.RemoteAddr}, out)
	if s.audit != nil && method != "domain.restore.status" {
		if err != nil {
			s.audit.Failure(sessionFrom(r).Username, method, node+" "+in.BackupID+" "+in.ID, r.RemoteAddr, err)
		} else {
			s.audit.Success(sessionFrom(r).Username, method, node+" "+in.BackupID+" "+in.ID, r.RemoteAddr)
		}
	}
	return err
}
func (s *Server) handleAPIDomainRestore(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	node := r.URL.Query().Get("node")
	var in service.DomainRestoreInput
	fail := func(err error) { writeJSON(w, 400, map[string]string{"error": err.Error()}) }
	if r.Method == http.MethodGet {
		in.ID = r.URL.Query().Get("id")
		var out service.DomainRestoreJob
		if err := s.callDomainRestore(r, node, "domain.restore.status", in, &out); err != nil {
			fail(err)
			return
		}
		writeJSON(w, 200, out)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		fail(err)
		return
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	method := "domain.restore.plan"
	if r.URL.Path == "/api/v1/backups/restore/start" {
		method = "domain.restore.start"
	}
	var out any
	if method == "domain.restore.plan" {
		out = &service.DomainRestorePlan{}
	} else {
		out = &service.DomainRestoreJob{}
	}
	err := s.callDomainRestore(r, node, method, in, out)
	if err != nil {
		fail(err)
		return
	}
	status := 200
	if method == "domain.restore.start" {
		status = 202
	}
	writeJSON(w, status, out)
}
