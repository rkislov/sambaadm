package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) sharePermissionMapPage(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	share, err := s.svcs.Shares.Show(r.Context(), name)
	if err != nil {
		http.Error(w, err.Error(), 404)
		return
	}
	pd := s.page(r, "shares.acl", map[string]any{"Share": share, "Root": r.URL.Query().Get("path")})
	s.render(w, "shares/permission-map.html", pd)
}
func shareMapResult(w http.ResponseWriter, result any, err error) {
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		status := 400
		if errors.Is(err, service.ErrShareMapConflict) || strings.Contains(err.Error(), service.ErrShareMapConflict.Error()) {
			status = 409
		}
		writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) handleSharePermissionMap(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	snapshot, err := s.svcs.Shares.PermissionMap(ctx, chi.URLParam(r, "name"), r.URL.Query().Get("path"))
	shareMapResult(w, snapshot, err)
}
func (s *Server) handleSharePermissionPlan(w http.ResponseWriter, r *http.Request) {
	s.handleSharePermissionTemplate(w, r, false)
}
func (s *Server) handleSharePermissionApply(w http.ResponseWriter, r *http.Request) {
	s.handleSharePermissionTemplate(w, r, true)
}
func (s *Server) handleSharePermissionTemplate(w http.ResponseWriter, r *http.Request, apply bool) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.SharePermissionMapRequest
	if !topologyJSON(w, r, &in) {
		return
	}
	if in.SnapshotRevision == "" || apply && (!in.Confirm || in.PlanRevision == "") {
		shareMapResult(w, nil, fmt.Errorf("требуются версия снимка, предпросмотр и подтверждение применения"))
		return
	}
	if len(in.Overlays) == 0 || len(in.Overlays) > 64 {
		shareMapResult(w, nil, fmt.Errorf("выберите 1–64 наложения"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
	defer cancel()
	// Resolve every group again on apply; supplied GIDs are never trusted.
	resolved := map[string]map[string]string{}
	for i := range in.Overlays {
		template := &in.Overlays[i].Template
		if len(template.Rules) == 0 || len(template.Rules) > 32 {
			shareMapResult(w, nil, fmt.Errorf("выберите 1–32 группы шаблона"))
			return
		}
		for j := range template.Rules {
			rule := &template.Rules[j]
			group, ok := resolved[rule.Group]
			if !ok {
				var err error
				group, err = s.svcs.ResolveFileGroup(ctx, rule.Group)
				if err != nil {
					shareMapResult(w, nil, err)
					return
				}
				resolved[rule.Group] = group
			}
			rule.GID = group["gid"]
		}
	}
	if !apply {
		plan, err := s.svcs.Shares.PlanPermissionMap(ctx, chi.URLParam(r, "name"), in)
		shareMapResult(w, plan, err)
		return
	}
	sess := sessionFrom(r)
	result, err := s.svcs.Shares.ApplyPermissionMap(ctx, chi.URLParam(r, "name"), in, sess.Username, r.RemoteAddr, s.cfg.Helper.StateDir)
	shareMapResult(w, result, err)
}
