package web

import (
	"errors"
	"github.com/go-chi/chi/v5"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
	"strings"
)

func (s *Server) sysvolSyncPage(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	s.render(w, "sysvol-sync.html", s.page(r, "settings.title", nil))
}
func (s *Server) handleSYSVOLSync(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	id := chi.URLParam(r, "id")
	if r.Method == http.MethodGet {
		if id != "" {
			out, e := s.svcs.GPO.SYSVOLSyncRead(id)
			topologyResult(w, out, e)
			return
		}
		dcs, e := s.svcs.Sites.Controllers(r.Context())
		if e != nil {
			topologyResult(w, nil, e)
			return
		}
		policies, e := s.svcs.GPO.List(r.Context())
		if e != nil {
			topologyResult(w, nil, e)
			return
		}
		cfg, e := s.svcs.Helpers.Configuration()
		if e != nil {
			topologyResult(w, nil, e)
			return
		}
		targets := []string{}
		for _, dc := range dcs {
			for _, node := range cfg.Nodes {
				if strings.EqualFold(node.Name, dc.DNS) {
					targets = append(targets, dc.DNS)
					break
				}
			}
		}
		history, e := s.svcs.GPO.SYSVOLSyncHistory()
		if e != nil {
			topologyResult(w, nil, e)
			return
		}
		writeJSON(w, 200, map[string]any{"controllers": dcs, "targets": targets, "policies": policies, "history": history})
		return
	}
	sess := sessionFrom(r)
	if id == "" {
		var in service.SYSVOLSyncInput
		if !topologyJSON(w, r, &in) {
			return
		}
		out, e := s.svcs.GPO.SYSVOLSyncPlan(r.Context(), in, sess.Username, r.RemoteAddr)
		topologyResult(w, out, e)
		return
	}
	var in struct {
		Revision string `json:"revision"`
		Confirm  bool   `json:"confirm"`
	}
	if !topologyJSON(w, r, &in) {
		return
	}
	out, e := s.svcs.GPO.SYSVOLSyncApply(r.Context(), id, in.Revision, sess.Username, r.RemoteAddr, in.Confirm)
	if errors.Is(e, service.ErrGPOBulkDeliveryActive) {
		writeJSON(w, 409, map[string]string{"error": e.Error()})
		return
	}
	topologyResult(w, out, e)
}
