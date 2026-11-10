package web

import (
	"net/http"
	"sambaadm/internal/auth"
	"strconv"
)

func (s *Server) handleGPOEditorSettings(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", 400)
		return
	}
	if s.svcs == nil || s.svcs.GPO == nil {
		http.Error(w, "GPO service unavailable", 503)
		return
	}
	choice := r.FormValue("enabled")
	if choice != "" && choice != "true" {
		http.Error(w, "invalid editor setting", 400)
		return
	}
	enabled := choice == "true"
	if err := s.svcs.GPO.SetEditorEnabled(enabled); err != nil {
		if s.audit != nil {
			s.audit.Failure(sessionFrom(r).Username, "settings.gpo-editor", strconv.FormatBool(enabled), r.RemoteAddr, err)
		}
		current, _ := s.cfg.GPO.EffectiveEditorEnabled()
		pd := s.page(r, "settings.title", map[string]any{"EditorEnabled": current})
		pd.Error = "Не удалось сохранить настройку редактора GPO: " + err.Error()
		w.WriteHeader(http.StatusInternalServerError)
		s.render(w, "settings/index.html", pd)
		return
	}
	if s.audit != nil {
		s.audit.Success(sessionFrom(r).Username, "settings.gpo-editor", strconv.FormatBool(enabled), r.RemoteAddr)
	}
	http.Redirect(w, r, "/settings?gpo-editor=saved", http.StatusSeeOther)
}
