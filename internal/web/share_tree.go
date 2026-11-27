package web

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

func shareDefaultACL(r *http.Request, spec string) string {
	if r.FormValue("domain_group") != "" && formOn(r, "group_default") {
		return spec
	}
	return r.FormValue("default_acl")
}

func (s *Server) handleShareDirectories(w http.ResponseWriter, r *http.Request) {
	offset := 0
	if value := r.URL.Query().Get("offset"); value != "" {
		var err error
		offset, err = strconv.Atoi(value)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid offset"})
			return
		}
	}
	result, err := s.svcs.Shares.Directories(r.Context(), chi.URLParam(r, "name"), r.URL.Query().Get("path"), offset)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, result)
}
