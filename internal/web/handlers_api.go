package web

import (
	"net/http"
)

func (s *Server) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.svcs.Users.List(r.Context(), r.URL.Query().Get("ou"), r.URL.Query().Get("q"))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleAPIGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.svcs.Groups.List(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

func (s *Server) handleAPIDomain(w http.ResponseWriter, r *http.Request) {
	info, err := s.svcs.Domain.Info(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, info)
}
