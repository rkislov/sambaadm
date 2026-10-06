package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

func (s *Server) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.svcs.Users.List(r.Context(), r.URL.Query().Get("ou"), r.URL.Query().Get("q"))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleAPIUserGet(w http.ResponseWriter, r *http.Request) {
	login, _ := url.PathUnescape(chi.URLParam(r, "login"))
	u, err := s.svcs.Users.Show(r.Context(), login)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleAPIUserCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.CreateUserInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sess := sessionFrom(r)
	u, err := s.svcs.Users.Create(r.Context(), in, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleAPIUserDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	login, _ := url.PathUnescape(chi.URLParam(r, "login"))
	sess := sessionFrom(r)
	if err := s.svcs.Users.Delete(r.Context(), login, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAPIUserEnable(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanHelpdesk) {
		return
	}
	login, _ := url.PathUnescape(chi.URLParam(r, "login"))
	sess := sessionFrom(r)
	if err := s.svcs.Users.Enable(r.Context(), login, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	s.respondUserFragment(w, r, login)
}

func (s *Server) handleAPIUserDisable(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanHelpdesk) {
		return
	}
	login, _ := url.PathUnescape(chi.URLParam(r, "login"))
	sess := sessionFrom(r)
	if err := s.svcs.Users.Disable(r.Context(), login, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	s.respondUserFragment(w, r, login)
}

func (s *Server) handleAPIUserPassword(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanHelpdesk) {
		return
	}
	login, _ := url.PathUnescape(chi.URLParam(r, "login"))
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password required"})
		return
	}
	sess := sessionFrom(r)
	if err := s.svcs.Users.SetPassword(r.Context(), login, body.Password, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) respondUserFragment(w http.ResponseWriter, r *http.Request, login string) {
	u, err := s.svcs.Users.Show(r.Context(), login)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		s.render(w, "users/row.html", u)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleAPIGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.svcs.Groups.List(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

func (s *Server) handleAPIGroupCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.CreateGroupInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sess := sessionFrom(r)
	g, err := s.svcs.Groups.Create(r.Context(), in, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) handleAPIGroupDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	sess := sessionFrom(r)
	if err := s.svcs.Groups.Delete(r.Context(), name, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAPIComputers(w http.ResponseWriter, r *http.Request) {
	computers, err := s.svcs.Computers.List(r.Context(), r.URL.Query().Get("q"))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, computers)
}

func (s *Server) handleAPIComputerDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	sess := sessionFrom(r)
	if err := s.svcs.Computers.Delete(r.Context(), name, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAPIOUs(w http.ResponseWriter, r *http.Request) {
	ous, err := s.svcs.OU.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, ous)
}

func (s *Server) handleAPIOUCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.CreateOUInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sess := sessionFrom(r)
	ou, err := s.svcs.OU.Create(r.Context(), in, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, ou)
}

func (s *Server) handleAPIOUDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	dn := r.URL.Query().Get("dn")
	if dn == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "dn query param required"})
		return
	}
	sess := sessionFrom(r)
	if err := s.svcs.OU.Delete(r.Context(), dn, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAPIDomain(w http.ResponseWriter, r *http.Request) {
	info, err := s.svcs.Domain.Info(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func requireRole(w http.ResponseWriter, r *http.Request, check func(auth.Role) bool) bool {
	sess := sessionFrom(r)
	if sess == nil || !check(sess.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return false
	}
	return true
}
