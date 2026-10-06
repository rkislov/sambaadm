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

func (s *Server) handleAPITrusts(w http.ResponseWriter, r *http.Request) {
	trusts, err := s.svcs.Trusts.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, trusts)
}

func (s *Server) handleAPITrustCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.CreateTrustInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	sess := sessionFrom(r)
	if err := s.svcs.Trusts.Create(r.Context(), in, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "domain": in.Domain})
}

func (s *Server) handleAPITrustDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	domain, _ := url.PathUnescape(chi.URLParam(r, "domain"))
	sess := sessionFrom(r)
	if err := s.svcs.Trusts.Delete(r.Context(), domain, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAPITrustValidate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	domain, _ := url.PathUnescape(chi.URLParam(r, "domain"))
	sess := sessionFrom(r)
	out, err := s.svcs.Trusts.Validate(r.Context(), domain, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "output": out})
}

func (s *Server) handleAPIFSMO(w http.ResponseWriter, r *http.Request) {
	roles, err := s.svcs.Domain.FSMOShow(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, roles)
}

func (s *Server) handleAPIFSMOTransfer(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Role == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role required"})
		return
	}
	sess := sessionFrom(r)
	if err := s.svcs.Domain.FSMOTransfer(r.Context(), body.Role, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "transferred", "role": body.Role})
}

func (s *Server) handleAPIDomainLevel(w http.ResponseWriter, r *http.Request) {
	lvl, err := s.svcs.Domain.LevelShow(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, lvl)
}

func (s *Server) handleAPIReplPartners(w http.ResponseWriter, r *http.Request) {
	partners, err := s.svcs.Repl.Partners(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, partners)
}

func (s *Server) handleAPIReplStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.svcs.Repl.Status(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) handleAPIReplSync(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var body struct {
		From string `json:"from"`
		Dest string `json:"dest,omitempty"`
		NC   string `json:"nc,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.From == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from required"})
		return
	}
	sess := sessionFrom(r)
	var err error
	if body.Dest == "" {
		err = s.svcs.Repl.SyncFrom(r.Context(), body.From, sess.Username, r.RemoteAddr)
	} else {
		err = s.svcs.Repl.Sync(r.Context(), body.Dest, body.From, body.NC, sess.Username, r.RemoteAddr)
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "synced"})
}

func (s *Server) handleAPISites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.svcs.Sites.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sites)
}

func (s *Server) handleAPISiteCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	sess := sessionFrom(r)
	site, err := s.svcs.Sites.Create(r.Context(), body.Name, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, site)
}

func (s *Server) handleAPISiteDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	name, _ := url.PathUnescape(chi.URLParam(r, "name"))
	sess := sessionFrom(r)
	if err := s.svcs.Sites.Delete(r.Context(), name, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAPISubnets(w http.ResponseWriter, r *http.Request) {
	subnets, err := s.svcs.Subnets.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, subnets)
}

func (s *Server) handleAPISubnetCreate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var body struct {
		Subnet string `json:"subnet"`
		Site   string `json:"site"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Subnet == "" || body.Site == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "subnet and site required"})
		return
	}
	sess := sessionFrom(r)
	sub, err := s.svcs.Subnets.Create(r.Context(), body.Subnet, body.Site, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, sub)
}

func requireRole(w http.ResponseWriter, r *http.Request, check func(auth.Role) bool) bool {
	sess := sessionFrom(r)
	if sess == nil || !check(sess.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return false
	}
	return true
}
