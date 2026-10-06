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

func (s *Server) handleAPIDNSZones(w http.ResponseWriter, r *http.Request) {
	zones, err := s.svcs.DNS.ListZones(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, zones)
}

func (s *Server) handleAPIDNSZoneCreate(w http.ResponseWriter, r *http.Request) {
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
	if err := s.svcs.DNS.CreateZone(r.Context(), body.Name, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "name": body.Name})
}

func (s *Server) handleAPIDNSZoneDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	zone, _ := url.PathUnescape(chi.URLParam(r, "zone"))
	sess := sessionFrom(r)
	if err := s.svcs.DNS.DeleteZone(r.Context(), zone, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAPIDNSRecords(w http.ResponseWriter, r *http.Request) {
	zone, _ := url.PathUnescape(chi.URLParam(r, "zone"))
	recs, err := s.svcs.DNS.QueryRecords(r.Context(), zone, r.URL.Query().Get("name"), r.URL.Query().Get("type"))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, recs)
}

func (s *Server) handleAPIDNSRecordAdd(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	zone, _ := url.PathUnescape(chi.URLParam(r, "zone"))
	var in service.AddDNSRecordInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	in.Zone = zone
	sess := sessionFrom(r)
	if err := s.svcs.DNS.AddRecord(r.Context(), in, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (s *Server) handleAPIDNSRecordDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	zone, _ := url.PathUnescape(chi.URLParam(r, "zone"))
	var in service.AddDNSRecordInput
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	in.Zone = zone
	sess := sessionFrom(r)
	if err := s.svcs.DNS.DeleteRecord(r.Context(), in, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAPIGPOs(w http.ResponseWriter, r *http.Request) {
	gpos, err := s.svcs.GPO.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, gpos)
}

func (s *Server) handleAPIGPOCreate(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.svcs.GPO.Create(r.Context(), body.Name, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created", "output": out})
}

func (s *Server) handleAPIGPODelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	gpo, _ := url.PathUnescape(chi.URLParam(r, "gpo"))
	sess := sessionFrom(r)
	if err := s.svcs.GPO.Delete(r.Context(), gpo, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *Server) handleAPIGPOLink(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	gpo, _ := url.PathUnescape(chi.URLParam(r, "gpo"))
	var body struct {
		Container string `json:"container"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Container == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "container required"})
		return
	}
	sess := sessionFrom(r)
	if err := s.svcs.GPO.Link(r.Context(), body.Container, gpo, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "linked"})
}

func (s *Server) handleAPIGPOUnlink(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	gpo, _ := url.PathUnescape(chi.URLParam(r, "gpo"))
	var body struct {
		Container string `json:"container"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Container == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "container required"})
		return
	}
	sess := sessionFrom(r)
	if err := s.svcs.GPO.Unlink(r.Context(), body.Container, gpo, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlinked"})
}

func (s *Server) handleAPIGPOBackup(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	gpo, _ := url.PathUnescape(chi.URLParam(r, "gpo"))
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path required"})
		return
	}
	sess := sessionFrom(r)
	if err := s.svcs.GPO.Backup(r.Context(), gpo, body.Path, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "backed_up"})
}

func (s *Server) handleAPIGPORestore(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	gpo, _ := url.PathUnescape(chi.URLParam(r, "gpo"))
	var body struct {
		Path string `json:"path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path required"})
		return
	}
	sess := sessionFrom(r)
	if err := s.svcs.GPO.Restore(r.Context(), gpo, body.Path, sess.Username, r.RemoteAddr); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "restored"})
}

func (s *Server) handleAPIGPODistribute(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	gpo, _ := url.PathUnescape(chi.URLParam(r, "gpo"))
	sess := sessionFrom(r)
	job, err := s.svcs.GPO.StartDistribute(r.Context(), gpo, sess.Username, r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		s.render(w, "gpo/job.html", job)
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) handleAPIGPODistributeStatus(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobID")
	job, ok := s.svcs.GPO.GetDistributeJob(jobID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		s.render(w, "gpo/job.html", job)
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func requireRole(w http.ResponseWriter, r *http.Request, check func(auth.Role) bool) bool {
	sess := sessionFrom(r)
	if sess == nil || !check(sess.Role) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return false
	}
	return true
}
