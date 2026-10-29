package web

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/url"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
	"strings"
)

func apiResult(w http.ResponseWriter, result any, err error) {
	if err != nil {
		upstreamError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (s *Server) handleAPIGroupGet(w http.ResponseWriter, r *http.Request) {
	result, err := s.svcs.Groups.Show(r.Context(), routeParam(r, "name"))
	apiResult(w, result, err)
}
func (s *Server) handleAPIGroupMembers(w http.ResponseWriter, r *http.Request) {
	result, err := s.svcs.Groups.Members(r.Context(), routeParam(r, "name"))
	apiResult(w, result, err)
}
func (s *Server) handleAPIGroupMemberAdd(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		MemberDN string `json:"memberDN"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(in.MemberDN) == "" {
		writeJSON(w, 400, map[string]string{"error": "required fields are missing"})
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Groups.AddMember(r.Context(), routeParam(r, "name"), in.MemberDN, sess.Username, r.RemoteAddr)
	apiResult(w, map[string]string{"status": "ok"}, err)
}
func (s *Server) handleAPIGroupMemberRemove(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		MemberDN string `json:"memberDN"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(in.MemberDN) == "" {
		writeJSON(w, 400, map[string]string{"error": "required fields are missing"})
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Groups.RemoveMember(r.Context(), routeParam(r, "name"), in.MemberDN, sess.Username, r.RemoteAddr)
	apiResult(w, map[string]string{"status": "ok"}, err)
}
func (s *Server) handleAPIUserMove(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		ToOU string `json:"toOU"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(in.ToOU) == "" {
		writeJSON(w, 400, map[string]string{"error": "required fields are missing"})
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Users.Move(r.Context(), routeParam(r, "login"), in.ToOU, sess.Username, r.RemoteAddr)
	apiResult(w, map[string]string{"status": "ok"}, err)
}
func (s *Server) handleAPIComputerMove(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		ToOU string `json:"toOU"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(in.ToOU) == "" {
		writeJSON(w, 400, map[string]string{"error": "required fields are missing"})
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Computers.Move(r.Context(), routeParam(r, "name"), in.ToOU, sess.Username, r.RemoteAddr)
	apiResult(w, map[string]string{"status": "ok"}, err)
}
func (s *Server) handleAPIComputerGet(w http.ResponseWriter, r *http.Request) {
	result, err := s.svcs.Computers.Show(r.Context(), routeParam(r, "name"))
	apiResult(w, result, err)
}
func (s *Server) handleAPIOUMove(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		DN       string `json:"dn"`
		ToParent string `json:"toParent"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(in.DN) == "" || strings.TrimSpace(in.ToParent) == "" {
		writeJSON(w, 400, map[string]string{"error": "required fields are missing"})
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.OU.Move(r.Context(), in.DN, in.ToParent, sess.Username, r.RemoteAddr)
	apiResult(w, map[string]string{"status": "ok"}, err)
}
func (s *Server) handleAPISubnetDelete(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Subnet string `json:"subnet"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(in.Subnet) == "" {
		writeJSON(w, 400, map[string]string{"error": "required fields are missing"})
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Subnets.Delete(r.Context(), in.Subnet, sess.Username, r.RemoteAddr)
	apiResult(w, map[string]string{"status": "ok"}, err)
}
func (s *Server) handleAPIFSMOSeize(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(in.Role) == "" {
		writeJSON(w, 400, map[string]string{"error": "required fields are missing"})
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Domain.FSMOSeize(r.Context(), in.Role, sess.Username, r.RemoteAddr)
	apiResult(w, map[string]string{"status": "ok"}, err)
}
func (s *Server) handleAPILevelRaise(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Domain string `json:"domain"`
		Forest string `json:"forest"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil || (in.Domain == "" && in.Forest == "") {
		writeJSON(w, 400, map[string]string{"error": "domain or forest level required"})
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Domain.LevelRaise(r.Context(), in.Domain, in.Forest, sess.Username, r.RemoteAddr)
	apiResult(w, map[string]string{"status": "ok"}, err)
}
func (s *Server) handleAPIGPOGet(w http.ResponseWriter, r *http.Request) {
	result, err := s.svcs.GPO.Show(r.Context(), routeParam(r, "gpo"))
	apiResult(w, result, err)
}
func (s *Server) handleAPIGPOLinks(w http.ResponseWriter, r *http.Request) {
	dn := r.URL.Query().Get("container")
	if strings.TrimSpace(dn) == "" {
		writeJSON(w, 400, map[string]string{"error": "container required"})
		return
	}
	result, err := s.svcs.GPO.GetLinks(r.Context(), dn)
	apiResult(w, result, err)
}
func (s *Server) handleAPIDNSRecordUpdate(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in service.UpdateDNSRecordInput
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil || in.Name == "" || in.Type == "" || in.OldData == "" || in.NewData == "" {
		writeJSON(w, 400, map[string]string{"error": "name, type, oldData and newData required"})
		return
	}
	in.Zone = routeParam(r, "zone")
	sess := sessionFrom(r)
	err := s.svcs.DNS.UpdateRecord(r.Context(), in, sess.Username, r.RemoteAddr)
	apiResult(w, map[string]string{"status": "ok"}, err)
}
func (s *Server) handleAPIShareReload(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Shares.Reload(r.Context())
	if err != nil {
		s.audit.Failure(sess.Username, "share.reload", "", r.RemoteAddr, err)
	} else {
		s.audit.Success(sess.Username, "share.reload", "", r.RemoteAddr)
	}
	apiResult(w, map[string]string{"status": "ok"}, err)
}
func (s *Server) handleAPIShareParam(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	var in struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if strings.TrimSpace(in.Key) == "" || strings.TrimSpace(in.Value) == "" {
		writeJSON(w, 400, map[string]string{"error": "required fields are missing"})
		return
	}
	sess := sessionFrom(r)
	err := s.svcs.Shares.SetParam(r.Context(), routeParam(r, "name"), in.Key, in.Value, sess.Username, r.RemoteAddr)
	apiResult(w, map[string]string{"status": "ok"}, err)
}

func routeParam(r *http.Request, key string) string {
	v, _ := url.PathUnescape(chi.URLParam(r, key))
	return v
}

func (s *Server) handleAPIDNSNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.svcs.DNS.Nodes(r.Context(), routeParam(r, "zone"))
	apiResult(w, nodes, err)
}
