package web

import (
	"encoding/json"
	"io"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
	"strconv"
	"strings"
)

type keaPageContent struct {
	Nodes  []string
	Domain string
}

func (s *Server) keaClient() service.KeaService {
	c := service.KeaService{Audit: s.audit}
	if s.svcs != nil {
		c.Helpers = s.svcs.Helpers
	}
	return c
}
func (s *Server) handleKea(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, "dhcp/index.html", s.page(r, "DHCP — Kea", keaPageContent{Nodes: s.timePageNodes(), Domain: dnsFromBaseDN(s.cfg.LDAP.BaseDN)}))
}
func (s *Server) handleAPIKea(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if strings.HasPrefix(r.URL.Path, "/api/v1/dhcp/gss/ad/") && sessionFrom(r).AuthMethod == "kerberos" {
		writeJSON(w, 409, map[string]string{"error": "для настройки AD/keytab войдите по паролю с правами управления служебной учётной записью и ACL DNS-зон"})
		return
	}
	req := service.KeaRequest{Family: r.URL.Query().Get("family")}
	method := "kea.inspect"
	var out any = &service.KeaStatus{}
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/dhcp/gss/install/status" {
		method = "kea.gss.install.status"
		req.JobID = r.URL.Query().Get("jobID")
		out = &service.KeaGSSJob{}
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/dhcp/ddns" {
		method = "kea.ddns.inspect"
		out = &service.KeaDDNSStatus{}
	}
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/dhcp/leases" {
		method = "kea.leases"
		out = &service.KeaLeasePage{}
		req.From = r.URL.Query().Get("from")
		req.Search = r.URL.Query().Get("search")
		if value := r.URL.Query().Get("subnetID"); value != "" {
			n, e := strconv.ParseUint(value, 10, 32)
			if e != nil || n == 0 {
				writeJSON(w, 400, map[string]string{"error": "неверный ID области"})
				return
			}
			req.SubnetID = uint32(n)
		}
	}
	if r.Method != http.MethodGet {
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
		d.DisallowUnknownFields()
		if d.Decode(&req) != nil || d.Decode(&struct{}{}) != io.EOF {
			writeJSON(w, 400, map[string]string{"error": "неверный запрос Kea"})
			return
		}
		if req.GSSSecret != "" || req.GSSJoin {
			writeJSON(w, 400, map[string]string{"error": "внутренние параметры HA не принимаются из браузера"})
			return
		}
		if r.URL.Path == "/api/v1/dhcp/gss/ad/pair/plan" || r.URL.Path == "/api/v1/dhcp/gss/ad/pair/apply" {
			s.handleKeaGSSPair(w, r, req)
			return
		}
		switch r.URL.Path {
		case "/api/v1/dhcp/gss/install/plan":
			method = "kea.gss.install.plan"
			out = &json.RawMessage{}
		case "/api/v1/dhcp/gss/install/start":
			method = "kea.gss.install.start"
			out = &service.KeaGSSJob{}
		case "/api/v1/dhcp/gss/ad/plan":
			method = "kea.gss.ad.plan"
			out = &json.RawMessage{}
		case "/api/v1/dhcp/gss/ad/apply":
			method = "kea.gss.ad.apply"
			out = &json.RawMessage{}
		case "/api/v1/dhcp/ddns/plan":
			method = "kea.ddns.plan"
			out = &service.KeaDDNSPlan{}
		case "/api/v1/dhcp/ddns/apply":
			method = "kea.ddns.apply"
			out = &service.KeaDDNSResult{}
		case "/api/v1/dhcp/ddns/service":
			method = "kea.ddns.service"
			out = &service.KeaDDNSResult{}
		case "/api/v1/dhcp/leases/delete":
			method = "kea.lease.delete"
			out = &service.KeaResult{}
		case "/api/v1/dhcp/leases/reservation/plan":
			method = "kea.lease.reserve.plan"
			out = &service.KeaPlan{}
		case "/api/v1/dhcp/plan":
			method = "kea.plan"
			out = &service.KeaPlan{}
		case "/api/v1/dhcp/apply":
			method = "kea.apply"
			out = &service.KeaResult{}
		case "/api/v1/dhcp/service":
			method = "kea.service"
			out = &service.KeaResult{}
		case "/api/v1/dhcp/install/plan":
			method = "kea.install.plan"
			out = &service.KeaPlan{}
		case "/api/v1/dhcp/install":
			method = "kea.install"
			out = &service.KeaResult{}
		default:
			http.NotFound(w, r)
			return
		}
	}
	sess := sessionFrom(r)
	if e := s.keaClient().Call(r.Context(), r.URL.Query().Get("node"), method, req, sess.Username, r.RemoteAddr, out); e != nil {
		writeJSON(w, 409, map[string]string{"error": e.Error()})
		return
	}
	writeJSON(w, 200, out)
}
