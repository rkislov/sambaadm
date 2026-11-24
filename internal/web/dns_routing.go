package web

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"io"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/service"
	"strings"
)

func (s *Server) handleDNSRouting(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	pd := s.page(r, "Маршрутизация DNS", nil)
	pd.Active = "/dns"
	s.render(w, "dns/routing.html", pd)
}
func dnsDecode(w http.ResponseWriter, r *http.Request, out any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "некорректные параметры DNS"})
		return false
	}
	return true
}
func (s *Server) handleDNSDelegations(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	zone := chi.URLParam(r, "zone")
	var out any
	var err error
	if r.Method == http.MethodGet {
		out, err = s.svcs.DNS.Delegations(r.Context(), zone)
	} else {
		var in service.DNSDelegationInput
		if !dnsDecode(w, r, &in) {
			return
		}
		in.Zone = zone
		if r.Method == http.MethodPut {
			sess := sessionFrom(r)
			out, err = s.svcs.DNS.ApplyDelegation(r.Context(), in, sess.Username, r.RemoteAddr)
		} else {
			out, err = s.svcs.DNS.PlanDelegation(r.Context(), in)
		}
	}
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleDNSForward(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	node := r.URL.Query().Get("node")
	if s.svcs.Helpers == nil || !s.svcs.Helpers.Has(node) {
		writeJSON(w, 409, map[string]string{"error": "выберите сервер с зарегистрированным helper"})
		return
	}
	var req service.DNSForwardRequest
	method := "dns.forward.inspect"
	var out any = &service.DNSForwardStatus{}
	if r.Method != http.MethodGet {
		if !dnsDecode(w, r, &req) {
			return
		}
		zones, e := s.svcs.DNS.ListZones(r.Context())
		if e != nil {
			writeJSON(w, 502, map[string]string{"error": e.Error()})
			return
		}
		states := map[string]*service.DNSDelegationState{}
		for _, rule := range req.Rules {
			name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rule.Domain), "."))
			parent := ""
			for _, zone := range zones {
				z := strings.ToLower(strings.TrimSuffix(zone.Name, "."))
				if name == z || strings.HasSuffix(z, "."+name) {
					writeJSON(w, 409, map[string]string{"error": "нельзя пересылать запросы собственной AD-зоны или её родителя: " + zone.Name})
					return
				}
				if strings.HasSuffix(name, "."+z) && len(z) > len(parent) {
					parent = z
				}
			}
			if parent != "" {
				state := states[parent]
				if state == nil {
					var err error
					state, err = s.svcs.DNS.Delegations(r.Context(), parent)
					if err != nil {
						writeJSON(w, 502, map[string]string{"error": err.Error()})
						return
					}
					states[parent] = state
				}
				delegated := false
				for _, d := range state.Delegations {
					if name == d.Domain || strings.HasSuffix(name, "."+d.Domain) {
						delegated = true
						break
					}
				}
				if !delegated {
					writeJSON(w, 409, map[string]string{"error": "для " + name + " сначала создайте делегирование в зоне " + parent + " на вкладке «Делегирование»; иначе BIND9 DLZ вернёт NXDOMAIN"})
					return
				}
			}
		}
		method = "dns.forward.plan"
		out = &service.DNSForwardPlan{}
		if r.Method == http.MethodPut {
			method = "dns.forward.apply"
			out = &service.DNSForwardResult{}
		}
	}
	sess := sessionFrom(r)
	e := s.svcs.Helpers.Call(r.Context(), node, method, service.HostOperation{Input: mustDNSJSON(req), Actor: sess.Username, IP: r.RemoteAddr}, out)
	if r.Method == http.MethodPut {
		if e != nil {
			s.audit.Failure(sess.Username, method, node, r.RemoteAddr, e)
		} else {
			s.audit.Success(sess.Username, method, node, r.RemoteAddr)
		}
	}
	if e != nil {
		writeJSON(w, 409, map[string]string{"error": e.Error() + ". Проверьте версию helper на выбранном сервере."})
		return
	}
	writeJSON(w, 200, out)
}
func mustDNSJSON(in any) json.RawMessage { v, _ := json.Marshal(in); return v }
func (s *Server) handleDNSRoutingNodes(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	writeJSON(w, 200, s.timePageNodes())
}

func (s *Server) handleDNSBackend(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	node := r.URL.Query().Get("node")
	if s.svcs.Helpers == nil || !s.svcs.Helpers.Has(node) {
		writeJSON(w, 409, map[string]string{"error": "выберите сервер с зарегистрированным helper"})
		return
	}
	var in service.DNSBackendInput
	method := "dns.backend.plan"
	if r.Method == http.MethodGet {
		in.ID = r.URL.Query().Get("id")
		method = "dns.backend.status"
	} else {
		if !dnsDecode(w, r, &in) {
			return
		}
		if strings.HasSuffix(r.URL.Path, "/start") {
			method = "dns.backend.start"
		}
	}
	sess := sessionFrom(r)
	var out any
	err := s.svcs.Helpers.Call(r.Context(), node, method, service.HostOperation{Input: mustDNSJSON(in), Actor: sess.Username, IP: r.RemoteAddr}, &out)
	if method == "dns.backend.start" {
		if err != nil {
			s.audit.Failure(sess.Username, method, node, r.RemoteAddr, err)
		} else {
			s.audit.Success(sess.Username, method, node, r.RemoteAddr)
		}
	}
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, out)
}
