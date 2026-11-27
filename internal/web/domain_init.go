package web

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"sambaadm/internal/auth"
	"sambaadm/internal/domaininit"
	"sambaadm/internal/pki"
	"sambaadm/internal/service"
	"strings"
	"time"
)

func domainInitAssets() http.Handler {
	files, _ := fs.Sub(domaininit.Files, "assets")
	return http.StripPrefix("/domain-init-assets/", http.FileServer(http.FS(files)))
}
func (s *Server) domainInitPage(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	s.render(w, "domain-init.html", s.page(r, "settings.title", nil))
}
func (s *Server) handleDomainInit(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		if r.URL.Query().Get("id") != "" {
			var out any
			err := s.svcs.Helpers.Call(r.Context(), r.URL.Query().Get("node"), "domain.init.status", service.HostOperation{Name: r.URL.Query().Get("id")}, &out)
			if err != nil {
				upstreamError(w, err)
				return
			}
			writeJSON(w, 200, out)
			return
		}
		cfg, err := s.svcs.Helpers.Configuration()
		if err != nil {
			upstreamError(w, err)
			return
		}
		sites, err := s.svcs.Sites.List(r.Context())
		if err != nil {
			upstreamError(w, err)
			return
		}
		dcs, err := s.svcs.Sites.Controllers(r.Context())
		if err != nil {
			upstreamError(w, err)
			return
		}
		info, err := s.svcs.Domain.Info(r.Context())
		if err != nil {
			upstreamError(w, err)
			return
		}
		nodes := make([]map[string]string, 0, len(cfg.Nodes))
		for _, node := range cfg.Nodes {
			nodes = append(nodes, map[string]string{"name": node.Name})
		}
		writeJSON(w, 200, map[string]any{"realm": dnsFromBaseDN(s.cfg.LDAP.BaseDN), "netbios": info.NetBIOS, "nodes": nodes, "sites": sites, "controllers": dcs})
		return
	}
	var request struct {
		Node string `json:"node"`
		domaininit.Input
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		writeJSON(w, 400, map[string]string{"error": "Некорректные параметры"})
		return
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "Некорректные параметры"})
		return
	}
	realm := dnsFromBaseDN(s.cfg.LDAP.BaseDN)
	if (request.Mode != "DC" && request.Mode != "RODC" && request.Mode != "member") || request.Realm != realm || !strings.EqualFold(request.Node, request.Hostname+"."+realm) {
		writeJSON(w, 400, map[string]string{"error": "Выберите новый сервер в текущем домене"})
		return
	}
	// Sites and the replication source come from AD, not arbitrary request values.
	sites, err := s.svcs.Sites.List(r.Context())
	if err != nil {
		upstreamError(w, err)
		return
	}
	found := request.Mode == "member"
	for _, site := range sites {
		if site.Name == request.Site {
			found = true
		}
	}
	dcs, err := s.svcs.Sites.Controllers(r.Context())
	if err != nil {
		upstreamError(w, err)
		return
	}
	source := false
	for _, dc := range dcs {
		if strings.EqualFold(dc.DNS, request.Node) {
			writeJSON(w, 409, map[string]string{"error": "Этот сервер уже является контроллером домена"})
			return
		}
		if !dc.RODC && strings.EqualFold(dc.DNS, request.Source) {
			source = true
		}
	}
	if !found || !source {
		writeJSON(w, 400, map[string]string{"error": "Выберите существующий сайт и исходный RWDC"})
		return
	}
	action := "plan"
	if strings.HasSuffix(r.URL.Path, "/start") {
		action = "start"
	}
	raw, _ := json.Marshal(request.Input)
	defer clear(raw)
	ctx, cancel := context.WithTimeout(r.Context(), 190*time.Second)
	defer cancel()
	if action == "start" && request.Mode != "member" {
		_, _, ca, err := pki.LoadAuthority(s.cfg.Server.CertificateDir)
		if err != nil {
			upstreamError(w, err)
			return
		}
		if err = domaininit.ValidateCertificate(request.Input, ca); err != nil {
			writeJSON(w, 409, map[string]string{"error": err.Error()})
			return
		}
	}
	var out domaininit.Plan
	if action == "start" {
		var status any
		err = s.svcs.Helpers.Call(ctx, request.Node, "domain.init.start", service.HostOperation{Input: raw, Actor: sessionFrom(r).Username, IP: r.RemoteAddr}, &status)
		if err != nil {
			upstreamError(w, err)
			return
		}
		if s.audit != nil {
			s.audit.Success(sessionFrom(r).Username, "domain.init.start", request.Node, r.RemoteAddr)
		}
		writeJSON(w, 202, status)
		return
	}
	err = s.svcs.Helpers.Call(ctx, request.Node, "domain.init."+action, service.HostOperation{Input: raw, Actor: sessionFrom(r).Username, IP: r.RemoteAddr}, &out)
	if err != nil {
		upstreamError(w, err)
		return
	}
	if request.Mode != "member" {
		if err = domaininit.SignPlan(&out, request.Input, s.cfg.Server.CertificateDir); err != nil {
			upstreamError(w, err)
			return
		}
	}
	if s.audit != nil {
		s.audit.Success(sessionFrom(r).Username, "domain.init."+action, request.Node, r.RemoteAddr)
	}
	writeJSON(w, 200, out)
}
