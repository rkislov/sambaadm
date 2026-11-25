package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sambaadm/internal/auth"
	"sambaadm/internal/dcdemote"
	"sambaadm/internal/service"
	"strings"
	"time"
)

func (s *Server) domainDemotePage(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	s.render(w, "domain-demote.html", s.page(r, "settings.title", nil))
}
func (s *Server) handleDomainDemote(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		if r.URL.Query().Get("id") != "" {
			var out any
			err := s.demoteCall(r.Context(), r.URL.Query().Get("node"), "domain.demote.status", service.HostOperation{Name: r.URL.Query().Get("id")}, &out)
			if err != nil {
				upstreamError(w, err)
				return
			}
			writeJSON(w, 200, out)
			return
		}
		controllers, err := s.svcs.Sites.Controllers(r.Context())
		if err != nil {
			upstreamError(w, err)
			return
		}
		cfg, err := s.svcs.Helpers.Configuration()
		if err != nil {
			upstreamError(w, err)
			return
		}
		nodes := []string{}
		for _, node := range cfg.Nodes {
			nodes = append(nodes, node.Name)
		}
		writeJSON(w, 200, map[string]any{"realm": dnsFromBaseDN(s.cfg.LDAP.BaseDN), "controllers": controllers, "nodes": nodes})
		return
	}
	var in dcdemote.Input
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(&struct{}{}) != io.EOF {
		writeJSON(w, 400, map[string]string{"error": "Некорректные параметры"})
		return
	}
	if err := in.Validate(); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if in.Realm != dnsFromBaseDN(s.cfg.LDAP.BaseDN) {
		writeJSON(w, 400, map[string]string{"error": "Выберите контроллер текущего домена"})
		return
	}
	// Removing the panel's LDAP backend would invalidate management mid-operation.
	backend, _ := url.Parse(s.cfg.LDAP.URI)
	usesTarget := backend != nil && strings.EqualFold(backend.Hostname(), in.Node)
	if backend != nil && backend.Hostname() != "" && !usesTarget && !strings.HasSuffix(r.URL.Path, "/resume") {
		lookup, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		backendIPs, backendErr := net.DefaultResolver.LookupNetIP(lookup, "ip", backend.Hostname())
		nodeIPs, nodeErr := net.DefaultResolver.LookupNetIP(lookup, "ip", in.Node)
		cancel()
		if backendErr != nil || nodeErr != nil {
			writeJSON(w, 409, map[string]string{"error": "Не удалось проверить адреса LDAP панели и выбранного DC. Восстановите DNS перед снятием роли."})
			return
		}
		for _, a := range backendIPs {
			for _, b := range nodeIPs {
				if a.Unmap() == b.Unmap() {
					usesTarget = true
				}
			}
		}
	}
	if usesTarget {
		writeJSON(w, 409, map[string]string{"error": "Панель использует LDAP этого DC. Сначала выберите другой рабочий RWDC в настройках панели."})
		return
	}
	action := "plan"
	if strings.HasSuffix(r.URL.Path, "/start") {
		action = "start"
	}
	if strings.HasSuffix(r.URL.Path, "/resume") {
		action = "resume"
	}
	// A resumed operation may already be absent from AD. The helper checks its root-owned ledger.
	if action != "resume" {
		controllers, err := s.svcs.Sites.Controllers(r.Context())
		if err != nil {
			upstreamError(w, err)
			return
		}
		target, source := false, false
		for _, dc := range controllers {
			if strings.EqualFold(dc.DNS, in.Node) {
				target = true
			}
			if strings.EqualFold(dc.DNS, in.Source) && !dc.RODC {
				source = true
			}
		}
		if !target || !source {
			writeJSON(w, 409, map[string]string{"error": "Нужны действующий DC и другой RWDC этого домена"})
			return
		}
	}
	var reference dcdemote.Manifest
	if action != "resume" {
		input, _ := json.Marshal(dcdemote.Input{Node: in.Source, Realm: in.Realm})
		ctx, cancel := context.WithTimeout(r.Context(), 190*time.Second)
		defer cancel()
		if err := s.svcs.Helpers.Call(ctx, in.Source, "domain.demote.manifest", service.HostOperation{Input: input}, &reference); err != nil {
			upstreamError(w, err)
			return
		}
	}
	raw, _ := json.Marshal(struct {
		dcdemote.Input
		Reference dcdemote.Manifest `json:"reference"`
	}{in, reference})
	defer clear(raw)
	ctx, cancel := context.WithTimeout(r.Context(), 190*time.Second)
	defer cancel()
	var out any
	var err error
	if action == "plan" {
		var plan dcdemote.Plan
		err = s.svcs.Helpers.Call(ctx, in.Node, "domain.demote.plan", service.HostOperation{Input: raw, Actor: sessionFrom(r).Username, IP: r.RemoteAddr}, &plan)
		if err == nil {
			err = s.saveDemoteAddress(in.Node, plan.Addresses)
			out = plan
		}
	} else {
		err = s.demoteCall(ctx, in.Node, "domain.demote."+action, service.HostOperation{Input: raw, Actor: sessionFrom(r).Username, IP: r.RemoteAddr}, &out)
	}
	if err != nil {
		upstreamError(w, err)
		return
	}
	if s.audit != nil {
		s.audit.Success(sessionFrom(r).Username, "domain.demote."+action, in.Node, r.RemoteAddr)
	}
	code := 200
	if action != "plan" {
		code = 202
	}
	writeJSON(w, code, out)
}

// A private, authenticated address pin keeps polling and recovery independent
// of AD DNS cleanup. TLS still verifies the original helper hostname and CA.
func (s *Server) demoteLocator(node string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(node)))
	return filepath.Join(s.cfg.Server.EnrollmentDir, "dc-demote", hex.EncodeToString(sum[:])+".ip")
}
func (s *Server) saveDemoteAddress(node string, addresses []string) error {
	path := s.demoteLocator(node)
	if !filepath.IsAbs(path) {
		return fmt.Errorf("Настройте абсолютный каталог привязки helper")
	}
	var selected string
	for _, address := range addresses {
		ip, err := netip.ParseAddr(address)
		if err == nil && ip.Is4() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast() {
			selected = address
			break
		}
	}
	if selected == "" {
		return fmt.Errorf("Helper не подтвердил IPv4 для связи после снятия роли")
	}
	// Prefer the configured transport origin on multi-homed/NATed servers.
	// It is still authenticated with the original hostname and CA on every call.
	cfg, configErr := s.svcs.Helpers.Configuration()
	if configErr != nil {
		return configErr
	}
	for _, helper := range cfg.Nodes {
		if !strings.EqualFold(helper.Name, node) {
			continue
		}
		hostname := node
		if helper.Transport == "https" {
			endpoint, err := url.Parse(helper.Endpoint)
			if err == nil {
				hostname = endpoint.Hostname()
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", hostname)
		cancel()
		if err == nil {
			for _, ip := range resolved {
				if !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast() {
					selected = ip.String()
					break
				}
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	st, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("Каталог привязки требует прав 0700")
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pin-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.WriteString(selected); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
func (s *Server) demoteCall(ctx context.Context, node, method string, in, out any) error {
	raw, err := os.ReadFile(s.demoteLocator(node))
	if err != nil {
		return fmt.Errorf("Не сохранён адрес helper. Сначала выполните предпросмотр снятия роли: %w", err)
	}
	return s.svcs.Helpers.CallPinned(ctx, node, method, in, out, string(raw))
}
