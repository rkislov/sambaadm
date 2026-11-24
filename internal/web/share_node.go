package web

import (
	"net/http"
	"net/url"
	"sambaadm/internal/service"
	"strings"
)

func (s *Server) shareNodeContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if !(strings.HasPrefix(path, "/shares") || strings.HasPrefix(path, "/api/v1/shares") || path == "/api/v1/acl" || strings.HasPrefix(path, "/api/v1/samba/")) {
			next.ServeHTTP(w, r)
			return
		}
		node := r.URL.Query().Get("node")
		if node != "" {
			found := ""
			if s.svcs != nil && s.svcs.Helpers != nil {
				cfg, e := s.svcs.Helpers.Configuration()
				if e != nil {
					writeJSON(w, 502, map[string]string{"error": "Не удалось прочитать реестр helper"})
					return
				}
				for _, n := range cfg.Nodes {
					if strings.EqualFold(n.Name, node) {
						found = n.Name
						break
					}
				}
			}
			if found == "" {
				writeJSON(w, 400, map[string]string{"error": "Выберите зарегистрированный сервер. Подмена на сервер по умолчанию не выполняется."})
				return
			}
			r = r.WithContext(service.WithHostNode(r.Context(), found))
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) handleShareNodes(w http.ResponseWriter, r *http.Request) {
	nodes := []string{}
	defaultNode := ""
	if s.svcs != nil && s.svcs.Helpers != nil {
		cfg, e := s.svcs.Helpers.Configuration()
		if e != nil {
			writeJSON(w, 502, map[string]string{"error": "Не удалось прочитать реестр helper"})
			return
		}
		defaultNode = cfg.HostNode
		for _, n := range cfg.Nodes {
			nodes = append(nodes, n.Name)
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"nodes": nodes, "default": defaultNode})
}
func shareURL(r *http.Request, path string) string {
	node := r.URL.Query().Get("node")
	if node == "" {
		return path
	}
	u, e := url.Parse(path)
	if e != nil {
		return path
	}
	q := u.Query()
	q.Set("node", node)
	u.RawQuery = q.Encode()
	return u.String()
}
