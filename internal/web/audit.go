package web

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"sambaadm/internal/audit"
	"sambaadm/internal/auth"
)

func auditPeer(r *http.Request) string {
	address := auth.PeerAddress(r.Context())
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	if ip, err := netip.ParseAddr(address); err == nil {
		return ip.Unmap().WithZone("").String()
	}
	return ""
}

func (s *Server) auditRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := sessionFrom(r)
		if s.audit == nil || session == nil {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		response := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
		status := http.StatusInternalServerError
		defer func() {
			route := chi.RouteContext(r.Context()).RoutePattern()
			if status >= 400 && (route == "" || strings.HasSuffix(route, "/*")) {
				matched := chi.NewRouteContext()
				if s.router.Match(matched, r.Method, r.URL.Path) {
					route = matched.RoutePattern()
				}
			}
			result := "success"
			if status >= 400 {
				result = "failure"
			}
			s.audit.Log(audit.Event{
				Actor: session.Username, Role: string(session.Role),
				Action: "web.request", Target: route, IP: auditPeer(r), Result: result,
				Method: r.Method, HTTPStatus: status, DurationMS: time.Since(start).Milliseconds(),
			})
		}()
		next.ServeHTTP(response, r)
		status = response.Status()
		if status == 0 {
			status = http.StatusOK
		}
	})
}

func (s *Server) auditSignIn(r *http.Request, actor, action string, role auth.Role, result string) {
	if s.audit != nil {
		s.audit.Log(audit.Event{
			Actor: actor, Action: action, Role: string(role), Result: result, IP: auditPeer(r),
		})
	}
}
