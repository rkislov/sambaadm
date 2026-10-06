package web

import (
	"net/http"
	"strings"

	"sambaadm/internal/auth"
)

const csrfHeader = "X-CSRF-Token"

// csrfProtect validates CSRF token for state-changing requests when a session exists.
func (s *Server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
			next.ServeHTTP(w, r)
			return
		}
		sess := sessionFrom(r)
		if sess == nil {
			// requireSession should have run first for protected routes
			if sess2, ok := s.sessions.FromRequest(r); ok {
				sess = sess2
			}
		}
		if sess == nil || sess.CSRFToken == "" {
			next.ServeHTTP(w, r)
			return
		}
		token := r.Header.Get(csrfHeader)
		if token == "" {
			_ = r.ParseForm()
			token = r.FormValue("csrf_token")
		}
		if !secureEqual(token, sess.CSRFToken) {
			if isAPI(r) || r.Header.Get("HX-Request") == "true" {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf"})
				return
			}
			http.Error(w, "CSRF validation failed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

func csrfMeta(sess *auth.Session) string {
	if sess == nil {
		return ""
	}
	return sess.CSRFToken
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}
