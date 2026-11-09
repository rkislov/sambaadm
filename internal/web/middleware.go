package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sambaadm/internal/agent"
	ldapproto "sambaadm/internal/ldap"

	"sambaadm/internal/auth"
)

type ctxKey int

const sessionKey ctxKey = 1

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.sessions.FromRequest(r)
		if !ok {
			if isAPI(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey, sess)
		ctx = ldapproto.WithLegacyCN(ctx, sess.AllowLegacyCN)
		if s.sessions.HasHelperCredentials(sess.ID) {
			id := sess.ID
			ctx = agent.WithCredentials(ctx, func() (agent.Credentials, error) {
				username, password, ok := s.sessions.HelperCredentials(id)
				if !ok {
					return agent.Credentials{}, fmt.Errorf("session credentials expired; sign in again")
				}
				return agent.Credentials{Username: username, Password: password}, nil
			})
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func sessionFrom(r *http.Request) *auth.Session {
	sess, _ := r.Context().Value(sessionKey).(*auth.Session)
	return sess
}

func isAPI(r *http.Request) bool {
	return len(r.URL.Path) >= 4 && r.URL.Path[:4] == "/api"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
