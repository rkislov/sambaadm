package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"sambaadm/internal/auth"
	"sambaadm/internal/config"
)

func TestCSRFProtect(t *testing.T) {
	s := &Server{
		sessions: auth.NewStore(time.Hour),
		cfg:      &config.Config{},
	}
	sess, err := s.sessions.Create("alice", "CN=alice", auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := s.requireSession(s.csrfProtect(okHandler))

	// Missing CSRF → 403
	req := httptest.NewRequest(http.MethodPost, "/users", nil)
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("missing csrf: got %d", rec.Code)
	}

	// Valid form CSRF → 204
	form := url.Values{"csrf_token": {sess.CSRFToken}}
	req = httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("valid csrf: got %d", rec.Code)
	}

	// Valid header CSRF → 204
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", nil)
	req.Header.Set(csrfHeader, sess.CSRFToken)
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("header csrf: got %d", rec.Code)
	}
}

func TestCSRFAllowsGET(t *testing.T) {
	s := &Server{
		sessions: auth.NewStore(time.Hour),
		cfg:      &config.Config{},
	}
	sess, err := s.sessions.Create("alice", "CN=alice", auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	h := s.requireSession(s.csrfProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sambaadm_session", Value: sess.ID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: got %d", rec.Code)
	}
}
