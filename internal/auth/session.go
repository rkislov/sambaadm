package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Role represents RBAC permission level.
type Role string

const (
	RoleReadonly Role = "readonly"
	RoleHelpdesk Role = "helpdesk"
	RoleAdmin    Role = "admin"
)

// Session holds authenticated user state.
type Session struct {
	ID         string
	Username   string
	DN         string
	Role       Role
	CSRFToken  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Store is an in-memory session store (replace with Redis/DB later if needed).
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	ttl      time.Duration
	cookie   string
}

// NewStore creates a session store with the given TTL.
func NewStore(ttl time.Duration) *Store {
	if ttl == 0 {
		ttl = 8 * time.Hour
	}
	return &Store{
		sessions: make(map[string]*Session),
		ttl:      ttl,
		cookie:   "sambaadm_session",
	}
}

// Create registers a new session and returns it.
func (s *Store) Create(username, dn string, role Role) (*Session, error) {
	id, err := randomID(32)
	if err != nil {
		return nil, err
	}
	csrf, err := randomID(32)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	sess := &Session{
		ID:        id,
		Username:  username,
		DN:        dn,
		Role:      role,
		CSRFToken: csrf,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess, nil
}

// Get returns a valid (non-expired) session by ID.
func (s *Store) Get(id string) (*Session, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok || time.Now().After(sess.ExpiresAt) {
		if ok {
			s.Delete(id)
		}
		return nil, false
	}
	return sess, true
}

// Delete removes a session.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// SetCookie writes the session cookie to the response.
func (s *Store) SetCookie(w http.ResponseWriter, sess *Session, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookie,
		Value:    sess.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  sess.ExpiresAt,
	})
}

// ClearCookie expires the session cookie.
func (s *Store) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// FromRequest extracts a session from the request cookie.
func (s *Store) FromRequest(r *http.Request) (*Session, bool) {
	cookie, err := r.Cookie(s.cookie)
	if err != nil {
		return nil, false
	}
	return s.Get(cookie.Value)
}

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
