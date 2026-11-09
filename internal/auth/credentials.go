package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"time"
)

type sealedCredentials struct {
	ciphertext []byte
	timer      *time.Timer
}

// Session credentials live only in this process. Neither the AEAD key nor its
// ciphertext is part of Session, cookies, templates or persistent state.
type credentialVault struct {
	cipher  cipher.AEAD
	entries map[string]sealedCredentials
}

func (s *Store) RememberHelperPassword(id, password string) error {
	if password == "" || len(password) > 16384 {
		return fmt.Errorf("invalid session password")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || !time.Now().Before(sess.ExpiresAt) {
		return fmt.Errorf("session expired")
	}
	if s.vault == nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		block, err := aes.NewCipher(key)
		clear(key)
		if err != nil {
			return err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		s.vault = &credentialVault{cipher: aead, entries: map[string]sealedCredentials{}}
	}
	nonce := make([]byte, s.vault.cipher.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := s.vault.cipher.Seal(nonce, nonce, []byte(password), []byte(id+"\x00"+sess.Username))
	s.forgetCredentialsLocked(id)
	timer := time.AfterFunc(time.Until(sess.ExpiresAt), func() { s.Delete(id) })
	s.vault.entries[id] = sealedCredentials{ciphertext: ciphertext, timer: timer}
	return nil
}

// HelperCredentials decrypts only for the immediate outgoing operation. Callers
// must not retain the plaintext in shared clients, jobs, configuration or logs.
func (s *Store) HelperCredentials(id string) (username, password string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, found := s.sessions[id]
	if !found || !time.Now().Before(sess.ExpiresAt) {
		s.forgetCredentialsLocked(id)
		return "", "", false
	}
	if s.vault == nil {
		return "", "", false
	}
	entry, found := s.vault.entries[id]
	if !found {
		return "", "", false
	}
	n := s.vault.cipher.NonceSize()
	if len(entry.ciphertext) < n {
		return "", "", false
	}
	raw, err := s.vault.cipher.Open(nil, entry.ciphertext[:n], entry.ciphertext[n:], []byte(id+"\x00"+sess.Username))
	if err != nil {
		return "", "", false
	}
	password = string(raw)
	clear(raw)
	return sess.Username, password, true
}

func (s *Store) HasHelperCredentials(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[id]
	if !ok || !time.Now().Before(sess.ExpiresAt) || s.vault == nil {
		return false
	}
	_, ok = s.vault.entries[id]
	return ok
}

func (s *Store) forgetCredentialsLocked(id string) {
	if s.vault == nil {
		return
	}
	if entry, ok := s.vault.entries[id]; ok {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		clear(entry.ciphertext)
		delete(s.vault.entries, id)
	}
}
