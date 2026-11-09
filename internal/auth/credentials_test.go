package auth

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestSessionVaultIsolationEncryptionAndLogout(t *testing.T) {
	store := NewStore(time.Hour)
	alice, _ := store.Create("alice@example.com", "cn=alice", RoleAdmin)
	bob, _ := store.Create("bob@example.com", "cn=bob", RoleAdmin)
	secrets := map[string]string{alice.ID: "alice-vault-secret-381", bob.ID: "bob-vault-secret-927"}
	for id, password := range secrets {
		if err := store.RememberHelperPassword(id, password); err != nil {
			t.Fatal(err)
		}
	}
	for id, entry := range store.vault.entries {
		if bytes.Contains(entry.ciphertext, []byte(secrets[id])) {
			t.Fatal("plaintext in vault")
		}
	}
	raw, err := json.Marshal(alice)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secrets[alice.ID])) {
		t.Fatal("password serialized in session")
	}
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sess := alice
			if i%2 != 0 {
				sess = bob
			}
			user, pw, ok := store.HelperCredentials(sess.ID)
			if !ok || user != sess.Username || pw != secrets[sess.ID] {
				t.Error("cross-session credentials")
			}
		}(i)
	}
	wg.Wait()
	store.Delete(alice.ID)
	if _, _, ok := store.HelperCredentials(alice.ID); ok {
		t.Fatal("logout retained password")
	}
	if _, _, ok := store.HelperCredentials(bob.ID); !ok {
		t.Fatal("logout removed another user's password")
	}
	store.Delete(bob.ID)
	if len(store.vault.entries) != 0 {
		t.Fatal("credential entries survived logout")
	}
}

func TestSessionVaultExpiresWithoutFurtherRequests(t *testing.T) {
	store := NewStore(25 * time.Millisecond)
	sess, _ := store.Create("admin", "cn=admin", RoleAdmin)
	if err := store.RememberHelperPassword(sess.ID, "secret"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		store.mu.RLock()
		n := len(store.vault.entries)
		store.mu.RUnlock()
		if n == 0 {
			if _, ok := store.Get(sess.ID); ok {
				t.Fatal("expired session remains usable")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("expired password retained without requests")
}

func TestSessionCiphertextCannotMoveBetweenUsers(t *testing.T) {
	store := NewStore(time.Hour)
	alice, _ := store.Create("alice", "cn=alice", RoleAdmin)
	bob, _ := store.Create("bob", "cn=bob", RoleAdmin)
	if err := store.RememberHelperPassword(alice.ID, "secret"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.vault.entries[bob.ID] = store.vault.entries[alice.ID]
	store.mu.Unlock()
	if _, _, ok := store.HelperCredentials(bob.ID); ok {
		t.Fatal("ciphertext accepted under another session")
	}
	store.Delete(alice.ID)
	store.Delete(bob.ID)
}
