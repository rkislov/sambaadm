package auth

import (
	"testing"

	"sambaadm/internal/config"
)

func TestRBACResolve(t *testing.T) {
	r := NewRBAC(config.RolesConfig{
		Admins:   []string{"CN=Domain Admins,CN=Users,DC=example,DC=com"},
		Helpdesk: []string{"CN=Helpdesk,OU=Groups,DC=example,DC=com"},
	})
	if !r.Configured() {
		t.Fatal("expected configured")
	}
	if got := r.Resolve([]string{"CN=Domain Admins,CN=Users,DC=example,DC=com"}); got != RoleAdmin {
		t.Fatalf("admin: got %s", got)
	}
	if got := r.Resolve([]string{"CN=Helpdesk,OU=Groups,DC=example,DC=com"}); got != RoleHelpdesk {
		t.Fatalf("helpdesk: got %s", got)
	}
	if got := r.Resolve([]string{"CN=Other,DC=example,DC=com"}); got != RoleReadonly {
		t.Fatalf("readonly: got %s", got)
	}
}

func TestRBACUnconfiguredIsAdmin(t *testing.T) {
	r := NewRBAC(config.RolesConfig{})
	if r.Configured() {
		t.Fatal("expected unconfigured")
	}
	if got := r.Resolve(nil); got != RoleAdmin {
		t.Fatalf("unconfigured should be admin, got %s", got)
	}
}

func TestSessionStore(t *testing.T) {
	store := NewStore(0)
	sess, err := store.Create("alice", "CN=alice", RoleHelpdesk)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := store.Get(sess.ID)
	if !ok || got.Username != "alice" {
		t.Fatalf("expected alice session, got %+v ok=%v", got, ok)
	}
	store.Delete(sess.ID)
	if _, ok := store.Get(sess.ID); ok {
		t.Fatal("session should be deleted")
	}
}
