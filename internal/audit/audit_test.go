package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecentMemory(t *testing.T) {
	l, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	l.Success("alice", "login", "", "1.2.3.4")
	l.Failure("bob", "user.create", "x", "1.2.3.4", os.ErrExist)
	ev, err := l.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 2 {
		t.Fatalf("want 2, got %d", len(ev))
	}
	if ev[0].Actor != "alice" || ev[1].Result != "failure" {
		t.Fatalf("unexpected events: %+v", ev)
	}
}

func TestRecentFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Success("alice", "login", "dn", "127.0.0.1")
	ev, err := l.Recent(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 1 || ev[0].Action != "login" {
		t.Fatalf("unexpected: %+v", ev)
	}
}
