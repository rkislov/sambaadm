package ldap

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLDAPCustomCA(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	uri := "ldaps://" + server.Listener.Addr().String()
	if conn, err := dial(context.Background(), uri, ""); err == nil {
		conn.Close()
		t.Fatal("untrusted certificate accepted")
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	conn, err := dial(context.Background(), uri, path)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if c, err := dial(context.Background(), strings.Replace(uri, "127.0.0.1", "localhost", 1), path); err == nil {
		c.Close()
		t.Fatal("hostname mismatch accepted")
	}
	if err := os.WriteFile(path, []byte("invalid PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := dial(context.Background(), uri, path); err == nil || !strings.Contains(err.Error(), "no valid PEM") {
		t.Fatalf("bad CA: %v", err)
	}
}
