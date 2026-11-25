package agent

import (
	"context"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestPinnedHelperRetainsTLSIdentity(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600)
	c := &Client{}
	// httptest's CA has the example.com SAN; no DNS record for that host is used.
	good := Node{Name: "example.com", Endpoint: "https://example.com:" + port, CACert: ca, dialAddress: "127.0.0.1"}
	client, err := c.httpClient(&good)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Get(good.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	wrong := good
	wrong.Endpoint = "https://wrong.invalid:" + port
	client, err = c.httpClient(&wrong)
	if err != nil {
		t.Fatal(err)
	}
	if response, err = client.Get(wrong.Endpoint); err == nil {
		response.Body.Close()
		t.Fatal("wrong TLS hostname accepted")
	}
	if c.CallPinned(context.Background(), "node", "shares.list", nil, nil, "192.0.2.1") == nil {
		t.Fatal("arbitrary capability accepted with pin")
	}
	if c.CallPinned(context.Background(), "node", "domain.demote.status", nil, nil, "127.0.0.1") == nil {
		t.Fatal("loopback accepted")
	}
}
