package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestClientCredentialsAreRequestLocalAndNeverFallBack(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "key"), filepath.Join(dir, "key.pub")
	if err := GenerateKey(private, public); err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier("dc0.example.org", []string{public})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	handler := func(ctx context.Context, method string, raw json.RawMessage) (any, error) {
		calls.Add(1)
		credentials, present, err := OperationCredentials(ctx)
		if err != nil {
			return nil, err
		}
		if method == "health" {
			if present {
				t.Error("credentials sent for OS operation")
			}
			return "healthy", nil
		}
		var expected string
		if err := json.Unmarshal(raw, &expected); err != nil {
			return nil, err
		}
		if !present || credentials.Username != expected || credentials.Password != "secret-for-"+expected {
			t.Error("operation used another user's identity")
		}
		return credentials.Username, nil
	}
	server := httptest.NewTLSServer(API(verifier, handler))
	defer server.Close()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client := &Client{Config: Config{PrivateKey: private, HostNode: "dc0.example.org", Nodes: []Node{{Name: "dc0.example.org", Transport: "https", Endpoint: server.URL, CACert: ca}}}}
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			user := fmt.Sprintf("user%d@example.org", i)
			ctx := WithCredentials(t.Context(), func() (Credentials, error) { return Credentials{Username: user, Password: "secret-for-" + user}, nil })
			var actual string
			if err := client.Call(ctx, "dc0.example.org", "sysvol.stat", user, &actual); err != nil {
				t.Error(err)
			} else if actual != user {
				t.Error("identity mixed across requests")
			}
		}(i)
	}
	wg.Wait()
	ctx := WithCredentials(t.Context(), func() (Credentials, error) { return Credentials{Username: "admin", Password: "secret-for-admin"}, nil })
	var out string
	if err := client.Call(ctx, "dc0.example.org", "health", nil, &out); err != nil {
		t.Fatal(err)
	}
	previous := calls.Load()
	expired := WithCredentials(t.Context(), func() (Credentials, error) { return Credentials{}, fmt.Errorf("session expired") })
	if err := client.Call(expired, "dc0.example.org", "sysvol.stat", "admin", &out); err == nil {
		t.Fatal("expired password silently replaced by fallback")
	}
	if calls.Load() != previous {
		t.Fatal("expired credentials were sent to helper")
	}
}
