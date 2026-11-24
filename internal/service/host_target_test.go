package service

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sambaadm/internal/agent"
	"sync"
	"testing"
)

func TestShareOperationsUseSelectedHelper(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "key"), filepath.Join(dir, "public")
	if e := agent.GenerateKey(private, public); e != nil {
		t.Fatal(e)
	}
	client := &agent.Client{Config: agent.Config{PrivateKey: private, HostNode: "one"}}
	for _, name := range []string{"one", "two"} {
		name := name
		v, e := agent.NewVerifier(name, []string{public})
		if e != nil {
			t.Fatal(e)
		}
		server := httptest.NewTLSServer(agent.API(v, func(ctx context.Context, method string, raw json.RawMessage) (any, error) {
			if method == "shares.list" {
				return []Share{{Name: name}}, nil
			}
			return nil, nil
		}))
		defer server.Close()
		ca := filepath.Join(dir, name+".pem")
		if e = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); e != nil {
			t.Fatal(e)
		}
		client.Config.Nodes = append(client.Config.Nodes, agent.Node{Name: name, Transport: "https", Endpoint: server.URL, CACert: ca})
	}
	s := &ShareService{helpers: client}
	var wg sync.WaitGroup
	for _, name := range []string{"one", "two", "one", "two"} {
		name := name
		wg.Add(1)
		go func() {
			defer wg.Done()
			list, e := s.List(WithHostNode(context.Background(), name))
			if e != nil || len(list) != 1 || list[0].Name != name {
				t.Errorf("selected helper mismatch: %v %+v", e, list)
			}
		}()
	}
	wg.Wait()
	if client.Config.HostNode != "one" {
		t.Fatal("global host changed")
	}
}
