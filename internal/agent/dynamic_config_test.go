package agent

import (
	"sync"
	"testing"
)

func TestManagedConfigCanChangeWithoutMutatingStaticConfig(t *testing.T) {
	var mu sync.Mutex
	current := Config{HostNode: "one", Nodes: []Node{{Name: "one"}}}
	client := &Client{LoadConfig: func() (Config, error) { mu.Lock(); defer mu.Unlock(); return current, nil }}
	if !client.Has("one") || client.Has("two") {
		t.Fatal("initial config")
	}
	mu.Lock()
	current = Config{HostNode: "two", Nodes: []Node{{Name: "two"}}}
	mu.Unlock()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !client.Has("two") || !client.Has("") || client.Has("one") {
				t.Error("stale managed config")
			}
		}()
	}
	wg.Wait()
	if len(client.Config.Nodes) != 0 {
		t.Fatal("static config mutated")
	}
}
