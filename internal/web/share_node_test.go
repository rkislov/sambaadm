package web

import (
	"net/http"
	"net/http/httptest"
	"sambaadm/internal/agent"
	"sambaadm/internal/service"
	"sync"
	"testing"
)

func TestShareNodeRequestScope(t *testing.T) {
	s := testWorkspaceServer(t)
	s.svcs = &service.Services{}
	s.svcs.Helpers = &agent.Client{Config: agent.Config{HostNode: "dc0", Nodes: []agent.Node{{Name: "dc0"}, {Name: "dc1"}}}}
	var wg sync.WaitGroup
	for _, node := range []string{"dc0", "dc1", "dc1", "dc0"} {
		node := node
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			s.shareNodeContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := service.HostNode(r.Context(), "default"); got != node {
					t.Errorf("target %s instead of %s", got, node)
				}
			})).ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/shares?node="+node, nil))
			if w.Code != 200 {
				t.Error(w.Code)
			}
		}()
	}
	wg.Wait()
	if s.svcs.Helpers.Config.HostNode != "dc0" {
		t.Fatal("global target mutated")
	}
	for _, path := range []string{"/api/v1/shares?node=unknown", "/shares/new?node=unknown", "/shares/x/acl?node=unknown", "/api/v1/acl?node=unknown"} {
		w := httptest.NewRecorder()
		s.shareNodeContext(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unknown target reached handler") })).ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
}
func TestShareNodeURLs(t *testing.T) {
	r := httptest.NewRequest("GET", "/shares?node=dc1.example.org", nil)
	if got := shareURL(r, "/shares/x/acl"); got != "/shares/x/acl?node=dc1.example.org" {
		t.Fatal(got)
	}
}
