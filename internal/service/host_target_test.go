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
			var op HostOperation
			if e := json.Unmarshal(raw, &op); e != nil {
				return nil, e
			}
			switch method {
			case "shares.permission-map":
				return SharePermissionSnapshot{Share: name, Root: op.Path, Complete: true}, nil
			case "shares.permission-map.plan":
				return SharePermissionPlan{Revision: name}, nil
			case "shares.permission-map.apply":
				return SharePermissionApplyResult{ID: name, Status: "complete"}, nil

			case "shares.directories":
				if op.Name != "docs" || op.Path != "child" || op.Key != "200" {
					t.Errorf("wrong directory request: %+v", op)
				}
				return ShareDirectoryPage{Directories: []ShareDirectory{{Name: name, Path: "child/" + name}}}, nil
			case "shares.path-acl.get", "shares.path-acl.set":
				if op.Name != "docs" || op.Path != "child" {
					t.Errorf("wrong ACL request: %+v", op)
				}
				return PathACL{Owner: name, Path: op.Path}, nil
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
			ctx := WithHostNode(context.Background(), name)
			snapshot, e := s.PermissionMap(ctx, "docs", "child")
			if e != nil || snapshot.Share != name {
				t.Errorf("snapshot helper mismatch: %+v %v", snapshot, e)
			}
			plan, e := s.PlanPermissionMap(ctx, "docs", SharePermissionMapRequest{})
			if e != nil || plan.Revision != name {
				t.Errorf("map plan helper mismatch: %+v %v", plan, e)
			}
			applied, e := s.ApplyPermissionMap(ctx, "docs", SharePermissionMapRequest{Confirm: true, PlanRevision: "r"}, "test", "", "")
			if e != nil || applied.ID != name {
				t.Errorf("map apply helper mismatch: %+v %v", applied, e)
			}
			page, e := s.Directories(ctx, "docs", "child", 200)
			if e != nil || len(page.Directories) != 1 || page.Directories[0].Name != name {
				t.Errorf("directory helper mismatch: %v %+v", e, page)
			}
			acl := newFSACLService(nil, s)
			info, e := acl.GetSharePath(ctx, "docs", "child")
			if e != nil || info.Owner != name {
				t.Errorf("ACL read helper mismatch: %v %+v", e, info)
			}
			info, e = acl.SetSharePath(ctx, "docs", "child", SetACLInput{Mode: "0750"}, "test", "")
			if e != nil || info.Owner != name {
				t.Errorf("ACL write helper mismatch: %v %+v", e, info)
			}
		}()
	}
	wg.Wait()
	if client.Config.HostNode != "one" {
		t.Fatal("global host changed")
	}
}
