package filecluster_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sambaadm/internal/agent"
	"sambaadm/internal/filecluster"
	"sambaadm/internal/service"
	"strings"
	"testing"
	"time"
)

func clusterIntegrationClient(t *testing.T) (*agent.Client, string) {
	t.Helper()
	if os.Getenv("SAMBAADM_IT_CLUSTER_HELPERS") != "1" {
		t.Skip("disposable QEMU helper lab only")
	}
	root := os.Getenv("SAMBAADM_CLUSTER_LAB")
	if root == "" {
		root = "/tmp/sambaadm-ha-lab"
	}
	var metadata struct {
		Key   string `json:"private_key"`
		Nodes []struct {
			Name     string `json:"name"`
			Endpoint string `json:"endpoint"`
			CA       string `json:"ca_cert"`
		} `json:"nodes"`
	}
	raw, err := os.ReadFile(filepath.Join(root, "agent-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &metadata); err != nil {
		t.Fatal(err)
	}
	cfg := agent.Config{PrivateKey: metadata.Key}
	for _, n := range metadata.Nodes {
		cfg.Nodes = append(cfg.Nodes, agent.Node{Name: n.Name, Transport: "https", Endpoint: n.Endpoint, CACert: n.CA})
	}
	return &agent.Client{Config: cfg}, root
}
func nonce(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}
func TestIntegrationClusterInventoryRepositoryAndReciprocalFencing(t *testing.T) {
	client, root := clusterIntegrationClient(t)
	ctx := context.Background()
	names := []string{"fs1.sambaadm.test", "fs2.sambaadm.test"}
	call := func(node, method string, input any, out any) error {
		raw, _ := json.Marshal(input)
		return client.Call(ctx, node, method, service.HostOperation{Input: raw, Actor: "cluster-lab"}, out)
	}
	for _, name := range names {
		var inventory map[string]any
		if err := call(name, "storage.inventory", struct{}{}, &inventory); err != nil {
			t.Fatal(err)
		}
		if inventory["platform"] != "p11" || inventory["workerHash"] == "" || inventory["bootID"] == "" {
			t.Fatal("incomplete signed inventory", name)
		}
		t.Log("PASS signed inventory", name, inventory["kernel"])
	}
	input := filecluster.Input{Name: "files", Realm: "sambaadm.test", Nodes: []filecluster.Node{{Name: names[0], Address: "10.77.0.11", DiskWWID: "360000000000000000000001"}, {Name: names[1], Address: "10.77.0.12", DiskWWID: "360000000000000000000001"}}, VirtualIP: "10.77.0.50", Prefix: 24, Storage: "iscsi", Filesystem: "lvm-xfs", Portals: []string{"10.0.2.2:3260", "10.0.3.2:3260"}, TargetIQN: "iqn.2026-11.test.sambaadm:ha"}
	secret, err := os.ReadFile(filepath.Join(root, "power.secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	for i, target := range names {
		reference := nonce(t)
		f := filecluster.Fence{Agent: "redfish", Address: "10.0.2.2:18081", System: "/redfish/v1/Systems/fs" + string(rune('1'+i)), Username: "lab", CredentialRef: reference}
		input.Fences = append(input.Fences, f)
		credential := filecluster.CredentialInput{Reference: reference, Kind: "fence", Node: target, Address: f.Address, System: f.System, Username: "lab", Password: strings.TrimSpace(string(secret))}
		for _, node := range names {
			var response struct {
				Reference string `json:"reference"`
			}
			if err = call(node, "filecluster.credentials.put", credential, &response); err != nil {
				t.Fatal(err)
			}
			if response.Reference != reference {
				t.Fatal("credential reference changed")
			}
		}
	}
	if err = input.Validate(); err != nil {
		t.Fatal(err)
	}
	var repository map[string]any
	if err = call(names[0], "filecluster.repository", input, &repository); err != nil {
		t.Fatal(err)
	}
	if repository["platform"] != "p11" {
		t.Fatal("repository branch not pinned")
	}
	t.Log("PASS repository check in transient service from sandboxed helper")
	for i, target := range names {
		source := names[1-i]
		var before map[string]any
		if err = call(target, "storage.inventory", struct{}{}, &before); err != nil {
			t.Fatal(err)
		}
		request := filecluster.FenceTestInput{RequestID: nonce(t), Cluster: input, Target: target, Confirm: true}
		var job filecluster.JobStatus
		if err = call(source, "filecluster.fence.test", request, &job); err != nil {
			t.Fatal(err)
		}
		if job.ID != request.RequestID {
			t.Fatal("job identity is not stable")
		}
		// A duplicate start (including a lost-response retry) must return the same job.
		var repeated filecluster.JobStatus
		if err = call(source, "filecluster.fence.test", request, &repeated); err != nil || repeated.ID != job.ID {
			t.Fatal("repeated request was not idempotent", err)
		}
		deadline := time.Now().Add(150 * time.Second)
		for time.Now().Before(deadline) {
			if err = client.Call(ctx, source, "filecluster.job.status", service.HostOperation{Name: job.ID}, &job); err != nil {
				t.Fatal(err)
			}
			if job.State == "completed" || job.State == "failed" || job.State == "interrupted" {
				break
			}
			time.Sleep(time.Second)
		}
		if job.State != "completed" {
			t.Fatalf("fencing job did not complete: %s %s", job.State, job.Error)
		}
		var proof struct {
			Off bool `json:"offConfirmed"`
			On  bool `json:"onConfirmed"`
		}
		if err = json.Unmarshal(job.Result, &proof); err != nil || !proof.Off || !proof.On {
			t.Fatal("power transition not verified", err)
		}
		var after map[string]any
		for time.Now().Before(deadline) {
			err = call(target, "storage.inventory", struct{}{}, &after)
			if err == nil {
				break
			}
			time.Sleep(time.Second)
		}
		if err != nil || after["bootID"] == before["bootID"] {
			t.Fatal("target VM did not actually reboot", err)
		}
		if err = call(source, "filecluster.fence.test", request, &repeated); err != nil || repeated.State != "completed" {
			t.Fatal("completed job replayed", err)
		}
		t.Log("PASS real Redfish power off/on and helper recovery, idempotent start", target)
	}
	var forbidden filecluster.JobStatus
	if err = call(names[0], "filecluster.fence.test", filecluster.FenceTestInput{RequestID: nonce(t), Cluster: input, Target: names[0], Confirm: true}, &forbidden); err == nil {
		t.Fatal("self-fencing accepted")
	}
	t.Log("PASS self-fencing rejected")
}
