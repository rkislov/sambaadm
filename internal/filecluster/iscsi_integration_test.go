package filecluster_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/filecluster"
	"sambaadm/internal/service"
)

var labNodes = []string{"fs1.sambaadm.test", "fs2.sambaadm.test"}

func labCall(client *agent.Client, node, method string, input any, out any) error {
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return client.Call(context.Background(), node, method, service.HostOperation{Input: raw, Actor: "cluster-lab"}, out)
}

func labJob(client *agent.Client, node, method string, input any, out any) error {
	var status filecluster.JobStatus
	if err := labCall(client, node, method, input, &status); err != nil {
		return err
	}
	for deadline := time.Now().Add(12 * time.Minute); time.Now().Before(deadline); {
		switch status.State {
		case "completed":
			return json.Unmarshal(status.Result, out)
		case "interrupted", "failed":
			return fmt.Errorf("%s: %s (%s)", method, status.Error, strings.Join(status.Log, ", "))
		}
		time.Sleep(time.Second)
		if err := client.Call(context.Background(), node, "filecluster.job.status", service.HostOperation{Name: status.ID}, &status); err != nil {
			return err
		}
	}
	return fmt.Errorf("%s: job timed out", method)
}

func TestIntegrationZFSISCSIStorage(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_ZFS_ISCSI") != "1" {
		t.Skip("disposable iSCSI lab only")
	}
	client, _ := clusterIntegrationClient(t)
	branch := os.Getenv("SAMBAADM_CLUSTER_BRANCH")
	if branch != "p10" && branch != "p11" {
		t.Fatal("set the exact lab branch")
	}
	port, name := "3260", "files11"
	if branch == "p10" {
		port, name = "3261", "files10"
	}
	portals := []string{"10.0.2.2:" + port, "10.0.3.2:" + port}
	target := "iqn.2026-11.test.sambaadm:ha"
	profile := filecluster.Prerequisites{Storage: "iscsi", Filesystem: "zfs", FenceAgents: []string{"redfish"}}
	type block struct {
		Type     string
		DiskWWID string
	}
	wwids := make([]string, 2)
	ids := make([][3]string, 2)
	for i := range ids {
		for j := range ids[i] {
			ids[i][j] = nonce(t)
		}
	}
	var wg sync.WaitGroup
	for i, node := range labNodes {
		wg.Add(1)
		go func(i int, node string) {
			defer wg.Done()
			if err := func() error {
				var repo struct {
					Platform string
					Revision string
				}
				if err := labCall(client, node, "filecluster.prerequisites", profile, &repo); err != nil {
					return err
				}
				if repo.Platform != branch {
					return fmt.Errorf("unexpected branch %q", repo.Platform)
				}
				t.Log(node, "verified repositories", branch)
				var prep struct{ RebootRequired bool }
				if err := labJob(client, node, "filecluster.prepare", filecluster.PrepareInput{RequestID: ids[i][0], Revision: repo.Revision, Profile: profile}, &prep); err != nil {
					return err
				}
				if prep.RebootRequired {
					return fmt.Errorf("kernel reboot required")
				}
				var discovery json.RawMessage
				if err := labCall(client, node, "storage.iscsi.discover", map[string]any{"portals": portals}, &discovery); err != nil {
					return err
				}
				if strings.Count(string(discovery), target) != len(portals) {
					return fmt.Errorf("target discovery incomplete: %s", discovery)
				}
				var connected struct {
					Sessions  []json.RawMessage
					Inventory struct {
						Blocks struct {
							Devices []block `json:"blockdevices"`
						}
					}
				}
				if err := labJob(client, node, "storage.iscsi.connect", filecluster.ISCSIConnectInput{RequestID: ids[i][1], TargetIQN: target, Portals: portals}, &connected); err != nil {
					return err
				}
				if len(connected.Sessions) != 2 {
					return fmt.Errorf("expected two iSCSI sessions, got %v", connected.Sessions)
				}
				counts := map[string]int{}
				for _, b := range connected.Inventory.Blocks.Devices {
					if b.Type == "disk" && b.DiskWWID != "" {
						counts[b.DiskWWID]++
					}
				}
				for id, n := range counts {
					if n == 2 {
						if wwids[i] != "" {
							return fmt.Errorf("ambiguous LUN")
						}
						wwids[i] = id
					}
				}
				if wwids[i] == "" {
					return fmt.Errorf("could not identify common WWID: %+v", connected.Inventory.Blocks.Devices)
				}
				var mapped struct {
					Paths    []string
					Topology string
				}
				if err := labJob(client, node, "storage.multipath.configure", filecluster.MultipathInput{RequestID: ids[i][2], Name: name, WWID: wwids[i], TargetIQN: target}, &mapped); err != nil {
					return err
				}
				if len(mapped.Paths) != 2 {
					return fmt.Errorf("expected two multipath block paths")
				}
				t.Logf("PASS %s %s %s\n%s", branch, node, wwids[i], mapped.Topology)
				return nil
			}(); err != nil {
				t.Errorf("%s: %v", node, err)
			}
		}(i, node)
	}
	wg.Wait()
	if wwids[0] != wwids[1] {
		t.Fatal("nodes see different LUNs")
	}
}
