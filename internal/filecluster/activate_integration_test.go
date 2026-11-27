package filecluster_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sambaadm/internal/filecluster"
)

func labSSH(root string, index int, command string, input string) (string, error) {
	port := 2221 + index
	if strings.Contains(root, "-p10") {
		port += 10
	}
	cmd := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "-o", "UserKnownHostsFile="+filepath.Join(root, "known_hosts"), "-i", filepath.Join(root, "lab_ed25519"), "-p", fmt.Sprint(port), "root@127.0.0.1", command)
	cmd.Stdin = strings.NewReader(input)
	data, err := cmd.CombinedOutput()
	if err != nil {
		return string(data), fmt.Errorf("%w: %s", err, data)
	}
	return strings.TrimSpace(string(data)), nil
}

func TestIntegrationZFSActivate(t *testing.T) {
	if os.Getenv("SAMBAADM_IT_ZFS_ACTIVATE") != "1" {
		t.Skip("uses prepared disposable LUN and powers both lab guests off")
	}
	client, root := clusterIntegrationClient(t)
	branch := os.Getenv("SAMBAADM_CLUSTER_BRANCH")
	name, iscsiPort, powerPort := "files11", "3260", "18081"
	if branch == "p10" {
		name, iscsiPort, powerPort = "files10", "3261", "18082"
	} else if branch != "p11" {
		t.Fatal("invalid lab branch")
	}
	scope := filepath.Join(root, "deployment.json")
	var request filecluster.StageInput
	if data, e := os.ReadFile(scope); e == nil {
		if err := json.Unmarshal(data, &request); err != nil {
			t.Fatal(err)
		}
	} else {
		secret, e := os.ReadFile(filepath.Join(root, "power.secret"))
		if e != nil {
			t.Fatal(e)
		}
		defer clear(secret)
		key := make([]byte, 128)
		if _, e = rand.Read(key); e != nil {
			t.Fatal(e)
		}
		request.Workgroup = "SAMBAADM"
		request.Controller = "dc1.sambaadm.test"
		request.OwnerGroupSID = strings.TrimSpace(os.Getenv("SAMBAADM_LAB_DOMAIN_SID")) + "-513"
		request.AuthKey = base64.StdEncoding.EncodeToString(key)
		request.Cluster = filecluster.Input{Name: name, Realm: "sambaadm.test", VirtualIP: "10.77.0.50", Prefix: 24, Storage: "iscsi", Filesystem: "zfs", Portals: []string{"10.0.2.2:" + iscsiPort, "10.0.3.2:" + iscsiPort}, TargetIQN: "iqn.2026-11.test.sambaadm:ha"}
		for i, node := range labNodes {
			disk := "360000000000000000e00000000010001"
			request.Cluster.Nodes = append(request.Cluster.Nodes, filecluster.Node{Name: node, Address: fmt.Sprintf("10.77.0.%d", 11+i), DiskWWID: disk})
			fence := filecluster.Fence{Agent: "redfish", Address: "10.0.2.2:" + powerPort, System: fmt.Sprintf("/redfish/v1/Systems/fs%d", i+1), Username: "lab", CredentialRef: nonce(t)}
			request.Cluster.Fences = append(request.Cluster.Fences, fence)
			for _, host := range labNodes {
				var result any
				if err := labCall(client, host, "filecluster.credentials.put", filecluster.CredentialInput{Reference: fence.CredentialRef, Kind: "fence", Node: node, Address: fence.Address, System: fence.System, Username: fence.Username, Password: string(bytes.TrimSpace(secret))}, &result); err != nil {
					t.Fatal(err)
				}
			}
		}
		for i, node := range labNodes {
			var before, after struct{ BootID string }
			if err := labCall(client, node, "storage.inventory", struct{}{}, &before); err != nil {
				t.Fatal(err)
			}
			var proof struct{ OffConfirmed, OnConfirmed bool }
			if err := labJob(client, labNodes[1-i], "filecluster.fence.test", filecluster.FenceTestInput{RequestID: nonce(t), Cluster: request.Cluster, Confirm: true, Target: node}, &proof); err != nil {
				t.Fatal(err)
			}
			if !proof.OffConfirmed || !proof.OnConfirmed {
				t.Fatal("fencing proof incomplete")
			}
			var err error
			for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline); {
				err = labCall(client, node, "storage.inventory", struct{}{}, &after)
				if err == nil && after.BootID != "" {
					break
				}
				time.Sleep(time.Second)
			}
			if err != nil || before.BootID == "" || after.BootID == before.BootID {
				t.Fatalf("no verified reboot %s: %v", node, err)
			}
			t.Log("PASS reciprocal fencing", node)
		}
		data, _ := json.Marshal(request)
		if err := os.WriteFile(scope, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var rev, zfsVersion, hostID string
	for _, node := range labNodes {
		request.RequestID = nonce(t)
		var staged struct{ Revision, Platform, ZFSVersion, HostID string }
		if err := labJob(client, node, "filecluster.stage", request, &staged); err != nil {
			t.Fatal(node, err)
		}
		if staged.Platform != branch || staged.HostID == "" || hostID == staged.HostID || (rev != "" && (rev != staged.Revision || zfsVersion != staged.ZFSVersion)) {
			t.Fatal("incompatible paired helpers")
		}
		rev, zfsVersion, hostID = staged.Revision, staged.ZFSVersion, staged.HostID
		t.Log("PASS staged", node, staged.Platform, staged.ZFSVersion)
	}
	for _, node := range labNodes {
		var result any
		if err := labJob(client, node, "filecluster.online", filecluster.ActivationInput{RequestID: nonce(t), Name: name, Revision: rev}, &result); err != nil {
			t.Fatal(err)
		}
	}
	var onlineErr error
	for deadline := time.Now().Add(45 * time.Second); time.Now().Before(deadline); {
		_, onlineErr = labSSH(root, 0, "crm_mon --one-shot --output-as=xml | grep -q 'name=\"fs2.sambaadm.test\".*online=\"true\"'", "")
		if onlineErr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if onlineErr != nil {
		t.Fatal(onlineErr)
	}
	password := os.Getenv("SAMBAADM_LAB_DOMAIN_PASSWORD")
	if password == "" {
		t.Fatal("lab domain password required")
	}
	credential := filecluster.CredentialInput{Reference: nonce(t), Kind: "domain-join", Node: labNodes[0], Address: request.Controller, System: name + ".sambaadm.test", Username: "Administrator@SAMBAADM.TEST", Password: password}
	var result any
	if err := labCall(client, labNodes[0], "filecluster.credentials.put", credential, &result); err != nil {
		t.Fatal(err)
	}
	if err := labJob(client, labNodes[0], "filecluster.initialize", filecluster.ActivationInput{RequestID: nonce(t), Name: name, Revision: rev, CredentialRef: credential.Reference}, &result); err != nil {
		t.Fatal(err)
	}
	t.Log("PASS initialized ZFS and requested Samba activation", result)
	if err := os.WriteFile(filepath.Join(root, "active-revision"), []byte(rev), 0600); err != nil {
		t.Fatal(err)
	}
}
