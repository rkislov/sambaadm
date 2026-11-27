package filecluster

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validInput() Input {
	return Input{Name: "files", Realm: "corp.example", Nodes: []Node{{Name: "fs1.corp.example", Address: "192.0.2.11", DiskWWID: "360000000000000000000001"}, {Name: "fs2.corp.example", Address: "192.0.2.12", DiskWWID: "360000000000000000000001"}}, VirtualIP: "192.0.2.50", Prefix: 24, Storage: "iscsi", Filesystem: "lvm-xfs", Portals: []string{"192.0.2.80:3260", "192.0.2.81:3260"}, TargetIQN: "iqn.2026-11.example:storage", Fences: []Fence{{Agent: "redfish", Address: "192.0.2.91", System: "fs1", Username: "fence", CredentialRef: "saved-fs1"}, {Agent: "redfish", Address: "192.0.2.92", System: "fs2", Username: "fence", CredentialRef: "saved-fs2"}}}
}
func TestClusterRequiresRealFencingStableDevicesAndRedundantPaths(t *testing.T) {
	in := validInput()
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, modify := range []func(*Input){func(v *Input) { v.Fences = nil }, func(v *Input) { v.Fences[0].Agent = "none" }, func(v *Input) { v.Portals = v.Portals[:1] }, func(v *Input) { v.Portals[1] = v.Portals[0] }, func(v *Input) { v.Nodes[1].DiskWWID = "another-disk" }, func(v *Input) { v.Nodes[0].DiskWWID = "/dev/sda" }, func(v *Input) { v.VirtualIP = v.Nodes[0].Address }} {
		v := validInput()
		modify(&v)
		if v.Validate() == nil {
			t.Fatal("unsafe cluster accepted", v.Name)
		}
	}
	in = validInput()
	in.Storage = "drbd"
	if in.Validate() == nil {
		t.Fatal("DRBD on same shared device accepted")
	}
	in.Nodes[1].DiskWWID = "local-disk-000002"
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRenderKeepsFencingAndStorageOwnershipConstraints(t *testing.T) {
	for _, storage := range []string{"iscsi", "drbd"} {
		for _, fs := range []string{"lvm-xfs", "zfs"} {
			in := validInput()
			in.Storage = storage
			in.Filesystem = fs
			if storage == "drbd" {
				in.Nodes[1].DiskWWID = "local-disk-000002"
			}
			out, err := Render(in, "/var/lib/sambaadm-helper")
			if err != nil {
				t.Fatal(err)
			}
			xmlText := out["cib.xml"]
			for _, required := range []string{`name="stonith-enabled" value="true"`, `name="startup-fencing" value="true"`, `name="no-quorum-policy" value="stop"`, `name="target-role" value="Stopped"`, `name="passwd_script"`, `pcmk_host_list`} {
				if !strings.Contains(xmlText, required) {
					t.Fatal("missing safety constraint", required)
				}
			}
			if strings.Contains(xmlText, `value="ignore"`) {
				t.Fatal("quorum bypass")
			}
			if storage == "drbd" && (!strings.Contains(xmlText, `with-rsc-role="Promoted"`) || !strings.Contains(xmlText, `name="promoted-max" value="1"`)) {
				t.Fatal("DRBD can have more than one owner")
			}
			var document anyXML
			if err := xml.Unmarshal([]byte(xmlText), &document); err != nil {
				t.Fatal(err)
			}
		}
	}
	if dir := os.Getenv("SAMBAADM_CLUSTER_RENDER"); dir != "" {
		in := validInput()
		in.Name = "files"
		in.Realm = "sambaadm.test"
		in.VirtualIP = "10.77.0.50"
		for i := range in.Nodes {
			in.Nodes[i].Name = fmt.Sprintf("fs%d.sambaadm.test", i+1)
			in.Nodes[i].Address = fmt.Sprintf("10.77.0.%d", i+11)
			in.Fences[i].Address = "10.0.2.2:18081"
			in.Fences[i].System = fmt.Sprintf("/redfish/v1/Systems/fs%d", i+1)
			in.Fences[i].Username = "lab"
			in.Fences[i].CredentialRef = fmt.Sprintf("lab-fs%d", i+1)
		}
		out, err := Render(in, "/var/lib/sambaadm-helper")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for name, body := range out {
			if err = os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type anyXML struct{ XMLName xml.Name }
