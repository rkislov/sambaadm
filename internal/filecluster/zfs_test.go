package filecluster

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestZFSPlanSeparatesSnapshotDataAndSambaSecrets(t *testing.T) {
	for _, storage := range []string{"iscsi", "drbd"} {
		in := validInput()
		in.Filesystem = "zfs"
		in.Storage = storage
		if storage == "drbd" {
			in.Nodes[1].DiskWWID = "local-disk-000002"
		}
		files, err := Render(in, "/var/lib/sambaadm-helper")
		if err != nil {
			t.Fatal(err)
		}
		var layout ZFSLayout
		if err = json.Unmarshal([]byte(files["zfs-layout.json"]), &layout); err != nil {
			t.Fatal(err)
		}
		if layout.SnapshotDataset != layout.Pool+"/data" {
			t.Fatal("snapshots may include Samba machine secrets")
		}
		paths := map[string]string{}
		for _, ds := range layout.Datasets {
			paths[ds.Name] = ds.Properties["mountpoint"]
		}
		state, data := paths[layout.Pool+"/state"], paths[layout.Pool+"/data"]
		if state == "" || data == "" || strings.HasPrefix(state, data+"/") || state == data {
			t.Fatal("Samba state is in exported data")
		}
		if layout.PoolProperties["cachefile"] != "none" {
			t.Fatal("cluster pool must not enter boot import cache")
		}
		if !strings.Contains(files["cib.xml"], `value="-d `+layout.ImportPath+`"`) {
			t.Fatal("pool import scans unrelated disks")
		}
		if storage == "drbd" && (layout.DeviceKind != "drbd-primary" || layout.BackingWWIDs[in.Nodes[1].Name] != in.Nodes[1].DiskWWID) {
			t.Fatal("ZFS recipe lost DRBD primary/device binding")
		}
		if strings.Contains(layout.ShadowCopy["shadow:format"], "@") {
			t.Fatal("snapshot names cannot include @GMT")
		}
	}
}
