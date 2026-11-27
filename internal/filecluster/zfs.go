package filecluster

import (
	"fmt"
	"path/filepath"
)

// ZFSLayout is a reviewable recipe, not authority to initialize a disk.
// Execution additionally requires matching device/fencing/ownership proofs.
type ZFSLayout struct {
	Pool            string            `json:"pool"`
	BackingWWIDs    map[string]string `json:"backingWWIDs"`
	DeviceKind      string            `json:"deviceKind"`
	ImportPath      string            `json:"importPath"`
	PoolProperties  map[string]string `json:"poolProperties"`
	Datasets        []ZFSDataset      `json:"datasets"`
	SnapshotDataset string            `json:"snapshotDataset"`
	ShadowCopy      map[string]string `json:"shadowCopy"`
}

type ZFSDataset struct {
	Name       string            `json:"name"`
	Properties map[string]string `json:"properties"`
	Mode       string            `json:"mode"`
}

func PlanZFS(in Input) (*ZFSLayout, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	if in.Filesystem != "zfs" {
		return nil, fmt.Errorf("выбран сценарий без ZFS")
	}
	pool := "sambaadm_" + in.Name
	base := filepath.Join("/srv/samba-ha", in.Name)
	kind := "multipath"
	importPath := filepath.Join("/dev/mapper", "sambaadm-"+in.Name)
	if in.Storage == "drbd" {
		kind = "drbd-primary"
		importPath = filepath.Join("/dev/drbd/by-res", "sambaadm-"+in.Name, "0")
	}
	return &ZFSLayout{
		Pool: pool, BackingWWIDs: map[string]string{in.Nodes[0].Name: in.Nodes[0].DiskWWID, in.Nodes[1].Name: in.Nodes[1].DiskWWID}, DeviceKind: kind,
		ImportPath:     importPath,
		PoolProperties: map[string]string{"cachefile": "none", "autoexpand": "off", "multihost": "on"},
		Datasets: []ZFSDataset{
			{Name: pool, Mode: "0700", Properties: map[string]string{"mountpoint": "none", "canmount": "off", "acltype": "posixacl", "xattr": "sa", "snapdir": "hidden", "atime": "off", "compression": "lz4", "dedup": "off", "sync": "standard"}},
			{Name: pool + "/state", Mode: "0700", Properties: map[string]string{"mountpoint": base + "/state", "canmount": "on"}},
			{Name: pool + "/data", Mode: "0770", Properties: map[string]string{"mountpoint": base + "/data", "canmount": "on"}},
		},
		SnapshotDataset: pool + "/data",
		// ZFS snapshot names cannot contain @GMT; shadow_copy2 translates them
		// to the Windows Previous Versions timestamp representation.
		ShadowCopy: map[string]string{"shadow:snapdir": ".zfs/snapshot", "shadow:basedir": base + "/data", "shadow:format": "sambaadm_%Y.%m.%d-%H.%M.%S", "shadow:localtime": "no", "shadow:sort": "desc"},
	}, nil
}
