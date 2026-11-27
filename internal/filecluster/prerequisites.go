package filecluster

import "fmt"

type Prerequisites struct {
	Storage     string   `json:"storage"`
	Filesystem  string   `json:"filesystem"`
	FenceAgents []string `json:"fenceAgents"`
}

func (p Prerequisites) Validate() error {
	if p.Storage != "iscsi" && p.Storage != "drbd" {
		return fmt.Errorf("выберите iSCSI или DRBD")
	}
	if p.Filesystem != "lvm-xfs" && p.Filesystem != "zfs" {
		return fmt.Errorf("выберите LVM/XFS или ZFS")
	}
	if len(p.FenceAgents) < 1 || len(p.FenceAgents) > 2 {
		return fmt.Errorf("выберите fencing-агент для каждого узла")
	}
	for _, kind := range p.FenceAgents {
		if kind != "redfish" && kind != "ipmilan" && kind != "pve" {
			return fmt.Errorf("неизвестный fencing-агент")
		}
	}
	return nil
}
func (p Prerequisites) Packages() []string {
	out := []string{"pacemaker", "corosync", "resource-agents"}
	seen := map[string]bool{}
	for _, kind := range p.FenceAgents {
		if !seen[kind] {
			out = append(out, "fence-agents-"+kind)
			seen[kind] = true
		}
	}
	if p.Storage == "iscsi" {
		out = append(out, "open-iscsi", "multipath-tools")
	} else {
		out = append(out, "drbd-utils")
	}
	if p.Filesystem == "zfs" {
		out = append(out, "zfs-utils")
	} else {
		out = append(out, "lvm2", "xfsprogs", "thin-provisioning-tools")
	}
	return append(out, "samba", "samba-winbind", "samba-winbind-clients", "samba-common-tools", "samba-client", "openssl", "acl", "attr")
}

type PrepareInput struct {
	RequestID           string        `json:"requestID"`
	Revision            string        `json:"revision"`
	Profile             Prerequisites `json:"profile"`
	PrepareDedicatedZFS bool          `json:"prepareDedicatedZFS,omitempty"`
}

func (in PrepareInput) Validate() error {
	if err := in.Profile.Validate(); err != nil {
		return err
	}
	if in.PrepareDedicatedZFS && in.Profile.Filesystem != "zfs" {
		return fmt.Errorf("подготовка хоста предназначена для ZFS")
	}
	if !validJob.MatchString(in.RequestID) || len(in.Revision) != 64 {
		return fmt.Errorf("повторите проверку пакетов и задайте requestID")
	}
	return nil
}
