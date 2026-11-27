// Package filecluster defines the closed helper workflow for active/passive SMB.
package filecluster

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

type Node struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	DiskWWID string `json:"diskWWID"`
}
type Fence struct {
	Agent         string `json:"agent"`
	Address       string `json:"address"`
	System        string `json:"system"`
	Username      string `json:"username"`
	CredentialRef string `json:"credentialRef"`
}
type Input struct {
	Name       string   `json:"name"`
	Realm      string   `json:"realm"`
	Nodes      []Node   `json:"nodes"`
	VirtualIP  string   `json:"virtualIP"`
	Prefix     int      `json:"prefix"`
	Storage    string   `json:"storage"`
	Filesystem string   `json:"filesystem"`
	Portals    []string `json:"portals,omitempty"`
	TargetIQN  string   `json:"targetIQN,omitempty"`
	Fences     []Fence  `json:"fences"`
	Revision   string   `json:"revision,omitempty"`
}

var clusterName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,14}$`)
var wwid = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{7,255}$`)
var dns = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
var iqn = regexp.MustCompile(`^iqn\.[0-9]{4}-[0-9]{2}\.[A-Za-z0-9][A-Za-z0-9.:-]{1,210}$`)

func (in Input) Validate() error {
	if !clusterName.MatchString(in.Name) || !dns.MatchString(in.Realm) || !strings.Contains(in.Realm, ".") {
		return fmt.Errorf("укажите имя кластера и DNS-домен")
	}
	if len(in.Nodes) != 2 || len(in.Fences) != 2 || in.Nodes[0].Name == in.Nodes[1].Name {
		return fmt.Errorf("нужны два разных helper и fencing каждого узла")
	}
	vip, err := netip.ParseAddr(in.VirtualIP)
	if err != nil || !vip.Is4() || vip.IsLoopback() || vip.IsUnspecified() || vip.IsMulticast() || in.Prefix < 1 || in.Prefix > 30 {
		return fmt.Errorf("нужен виртуальный IPv4 и префикс сети")
	}
	for i, node := range in.Nodes {
		ip, err := netip.ParseAddr(node.Address)
		if !dns.MatchString(node.Name) || !strings.HasSuffix(node.Name, "."+in.Realm) || err != nil || !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip == vip || !netip.PrefixFrom(vip, in.Prefix).Contains(ip) || !wwid.MatchString(node.DiskWWID) {
			return fmt.Errorf("неверное имя, адрес или WWID узла %d", i+1)
		}
		f := in.Fences[i]
		if f.Agent != "redfish" && f.Agent != "ipmilan" && f.Agent != "pve" {
			return fmt.Errorf("выберите поддерживаемый fencing-агент")
		}
		if f.Address == "" || strings.ContainsAny(f.Address+f.System+f.Username, "\x00\r\n") || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`).MatchString(f.CredentialRef) {
			return fmt.Errorf("настройте адрес и защищённые реквизиты fencing каждого узла")
		}
	}
	if in.Nodes[0].Address == in.Nodes[1].Address {
		return fmt.Errorf("адреса узлов должны различаться")
	}
	if in.Storage != "iscsi" && in.Storage != "drbd" {
		return fmt.Errorf("выберите общий iSCSI LUN или DRBD")
	}
	if in.Filesystem != "lvm-xfs" && in.Filesystem != "zfs" {
		return fmt.Errorf("выберите LVM/XFS или ZFS")
	}
	if in.Storage == "iscsi" {
		if len(in.Portals) < 2 || len(in.Portals) > 8 || !iqn.MatchString(in.TargetIQN) || in.Nodes[0].DiskWWID != in.Nodes[1].DiskWWID {
			return fmt.Errorf("для multipath нужны минимум два портала и одинаковый WWID общего LUN на обоих узлах")
		}
		seen := map[string]bool{}
		for _, portal := range in.Portals {
			a, e := netip.ParseAddrPort(portal)
			if e != nil || a.Port() == 0 || a.Addr().IsUnspecified() || a.Addr().IsLoopback() || a.Addr().IsMulticast() || seen[portal] {
				return fmt.Errorf("неверный или повторный iSCSI-портал")
			}
			seen[portal] = true
		}
	} else if in.Nodes[0].DiskWWID == in.Nodes[1].DiskWWID {
		return fmt.Errorf("DRBD требует два разных локальных устройства, а не один общий LUN")
	}
	return nil
}
func (in Input) Packages() []string {
	agents := make([]string, 0, len(in.Fences))
	for _, f := range in.Fences {
		agents = append(agents, f.Agent)
	}
	return (Prerequisites{Storage: in.Storage, Filesystem: in.Filesystem, FenceAgents: agents}).Packages()
}
