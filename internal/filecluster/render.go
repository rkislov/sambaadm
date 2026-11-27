package filecluster

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"path/filepath"
	"strings"
)

type xmlNode struct {
	XMLName  xml.Name
	Attrs    []xml.Attr `xml:",any,attr"`
	Children []xmlNode  `xml:",any"`
}

func element(name string, attrs ...string) xmlNode {
	n := xmlNode{XMLName: xml.Name{Local: name}}
	for i := 0; i < len(attrs); i += 2 {
		n.Attrs = append(n.Attrs, xml.Attr{Name: xml.Name{Local: attrs[i]}, Value: attrs[i+1]})
	}
	return n
}
func settings(tag, id string, values ...string) xmlNode {
	n := element(tag, "id", id)
	for i := 0; i < len(values); i += 2 {
		n.Children = append(n.Children, element("nvpair", "id", fmt.Sprintf("%s-%d", id, i/2), "name", values[i], "value", values[i+1]))
	}
	return n
}
func resource(id, class, provider, kind string, params ...string) xmlNode {
	n := element("primitive", "id", id, "class", class, "type", kind)
	if provider != "" {
		n.Attrs = append(n.Attrs, xml.Attr{Name: xml.Name{Local: "provider"}, Value: provider})
	}
	if len(params) > 0 {
		n.Children = append(n.Children, settings("instance_attributes", id+"-params", params...))
	}
	ops := element("operations")
	ops.Children = []xmlNode{element("op", "id", id+"-start", "name", "start", "interval", "0", "timeout", "120s"), element("op", "id", id+"-stop", "name", "stop", "interval", "0", "timeout", "120s", "on-fail", "fence"), element("op", "id", id+"-monitor", "name", "monitor", "interval", "20s", "timeout", "30s")}
	n.Children = append(n.Children, ops)
	return n
}

// Render produces reviewable configuration only. Secrets remain in helper vaults;
// storage initialization and CIB commit require a verified execution plan.
func Render(in Input, helperStateDir string) (map[string]string, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(helperStateDir) || strings.ContainsAny(helperStateDir, "\x00\r\n") {
		return nil, fmt.Errorf("неверный каталог состояния helper")
	}
	prefix := "sambaadm-" + in.Name
	mount := "/srv/samba-ha/" + in.Name
	var corosync strings.Builder
	fmt.Fprintf(&corosync, "totem {\n version: 2\n cluster_name: %s\n transport: knet\n crypto_cipher: aes256\n crypto_hash: sha256\n}\nnodelist {\n", prefix)
	for i, n := range in.Nodes {
		fmt.Fprintf(&corosync, " node {\n  name: %s\n  ring0_addr: %s\n  nodeid: %d\n }\n", n.Name, n.Address, i+1)
	}
	corosync.WriteString("}\nquorum {\n provider: corosync_votequorum\n two_node: 1\n wait_for_all: 1\n}\nlogging {\n to_syslog: yes\n}\n")
	root := element("cib", "validate-with", "pacemaker-3.9", "admin_epoch", "0", "epoch", "0", "num_updates", "0")
	cfg := element("configuration")
	props := element("crm_config")
	props.Children = append(props.Children, settings("cluster_property_set", prefix+"-properties", "stonith-enabled", "true", "startup-fencing", "true", "no-quorum-policy", "stop", "stonith-timeout", "120s"))
	cfg.Children = append(cfg.Children, props)
	nodes := element("nodes")
	for i, n := range in.Nodes {
		nodes.Children = append(nodes.Children, element("node", "id", fmt.Sprint(i+1), "uname", n.Name))
	}
	cfg.Children = append(cfg.Children, nodes)
	resources := element("resources")
	for i, f := range in.Fences {
		if f.Agent == "pve" {
			return nil, fmt.Errorf("fence_pve требует отдельной проверки метаданных агента")
		}
		host, port, err := net.SplitHostPort(f.Address)
		if err != nil {
			host = f.Address
			port = ""
		}
		secret := filepath.Join(helperStateDir, "filecluster", "vault", f.CredentialRef+".json")
		quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
		params := []string{"ipaddr", host, "login", f.Username, "passwd_script", "/usr/libexec/sambaadm-filecluster-secret " + quote(secret), "pcmk_host_list", in.Nodes[i].Name, "pcmk_host_check", "static-list", "pcmk_reboot_action", "off"}
		if port != "" {
			params = append(params, "ipport", port)
		}
		if f.Agent == "redfish" {
			params = append(params, "systems_uri", f.System, "ssl", "1")
		} else {
			params = append(params, "lanplus", "1")
		}
		resources.Children = append(resources.Children, resource(prefix+fmt.Sprintf("-fence-%d", i+1), "stonith", "", "fence_"+f.Agent, params...))
	}
	group := element("group", "id", prefix+"-group")
	if in.Filesystem == "lvm-xfs" {
		group.Children = append(group.Children, resource(prefix+"-lvm", "ocf", "heartbeat", "LVM-activate", "vgname", "sambaadm_"+in.Name, "vg_access_mode", "system_id", "activation_mode", "exclusive"), resource(prefix+"-state-fs", "ocf", "heartbeat", "Filesystem", "device", "/dev/sambaadm_"+in.Name+"/state", "directory", mount+"/state", "fstype", "xfs", "options", "noatime"), resource(prefix+"-fs", "ocf", "heartbeat", "Filesystem", "device", "/dev/sambaadm_"+in.Name+"/data", "directory", mount+"/data", "fstype", "xfs", "options", "noatime"))
	} else {
		layout, err := PlanZFS(in)
		if err != nil {
			return nil, err
		}
		group.Children = append(group.Children, resource(prefix+"-zfs", "ocf", "heartbeat", "ZFS", "pool", layout.Pool, "importargs", "-d "+layout.ImportPath, "importforce", "true"))
	}
	group.Children = append(group.Children, resource(prefix+"-vip", "ocf", "heartbeat", "IPaddr2", "ip", in.VirtualIP, "cidr_netmask", fmt.Sprint(in.Prefix)), resource(prefix+"-winbind", "systemd", "", prefix+"-winbind"), resource(prefix+"-smb", "systemd", "", prefix+"-smb"))
	group.Children = append(group.Children, settings("meta_attributes", prefix+"-group-meta", "target-role", "Stopped", "resource-stickiness", "200"))
	resources.Children = append(resources.Children, group)
	constraints := element("constraints")
	if in.Storage == "drbd" {
		drbd := resource(prefix+"-drbd", "ocf", "linbit", "drbd", "drbd_resource", prefix)
		clone := element("clone", "id", prefix+"-drbd-clone")
		clone.Children = []xmlNode{drbd, settings("meta_attributes", prefix+"-drbd-meta", "promotable", "true", "promoted-max", "1", "promoted-node-max", "1", "clone-max", "2", "clone-node-max", "1", "notify", "true", "target-role", "Stopped")}
		resources.Children = append(resources.Children, clone)
		constraints.Children = append(constraints.Children, element("rsc_colocation", "id", prefix+"-with-primary", "rsc", prefix+"-group", "with-rsc", prefix+"-drbd-clone", "with-rsc-role", "Promoted", "score", "INFINITY"), element("rsc_order", "id", prefix+"-after-primary", "first", prefix+"-drbd-clone", "first-action", "promote", "then", prefix+"-group", "then-action", "start", "kind", "Mandatory"))
	}
	cfg.Children = append(cfg.Children, resources, constraints, element("rsc_defaults"))
	root.Children = append(root.Children, cfg, element("status"))
	var out bytes.Buffer
	encoder := xml.NewEncoder(&out)
	encoder.Indent("", "  ")
	if err := encoder.Encode(root); err != nil {
		return nil, err
	}
	result := map[string]string{"corosync.conf": corosync.String(), "cib.xml": xml.Header + out.String() + "\n"}
	if in.Filesystem == "zfs" {
		layout, err := PlanZFS(in)
		if err != nil {
			return nil, err
		}
		data, err := json.MarshalIndent(layout, "", "  ")
		if err != nil {
			return nil, err
		}
		result["zfs-layout.json"] = string(data) + "\n"
	}
	return result, nil
}
