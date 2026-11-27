package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"sambaadm/internal/config"
)

// HostServices is a read-only projection. It carries neither config nor command output.
type HostServices struct {
	Systemd  bool          `json:"systemd"`
	Services []ServiceUnit `json:"services"`
}

type ServiceUnit struct {
	ID       string      `json:"id"`
	Unit     string      `json:"unit,omitempty"`
	State    string      `json:"state"`
	SubState string      `json:"subState,omitempty"`
	Enabled  bool        `json:"enabled,omitempty"`
	DHCP     *DHCPHealth `json:"dhcp,omitempty"`
}

type DHCPHealth struct {
	Source        string        `json:"source,omitempty"`
	Standalone    bool          `json:"standalone,omitempty"`
	Relationships []KeaHAHealth `json:"relationships,omitempty"`
	SocketState   string        `json:"socketState,omitempty"`
}

type KeaHAHealth struct {
	PairID      string `json:"pairID,omitempty"`
	Mode        string `json:"mode,omitempty"`
	Name        string `json:"name,omitempty"`
	Role        string `json:"role,omitempty"`
	State       string `json:"state,omitempty"`
	Serving     *bool  `json:"serving,omitempty"`
	Peer        string `json:"peer,omitempty"`
	PeerState   string `json:"peerState,omitempty"`
	Interrupted *bool  `json:"interrupted,omitempty"`
	InTouch     *bool  `json:"inTouch,omitempty"`
	AgeSeconds  *int   `json:"ageSeconds,omitempty"`
}

type serviceUnits struct {
	id    string
	units []string
	keep  bool
}

var monitoredServices = []serviceUnits{
	{"ad", []string{"samba-ad-dc.service", "samba.service"}, true},
	{"smb", []string{"smb.service", "smbd.service"}, true},
	{"dhcp4", []string{"kea-dhcp4.service"}, true},
	{"dhcp6", []string{"kea-dhcp6.service"}, true},
	{"ddns", []string{"kea-dhcp-ddns.service"}, false},
	{"cups", []string{"cups.service", "cupsd.service"}, false},
	{"kea-control", []string{"kea-ctrl-agent.service"}, false},
	{"dns", []string{"named.service", "bind9.service", "bind.service"}, false},
	{"ntp", []string{"chronyd.service", "chrony.service"}, false},
	{"winbind", []string{"winbind.service"}, false},
	{"sssd", []string{"sssd.service"}, false},
	{"pacemaker", []string{"pacemaker.service"}, false},
	{"corosync", []string{"corosync.service"}, false},
	{"multipath", []string{"multipathd.service"}, false},
	{"iscsi", []string{"iscsid.service"}, false},
	{"zed", []string{"zfs-zed.service"}, false},
	{"ctdb", []string{"ctdb.service"}, false},
}

type systemdUnit struct {
	id, load, active, sub, file string
}

func parseSystemdUnits(raw string) map[string]systemdUnit {
	byName := make(map[string]systemdUnit)
	for _, block := range strings.Split(raw, "\n\n") {
		props := make(map[string]string)
		for _, line := range strings.Split(block, "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				props[key] = value
			}
		}
		if props["Id"] == "" || props["LoadState"] == "" || props["ActiveState"] == "" {
			continue
		}
		unit := systemdUnit{props["Id"], props["LoadState"], props["ActiveState"], props["SubState"], props["UnitFileState"]}
		for _, name := range append(strings.Fields(props["Names"]), unit.id) {
			byName[name] = unit
		}
	}
	return byName
}

func selectServiceUnit(group serviceUnits, units map[string]systemdUnit) ServiceUnit {
	current := ServiceUnit{ID: group.id, State: "unknown"}
	score := -1
	missing := 0
	for _, name := range group.units {
		unit, ok := units[name]
		if !ok {
			continue
		}
		if unit.load == "not-found" && unit.active == "inactive" {
			missing++
			continue
		}
		candidate := ServiceUnit{ID: group.id, Unit: unit.id, SubState: unit.sub, Enabled: unit.file == "enabled" || unit.file == "enabled-runtime"}
		priority := 0
		switch unit.active {
		case "active", "reloading", "refreshing":
			candidate.State, priority = "active", 5
		case "failed":
			candidate.State, priority = "failed", 4
		case "activating", "deactivating":
			candidate.State, priority = "transition", 3
		case "inactive":
			candidate.State, priority = "inactive", 2
			if unit.load != "loaded" && unit.load != "masked" {
				candidate.State, priority = "unknown", 1
			}
		default:
			candidate.State = "unknown"
		}
		if priority > score {
			current, score = candidate, priority
		}
	}
	if missing == len(group.units) {
		current.State = "absent"
	}
	return current
}

func observeHostServices(ctx context.Context, cfg *config.Config) HostServices {
	args := []string{"show", "--all", "--property=Id,Names,LoadState,ActiveState,SubState,UnitFileState"}
	for _, group := range monitoredServices {
		args = append(args, group.units...)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	raw, _ := runTimeCommand(probeCtx, "systemctl", args...)
	cancel()
	units := parseSystemdUnits(raw)
	out := HostServices{Systemd: len(units) > 0, Services: []ServiceUnit{}}
	for _, group := range monitoredServices {
		unit := selectServiceUnit(group, units)
		if group.keep || unit.Unit != "" {
			out.Services = append(out.Services, unit)
		}
	}
	var wg sync.WaitGroup
	for i, unit := range out.Services {
		if (unit.ID == "dhcp4" || unit.ID == "dhcp6") && unit.Unit != "" {
			wg.Go(func() {
				host, err := configuredKeaHost(cfg, strings.TrimPrefix(unit.ID, "dhcp"))
				if err == nil {
					out.Services[i].DHCP = host.dhcpHealth(ctx, unit.State == "active")
				}
			})
		}
	}
	wg.Wait()
	return out
}

func validKeaMode(mode string) string {
	switch mode {
	case "hot-standby", "load-balancing", "passive-backup":
		return mode
	}
	return ""
}

func configuredDHCPHealth(root map[string]any) *DHCPHealth {
	health := &DHCPHealth{Source: "config", Standalone: true}
	hooks, _ := root["hooks-libraries"].([]any)
	for _, item := range hooks {
		hook, _ := item.(map[string]any)
		path, _ := hook["library"].(string)
		if filepath.Base(path) != "libdhcp_ha.so" {
			continue
		}
		health.Standalone = false
		params, _ := hook["parameters"].(map[string]any)
		list, _ := params["high-availability"].([]any)
		for _, item := range list {
			row, _ := item.(map[string]any)
			name, _ := row["this-server-name"].(string)
			mode, _ := row["mode"].(string)
			ha := KeaHAHealth{Mode: validKeaMode(mode), Name: name}
			peers, _ := row["peers"].([]any)
			endpoints := map[string]string{}
			for _, entry := range peers {
				peer, _ := entry.(map[string]any)
				peerName, _ := peer["name"].(string)
				role, _ := peer["role"].(string)
				if endpoint, ok := peer["url"].(string); ok && endpoint != "" {
					endpoints[peerName] = endpoint
				}
				if peerName == name {
					ha.Role = role
				} else if peerName != "" && ha.Peer == "" && role != "backup" {
					ha.Peer = peerName
				}
			}
			if (ha.Mode == "hot-standby" || ha.Mode == "load-balancing") && ha.Name != "" && ha.Peer != "" &&
				endpoints[ha.Name] != "" && endpoints[ha.Peer] != "" && endpoints[ha.Name] != endpoints[ha.Peer] {
				members := []string{ha.Name, ha.Peer}
				slices.Sort(members)
				identity, _ := json.Marshal([]string{ha.Mode, members[0], endpoints[members[0]], members[1], endpoints[members[1]]})
				digest := sha256.Sum256(identity)
				ha.PairID = hex.EncodeToString(digest[:])
			}
			health.Relationships = append(health.Relationships, ha)
		}
	}
	return health
}

func runtimeDHCPHealth(arguments json.RawMessage, configured *DHCPHealth) (*DHCPHealth, error) {
	var response struct {
		UpTime  *int `json:"uptime"`
		Sockets struct {
			Status string `json:"status"`
		} `json:"sockets"`
		HA []struct {
			Mode    string `json:"ha-mode"`
			Servers struct {
				Local struct {
					Name   string   `json:"server-name"`
					Role   string   `json:"role"`
					State  string   `json:"state"`
					Scopes []string `json:"scopes"`
				} `json:"local"`
				Remote *struct {
					Name        string `json:"server-name"`
					State       string `json:"last-state"`
					Interrupted *bool  `json:"communication-interrupted"`
					InTouch     *bool  `json:"in-touch"`
					Age         *int   `json:"age"`
				} `json:"remote"`
			} `json:"ha-servers"`
		} `json:"high-availability"`
	}
	if json.Unmarshal(arguments, &response) != nil || response.UpTime == nil {
		return nil, errors.New("некорректный статус Kea")
	}
	health := &DHCPHealth{Source: "runtime", Standalone: len(response.HA) == 0}
	switch response.Sockets.Status {
	case "ready", "retrying", "failed":
		health.SocketState = response.Sockets.Status
	}
	for _, item := range response.HA {
		local := item.Servers.Local
		ha := KeaHAHealth{Mode: validKeaMode(item.Mode), Name: local.Name, Role: local.Role, State: local.State}
		if local.Scopes != nil {
			serving := len(local.Scopes) > 0
			ha.Serving = &serving
		}
		if peer := item.Servers.Remote; peer != nil {
			ha.Peer, ha.PeerState = peer.Name, peer.State
			ha.Interrupted, ha.InTouch, ha.AgeSeconds = peer.Interrupted, peer.InTouch, peer.Age
			match := func(rel KeaHAHealth) bool {
				return rel.Mode == ha.Mode && (local.Name == "" || rel.Name == local.Name) && (peer.Name == "" || rel.Peer == peer.Name)
			}
			matches := 0
			for _, rel := range configured.Relationships {
				if match(rel) {
					matches++
					if matches == 1 {
						ha.Name, ha.Peer, ha.PairID = rel.Name, rel.Peer, rel.PairID
					}
				}
			}
			if matches > 1 {
				ha.Name, ha.Peer, ha.PairID = local.Name, peer.Name, ""
			}
		}
		health.Relationships = append(health.Relationships, ha)
	}
	return health, nil
}

func (h *keaHost) dhcpHealth(ctx context.Context, active bool) *DHCPHealth {
	raw, _, err := h.read()
	if err != nil {
		return &DHCPHealth{}
	}
	_, root, err := keaRoot(raw, h.family)
	if err != nil {
		return &DHCPHealth{}
	}
	configured := configuredDHCPHealth(root)
	if !active {
		return configured
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	response, err := keaSocketCommand(ctx, root, "status-get", nil)
	if err == nil && response.Result == 0 {
		if runtime, err := runtimeDHCPHealth(response.Arguments, configured); err == nil {
			return runtime
		}
	}
	return configured
}
