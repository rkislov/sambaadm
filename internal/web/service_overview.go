package web

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"sambaadm/internal/auth"
	"sambaadm/internal/service"
)

type dashboardServices struct {
	Observed         time.Time          `json:"observed"`
	DirectoryUnknown bool               `json:"directoryUnknown,omitempty"`
	HelpersUnknown   bool               `json:"helpersUnknown,omitempty"`
	CatalogPartial   bool               `json:"catalogPartial,omitempty"`
	Servers          []dashboardServer  `json:"servers"`
	Clusters         []dashboardCluster `json:"clusters"`
}

type dashboardServer struct {
	Name       string                `json:"name"`
	Site       string                `json:"site,omitempty"`
	Controller bool                  `json:"controller,omitempty"`
	RODC       bool                  `json:"rodc,omitempty"`
	Helper     string                `json:"helper"`
	Services   []service.ServiceUnit `json:"services"`
}

type dashboardCluster struct {
	Name   string                 `json:"name"`
	Key    string                 `json:"key"`
	State  string                 `json:"state"`
	Owner  string                 `json:"owner,omitempty"`
	Quorum bool                   `json:"quorum"`
	Nodes  []dashboardClusterNode `json:"nodes"`
}

type dashboardClusterNode struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	ReadyPaths int    `json:"readyPaths"`
	TotalPaths int    `json:"totalPaths"`
	Membership string `json:"membership,omitempty"`
}

func (s *Server) handleServiceOverview(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanRead) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 14*time.Second)
	defer cancel()
	rpc := clusterRPC{s, sessionFrom(r).Username}
	started := time.Now()
	observation := s.observeServices(ctx, rpc, true)
	if ctx.Err() == nil {
		s.recordHAHistory(started, observation)
	}
	writeJSON(w, http.StatusOK, observation)
}

func (s *Server) observeServices(ctx context.Context, rpc clusterRPC, includeDirectory bool) dashboardServices {
	result := dashboardServices{Servers: []dashboardServer{}, Clusters: []dashboardCluster{}}
	if s.svcs == nil {
		result.Observed = time.Now().UTC()
		return result
	}
	hosts := map[string]*dashboardServer{}
	server := func(name string) *dashboardServer {
		key := strings.ToLower(strings.TrimSuffix(name, "."))
		if entry := hosts[key]; entry != nil {
			return entry
		}
		entry := &dashboardServer{Name: name, Helper: "unregistered", Services: []service.ServiceUnit{}}
		hosts[key] = entry
		return entry
	}

	var controllers []service.Controller
	var catalog fileClusterCatalog
	var wg sync.WaitGroup
	if includeDirectory && s.svcs.Sites != nil {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()
			var err error
			controllers, err = s.svcs.Sites.Controllers(ctx)
			result.DirectoryUnknown = err != nil
		})
	}
	wg.Go(func() { catalog = s.clusterCatalog(ctx, rpc, false) })

	gate := make(chan struct{}, 8)
	if s.svcs.Helpers != nil {
		cfg, err := s.svcs.Helpers.Configuration()
		result.HelpersUnknown = err != nil
		for _, helper := range cfg.Nodes {
			if hosts[strings.ToLower(strings.TrimSuffix(helper.Name, "."))] != nil {
				continue
			}
			host := server(helper.Name)
			host.Helper = "unavailable"
			wg.Go(func() {
				select {
				case gate <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-gate }()
				ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
				defer cancel()
				probeServerServices(ctx, rpc, host)
			})
		}
	}
	wg.Wait()

	result.CatalogPartial = catalog.unreachable > 0
	for _, dc := range controllers {
		if dc.DNS != "" {
			host := server(dc.DNS)
			host.Controller, host.Site, host.RODC = true, dc.Site, dc.RODC
		}
	}
	clusters := make([]dashboardCluster, len(catalog.Clusters))
	for index, ref := range catalog.Clusters {
		for _, name := range ref.Nodes {
			server(name)
		}
		wg.Go(func() {
			select {
			case gate <- struct{}{}:
			case <-ctx.Done():
				clusters[index] = summarizeDashboardCluster(ref, nil)
				return
			}
			defer func() { <-gate }()
			statuses, _ := rpc.clusterStatus(ctx, ref, "filecluster.monitor")
			clusters[index] = summarizeDashboardCluster(ref, statuses)
		})
	}
	wg.Wait()
	result.Clusters = clusters
	slices.SortFunc(result.Clusters, func(a, b dashboardCluster) int { return strings.Compare(a.Name, b.Name) })
	for _, host := range hosts {
		result.Servers = append(result.Servers, *host)
	}
	slices.SortFunc(result.Servers, func(a, b dashboardServer) int {
		if a.Controller != b.Controller {
			if a.Controller {
				return -1
			}
			return 1
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	result.Observed = time.Now().UTC()
	return result
}

func helperMethodUnsupported(err error) bool {
	return err != nil && strings.HasSuffix(err.Error(), ": unsupported helper method")
}

func probeServerServices(ctx context.Context, rpc clusterRPC, host *dashboardServer) {
	var status service.HostServices
	err := rpc.call(ctx, host.Name, "host.services", struct{}{}, &status)
	if err == nil {
		host.Helper = "online"
		if !status.Systemd {
			host.Helper = "no-systemd"
		}
		host.Services = status.Services
		return
	}
	if !helperMethodUnsupported(err) {
		return
	}
	var inventory service.ControllerInventory
	if rpc.call(ctx, host.Name, "host.inventory", struct{}{}, &inventory) != nil {
		return
	}
	host.Helper = "legacy"
	for _, check := range inventory.Checks {
		var id, unit string
		switch check.ID {
		case "samba_service":
			id, unit = "ad", "samba.service"
		case "samba_ad_dc_service":
			id, unit = "ad", "samba-ad-dc.service"
		case "smb_service":
			id, unit = "smb", "smb.service"
		default:
			continue
		}
		switch check.Detail {
		case "active", "failed":
			host.Services = append(host.Services, service.ServiceUnit{ID: id, Unit: unit, State: check.Detail})
		case "activating", "deactivating":
			host.Services = append(host.Services, service.ServiceUnit{ID: id, Unit: unit, State: "transition"})
		}
	}
}

func summarizeDashboardCluster(ref clusterRef, statuses []clusterNodeStatus) dashboardCluster {
	cluster := dashboardCluster{Name: ref.Name + "." + ref.Realm, Key: ref.Name + "@" + ref.Revision, State: "unknown"}
	reportedOwner, _ := snapshotOwner(statuses)
	cluster.Owner = reportedOwner
	for _, status := range statuses {
		if status.Node == reportedOwner && status.SMBReady != nil && !*status.SMBReady {
			cluster.Owner = ""
		}
	}
	degraded, observed, claimedOwner := false, false, false
	for _, name := range ref.Nodes {
		node := dashboardClusterNode{Name: name, State: "unknown"}
		seenUp, seenDown := false, false
		for _, status := range statuses {
			if status.Error != "" || status.ClusterError != "" || !status.Quorum || !slices.Contains(status.OnlineNodes, status.LocalNode) {
				continue
			}
			if slices.Contains(status.OnlineNodes, name) {
				seenUp = true
			} else {
				seenDown = true
			}
		}
		switch {
		case seenUp && !seenDown:
			node.Membership = "up"
		case seenDown && !seenUp:
			node.Membership = "down"
		}
		for _, status := range statuses {
			if !strings.EqualFold(status.Node, name) || status.Error != "" || status.ClusterError != "" {
				continue
			}
			observed = true
			claimedOwner = claimedOwner || (status.Quorum && status.Owner != "")
			cluster.Quorum = cluster.Quorum || status.Quorum
			switch {
			case cluster.Owner == name:
				node.State = "active"
			case reportedOwner == name:
				node.State = "transition"
			case status.Quorum && slices.Contains(status.OnlineNodes, status.LocalNode):
				node.State = "reserve"
			default:
				node.State = "offline"
			}
			var storage struct{ Paths []struct{ Ready bool } }
			if json.Unmarshal(status.Multipath, &storage) == nil {
				node.TotalPaths = len(storage.Paths)
				for _, path := range storage.Paths {
					if path.Ready {
						node.ReadyPaths++
					}
				}
			}
		}
		if node.State == "unknown" && cluster.Owner != "" {
			for _, status := range statuses {
				if status.Node == cluster.Owner && status.Error == "" && status.ClusterError == "" && status.OnlineNodes != nil &&
					!slices.ContainsFunc(status.OnlineNodes, func(online string) bool { return strings.EqualFold(online, name) }) {
					node.State = "offline"
				}
			}
		}
		degraded = degraded || node.State == "offline" || node.State == "unknown" || node.TotalPaths == 0 || node.ReadyPaths < node.TotalPaths
		cluster.Nodes = append(cluster.Nodes, node)
	}
	switch {
	case cluster.Owner != "" && degraded:
		cluster.State = "degraded"
	case cluster.Owner != "":
		cluster.State = "active"
	case reportedOwner != "":
		cluster.State = "transition"
	case observed && !claimedOwner:
		cluster.State = "no-owner"
	}
	return cluster
}
