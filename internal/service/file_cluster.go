package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sambaadm/internal/filecluster"
	"strings"
	"sync"
)

type FileClusterNode struct {
	Name string `json:"name"`
}
type FileClusterProbe struct {
	Node       string          `json:"node"`
	StateDir   string          `json:"stateDir"`
	Inventory  json.RawMessage `json:"inventory"`
	Repository json.RawMessage `json:"repository"`
}
type FileClusterPlan struct {
	Revision string             `json:"revision"`
	Nodes    []FileClusterProbe `json:"nodes"`
	Files    map[string]string  `json:"files"`
	Checks   []string           `json:"checks"`
	Blockers []string           `json:"blockers"`
}

func (s *ShareService) FileClusterNodes() ([]FileClusterNode, error) {
	if s.helpers == nil {
		return nil, fmt.Errorf("подключите helper обоих файловых серверов")
	}
	cfg, err := s.helpers.Configuration()
	if err != nil {
		return nil, err
	}
	out := make([]FileClusterNode, 0, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		out = append(out, FileClusterNode{Name: n.Name})
	}
	return out, nil
}
func (s *ShareService) FileClusterProbe(ctx context.Context, node string, discover []string) (json.RawMessage, error) {
	if s.helpers == nil || !s.helpers.Has(node) {
		return nil, fmt.Errorf("выберите зарегистрированный helper")
	}
	method := "storage.inventory"
	var input any = struct{}{}
	if discover != nil {
		method = "storage.iscsi.discover"
		input = struct {
			Portals []string `json:"portals"`
		}{discover}
	}
	var result json.RawMessage
	err := s.helpers.Call(ctx, node, method, HostOperation{Input: hostInput(input)}, &result)
	return result, err
}
func (s *ShareService) PlanFileCluster(ctx context.Context, in filecluster.Input) (*FileClusterPlan, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	if s.helpers == nil {
		return nil, fmt.Errorf("подключите helper обоих файловых серверов")
	}
	for _, node := range in.Nodes {
		if !s.helpers.Has(node.Name) {
			return nil, fmt.Errorf("узел %s не зарегистрирован", node.Name)
		}
	}
	plan := &FileClusterPlan{Nodes: make([]FileClusterProbe, 2), Blockers: []string{"До применения обязательна проверка fencing обоих узлов"}}
	errors := make([]error, 2)
	var wg sync.WaitGroup
	for i, node := range in.Nodes {
		wg.Add(1)
		go func(i int, node filecluster.Node) {
			defer wg.Done()
			plan.Nodes[i].Node = node.Name
			if errors[i] = s.helpers.Call(ctx, node.Name, "storage.inventory", HostOperation{}, &plan.Nodes[i].Inventory); errors[i] != nil {
				return
			}
			errors[i] = s.helpers.Call(ctx, node.Name, "filecluster.repository", HostOperation{Input: hostInput(in)}, &plan.Nodes[i].Repository)
		}(i, node)
	}
	wg.Wait()
	for i, err := range errors {
		if err != nil {
			return nil, fmt.Errorf("%s: %w", in.Nodes[i].Name, err)
		}
	}
	var branch, workerHash, stateDir string
	type block struct {
		WWID     string      `json:"diskWWID"`
		Type     string      `json:"type"`
		Size     json.Number `json:"size"`
		RO       bool        `json:"ro"`
		FSType   string      `json:"fstype"`
		UUID     string      `json:"uuid"`
		PTType   string      `json:"pttype"`
		PTUUID   string      `json:"ptuuid"`
		Mounts   []*string   `json:"mountpoints"`
		Children []block     `json:"children"`
	}
	type stamp struct {
		Node, Platform, Kernel, WWID string
		ZFSVersion                   string
		ZFSHostID                    string
		Size                         json.Number
		Repository                   json.RawMessage
		ConfigHashes                 map[string]string
	}
	stamps := make([]stamp, 2)
	for i, probe := range plan.Nodes {
		var inv struct {
			WorkerHash   string            `json:"workerHash"`
			StateDir     string            `json:"stateDir"`
			Platform     string            `json:"platform"`
			Kernel       string            `json:"kernel"`
			ConfigHashes map[string]string `json:"configHashes"`
			ZFSReadiness struct {
				Ready         bool     `json:"ready"`
				ModuleVersion string   `json:"moduleVersion"`
				HostID        string   `json:"hostID"`
				Blockers      []string `json:"blockers"`
			} `json:"zfsReadiness"`
			Blocks struct {
				Devices []block `json:"blockdevices"`
			} `json:"blocks"`
			SambaRole struct {
				Value string `json:"value"`
			} `json:"sambaRole"`
		}
		if err := json.Unmarshal(probe.Inventory, &inv); err != nil {
			return nil, fmt.Errorf("неверный ответ инвентаризации %s", probe.Node)
		}
		if inv.Platform != "p10" && inv.Platform != "p11" {
			return nil, fmt.Errorf("узел %s не подтверждает p10/p11", probe.Node)
		}
		if inv.WorkerHash == "" || inv.StateDir == "" {
			return nil, fmt.Errorf("обновите helper на %s", probe.Node)
		}
		if i == 0 {
			workerHash = inv.WorkerHash
			stateDir = inv.StateDir
		} else if inv.WorkerHash != workerHash || inv.StateDir != stateDir {
			return nil, fmt.Errorf("обновите helper и используйте одинаковый каталог состояния на обоих узлах")
		}
		if i == 0 {
			branch = inv.Platform
		} else if inv.Platform != branch {
			return nil, fmt.Errorf("смешанный кластер p10/p11 не проверен; используйте одну ветку на обоих узлах")
		}
		if strings.TrimSpace(inv.SambaRole.Value) != "member server" {
			return nil, fmt.Errorf("%s должен быть файловым участником домена", probe.Node)
		}
		var selected *block
		var visit func([]block) error
		visit = func(list []block) error {
			for _, b := range list {
				if b.WWID == in.Nodes[i].DiskWWID {
					var used func(block) bool
					used = func(x block) bool {
						if x.RO || x.FSType != "" || x.UUID != "" || x.PTType != "" || x.PTUUID != "" || x.Type == "part" {
							return true
						}
						for _, m := range x.Mounts {
							if m != nil && *m != "" {
								return true
							}
						}
						for _, child := range x.Children {
							if used(child) {
								return true
							}
						}
						return false
					}
					if used(b) {
						return fmt.Errorf("выбранный WWID на %s содержит данные, смонтирован или защищён от записи", probe.Node)
					}
					copy := b
					selected = &copy
				}
				if err := visit(b.Children); err != nil {
					return err
				}
			}
			return nil
		}
		if err := visit(inv.Blocks.Devices); err != nil {
			return nil, err
		}
		if selected == nil {
			return nil, fmt.Errorf("WWID %s не обнаружен на %s", in.Nodes[i].DiskWWID, probe.Node)
		}
		size, err := selected.Size.Int64()
		if err != nil || size < 1<<30 {
			return nil, fmt.Errorf("выбранное устройство должно иметь размер от 1 ГиБ")
		}
		stamps[i] = stamp{Node: probe.Node, Platform: inv.Platform, Kernel: inv.Kernel, WWID: selected.WWID, Size: selected.Size, Repository: probe.Repository, ConfigHashes: inv.ConfigHashes}
		plan.Nodes[i].StateDir = inv.StateDir
		if in.Filesystem == "zfs" {
			stamps[i].ZFSVersion = inv.ZFSReadiness.ModuleVersion
			stamps[i].ZFSHostID = inv.ZFSReadiness.HostID
			if !inv.ZFSReadiness.Ready {
				if len(inv.ZFSReadiness.Blockers) == 0 {
					plan.Blockers = append(plan.Blockers, probe.Node+": готовность ZFS не подтверждена; обновите helper и повторите проверку")
				}
				for _, reason := range inv.ZFSReadiness.Blockers {
					plan.Blockers = append(plan.Blockers, probe.Node+": "+reason)
				}
			}
		}
		var repo struct {
			Reboot bool `json:"rebootRequired"`
		}
		_ = json.Unmarshal(probe.Repository, &repo)
		if repo.Reboot {
			plan.Blockers = append(plan.Blockers, probe.Node+": сначала установите совместимые модули и перезагрузите узел")
		}
	}
	if in.Storage == "iscsi" && stamps[0].Size != stamps[1].Size {
		return nil, fmt.Errorf("размер общего LUN на узлах различается")
	}
	if in.Filesystem == "zfs" && stamps[0].ZFSVersion != stamps[1].ZFSVersion {
		plan.Blockers = append(plan.Blockers, "Установите одинаковую версию ZFS на обоих узлах до создания пула")
	}
	if in.Filesystem == "zfs" && stamps[0].ZFSHostID != "" && stamps[0].ZFSHostID == stamps[1].ZFSHostID {
		plan.Blockers = append(plan.Blockers, "Узлы ZFS имеют одинаковый hostid; задайте разные постоянные идентификаторы до создания пула")
	}
	var err error
	plan.Files, err = filecluster.Render(in, stateDir)
	if err != nil {
		return nil, err
	}
	in.Revision = ""
	raw, _ := json.Marshal(struct {
		Input      filecluster.Input
		Stamps     []stamp
		Files      map[string]string
		WorkerHash string
	}{in, stamps, plan.Files, workerHash})
	hash := sha256.Sum256(raw)
	plan.Revision = hex.EncodeToString(hash[:])
	plan.Checks = []string{"Два подписанных helper, доменные файловые серверы", "Одинаковая целевая платформа " + branch, "Выбранные WWID существуют и не содержат файловых систем/монтирований", "Репозитории и пакеты выбранного сценария доступны на обоих узлах", "Конфигурация включает fencing и единственного владельца файловой системы"}
	return plan, nil
}
