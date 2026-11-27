package web

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"sambaadm/internal/filecluster"
)

func inPair(nodes []filecluster.Node, run func(int, string) error) error {
	var wg sync.WaitGroup
	errs := make([]error, len(nodes))
	for i, node := range nodes {
		wg.Go(func() { errs[i] = run(i, node.Name) })
	}
	wg.Wait()
	return errors.Join(errs...)
}

func (s *Server) startClusterAction(rpc clusterRPC, id, action string, in clusterSetupAction) (fileClusterDraft, error) {
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()
	state, err := s.readClusterDraft(id)
	if err != nil {
		return state.Draft, err
	}
	if s.clusterRunning[id] {
		return state.Draft, errors.New("операция уже выполняется")
	}
	for runningID := range s.clusterRunning {
		busy, err := s.readClusterDraft(runningID)
		if err != nil {
			return state.Draft, errors.New("дождитесь завершения текущей операции с хелперами")
		}
		for _, node := range state.Draft.Plan.Nodes {
			if slices.ContainsFunc(busy.Draft.Plan.Nodes, func(other filecluster.Node) bool { return other.Name == node.Name }) {
				return state.Draft, fmt.Errorf("%s занят операцией другого кластера", node.Name)
			}
		}
	}
	phase := map[string]string{"prepare": "nodes", "discover": "storage", "connect": "storage", "map": "connected", "fence": "mapped", "deploy": "fenced"}[action]
	if phase == "" || state.Draft.Phase != phase {
		return state.Draft, errors.New("завершите текущий шаг настройки")
	}
	if (action == "fence" || action == "deploy") && !in.Confirm {
		return state.Draft, errors.New("подтвердите действие")
	}
	if action == "deploy" {
		if in.WWID != state.Draft.Plan.Nodes[0].DiskWWID {
			return state.Draft, errors.New("выбранный WWID изменился")
		}
		if state.Draft.Workgroup != "" && (state.Draft.Workgroup != in.Workgroup || state.Draft.Controller != in.Controller || state.Draft.GroupSID != in.GroupSID) {
			return state.Draft, errors.New("сохраните параметры домена из начатого развёртывания")
		}
		state.Draft.Workgroup, state.Draft.Controller, state.Draft.GroupSID = in.Workgroup, in.Controller, in.GroupSID
		// Validate before locking a draft to the domain settings.
		stage := state.stage()
		if _, err := stage.Payload(stage.Cluster.Nodes[0].Name, "/var/lib/sambaadm-helper"); err != nil {
			return state.Draft, err
		}
	}
	if s.clusterRunning == nil {
		s.clusterRunning = make(map[string]bool)
	}
	state.Draft.Action, state.Draft.Error, state.Draft.Log = action, "", nil
	if err = s.writeClusterDraft(state); err != nil {
		return state.Draft, err
	}
	s.clusterRunning[id] = true
	view := state.Draft
	view.Plan.Nodes = slices.Clone(state.Draft.Plan.Nodes)
	go s.runClusterAction(rpc, state, action, in)
	return view, nil
}

func (s *Server) runClusterAction(rpc clusterRPC, state fileClusterState, action string, in clusterSetupAction) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	redact := func(message string) string {
		for _, password := range append([]string{in.Password}, fencePasswords(in.Fences)...) {
			if password != "" {
				message = strings.ReplaceAll(message, password, "[скрыто]")
			}
		}
		return message
	}
	log := func(message string) {
		s.clusterMu.Lock()
		defer s.clusterMu.Unlock()
		state.Draft.Log = append(state.Draft.Log, redact(message))
		if len(state.Draft.Log) > 50 {
			state.Draft.Log = state.Draft.Log[len(state.Draft.Log)-50:]
		}
		_ = s.writeClusterDraft(state)
	}
	err := rpc.setup(ctx, &state, action, in, log)
	s.clusterMu.Lock()
	defer s.clusterMu.Unlock()
	delete(s.clusterRunning, state.Draft.ID)
	state.Draft.Action = ""
	if err != nil {
		state.Draft.Error = redact(err.Error())
	}
	if saveErr := s.writeClusterDraft(state); saveErr != nil {
		err = saveErr
	}
	if s.audit != nil {
		event := "filecluster." + action
		if err != nil {
			s.audit.Failure(rpc.actor, event, state.Draft.Plan.Name, "", errors.New(redact(err.Error())))
		} else {
			s.audit.Success(rpc.actor, event, state.Draft.Plan.Name, "")
		}
	}
}

func fencePasswords(fences []filecluster.CredentialInput) []string {
	out := make([]string, 0, len(fences))
	for _, fence := range fences {
		out = append(out, fence.Password)
	}
	return out
}

func (s fileClusterState) stage() filecluster.StageInput {
	plan := s.Draft.Plan
	plan.Fences = s.Fences
	return filecluster.StageInput{RequestID: clusterID(), Cluster: plan, AuthKey: s.Key, Workgroup: s.Draft.Workgroup, Controller: s.Draft.Controller, OwnerGroupSID: s.Draft.GroupSID}
}

func (c clusterRPC) setup(ctx context.Context, state *fileClusterState, action string, in clusterSetupAction, log func(string)) error {
	d := &state.Draft
	nodes := d.Plan.Nodes
	switch action {
	case "prepare":
		profile := filecluster.Prerequisites{Storage: "iscsi", Filesystem: "zfs", FenceAgents: []string{"redfish"}}
		var hosts [2]struct{ Platform, WorkerHash, StateDir string }
		err := inPair(nodes, func(i int, node string) error { return c.call(ctx, node, "storage.inventory", struct{}{}, &hosts[i]) })
		if err != nil {
			return err
		}
		first, second := hosts[0], hosts[1]
		if (first.Platform != "p10" && first.Platform != "p11") || first.Platform != second.Platform || first.WorkerHash == "" || first.WorkerHash != second.WorkerHash || first.StateDir != second.StateDir {
			return errors.New("нужны два helper одной версии и одной ветки ALT p10 или p11")
		}
		// Check both repositories before changing either node.
		var repos [2]struct{ Revision string }
		if err = inPair(nodes, func(i int, node string) error {
			return c.call(ctx, node, "filecluster.prerequisites", profile, &repos[i])
		}); err != nil {
			return err
		}
		log("Оба репозитория проверены. Устанавливаются зависимости ZFS и iSCSI.")
		if err = inPair(nodes, func(i int, node string) error {
			var answer struct{ RebootRequired bool }
			err := c.job(ctx, node, "filecluster.prepare", filecluster.PrepareInput{RequestID: clusterID(), Revision: repos[i].Revision, Profile: profile, PrepareDedicatedZFS: in.DedicatedZFS}, &answer, log)
			if err == nil && answer.RebootRequired {
				return fmt.Errorf("%s: перезагрузите узел и повторите проверку", node)
			}
			return err
		}); err != nil {
			return err
		}
		var ready [2]struct {
			ZFSReadiness struct {
				Ready                 bool
				ModuleVersion, HostID string
				Blockers              []string
			}
		}
		if err = inPair(nodes, func(i int, node string) error {
			return c.call(ctx, node, "storage.inventory", struct{}{}, &ready[i])
		}); err != nil {
			return err
		}
		for i, row := range ready {
			if !row.ZFSReadiness.Ready {
				return fmt.Errorf("%s: %s", nodes[i].Name, strings.Join(row.ZFSReadiness.Blockers, "; "))
			}
		}
		if ready[0].ZFSReadiness.HostID == ready[1].ZFSReadiness.HostID ||
			ready[0].ZFSReadiness.ModuleVersion != ready[1].ZFSReadiness.ModuleVersion {
			return errors.New("нужны разные hostid и одинаковая версия ZFS")
		}
		d.Platform, d.Phase = first.Platform, "storage"
	case "discover":
		// The same portal validator is used for discovery and login.
		check := filecluster.ISCSIConnectInput{RequestID: clusterID(), TargetIQN: "iqn.2026-11.invalid:placeholder", Portals: in.Portals}
		if len(in.Portals) < 2 {
			return errors.New("укажите минимум два портала")
		}
		if err := check.Validate(); err != nil {
			return err
		}
		var results [2]struct {
			Discoveries []struct{ Targets []struct{ IQN string } }
		}
		if err := inPair(nodes, func(i int, node string) error {
			return c.call(ctx, node, "storage.iscsi.discover", map[string]any{"portals": in.Portals}, &results[i])
		}); err != nil {
			return err
		}
		counts := map[string]int{}
		for _, result := range results {
			if len(result.Discoveries) != len(in.Portals) {
				return errors.New("проверены не все порталы")
			}
			for _, discovery := range result.Discoveries {
				seen := map[string]bool{}
				for _, target := range discovery.Targets {
					if !seen[target.IQN] {
						counts[target.IQN]++
						seen[target.IQN] = true
					}
				}
			}
		}
		targets := []string{}
		for name, n := range counts {
			if n == 2*len(in.Portals) {
				targets = append(targets, name)
			}
		}
		sort.Strings(targets)
		if len(targets) == 0 {
			return errors.New("нет общей цели, видимой обоим helper через все порталы")
		}
		d.Plan.Portals, d.Targets = in.Portals, targets
	case "connect":
		if !slices.Contains(d.Targets, in.Target) {
			return errors.New("выберите цель, найденную на обоих узлах")
		}
		var answers [2]struct{ LUNs []clusterLUN }
		if err := inPair(nodes, func(i int, node string) error {
			request := filecluster.ISCSIConnectInput{RequestID: clusterID(), TargetIQN: in.Target, Portals: d.Plan.Portals}
			if in.Password != "" {
				if in.Username == "" {
					return errors.New("укажите имя CHAP")
				}
				addresses := slices.Clone(request.Portals)
				sort.Strings(addresses)
				request.CredentialRef = clusterID()
				if err := c.storeCredential(ctx, node, filecluster.CredentialInput{Reference: request.CredentialRef, Kind: "iscsi", Node: node, Address: strings.Join(addresses, ","), System: in.Target, Username: in.Username, Password: in.Password}); err != nil {
					return err
				}
			}
			return c.job(ctx, node, "storage.iscsi.connect", request, &answers[i], log)
		}); err != nil {
			return err
		}
		common := []clusterLUN{}
		for _, candidate := range answers[0].LUNs {
			if slices.Contains(answers[1].LUNs, candidate) {
				common = append(common, candidate)
			}
		}
		if len(common) == 0 {
			return errors.New("оба helper должны видеть один и тот же LUN через все выбранные порталы")
		}
		d.Plan.TargetIQN, d.LUNs, d.Phase = in.Target, common, "connected"
	case "map":
		selected := false
		for _, lun := range d.LUNs {
			selected = selected || lun.WWID == in.WWID
		}
		if !selected {
			return errors.New("выберите общий LUN из обнаруженных")
		}
		if err := inPair(nodes, func(i int, node string) error {
			var answer any
			return c.job(ctx, node, "storage.multipath.configure", filecluster.MultipathInput{RequestID: clusterID(), Name: d.Plan.Name, WWID: in.WWID, TargetIQN: d.Plan.TargetIQN}, &answer, log)
		}); err != nil {
			return err
		}
		for i := range nodes {
			nodes[i].DiskWWID = in.WWID
		}
		d.Phase = "mapped"
	case "fence":
		if err := c.fence(ctx, state, in.Fences, log); err != nil {
			return err
		}
		d.Phase = "fenced"
	case "deploy":
		if err := c.deploy(ctx, state, in, log); err != nil {
			return err
		}
		d.Phase = "done"
	}
	return nil
}

func (c clusterRPC) storeCredential(ctx context.Context, node string, credential filecluster.CredentialInput) error {
	if err := credential.Validate(); err != nil {
		return err
	}
	var answer struct{ Reference string }
	if err := c.call(ctx, node, "filecluster.credentials.put", credential, &answer); err != nil {
		return err
	}
	if answer.Reference != credential.Reference {
		return errors.New("helper вернул другой идентификатор реквизитов")
	}
	return nil
}

func (c clusterRPC) fence(ctx context.Context, state *fileClusterState, input []filecluster.CredentialInput, log func(string)) error {
	plan := state.Draft.Plan
	if len(input) != 2 {
		return errors.New("заполните Redfish для обоих узлов")
	}
	for i, credential := range input {
		if !strings.HasPrefix(credential.System, "/redfish/v1/Systems/") || credential.Username == "" {
			return errors.New("нужны имя пользователя и путь системы Redfish")
		}
		credential.Kind, credential.Reference, credential.Node = "fence", clusterID(), plan.Nodes[i].Name
		if err := inPair(plan.Nodes, func(_ int, node string) error { return c.storeCredential(ctx, node, credential) }); err != nil {
			return err
		}
		plan.Fences = append(plan.Fences, filecluster.Fence{Agent: "redfish", Address: credential.Address, System: credential.System, Username: credential.Username, CredentialRef: credential.Reference})
	}
	if plan.Fences[0].Address == plan.Fences[1].Address && plan.Fences[0].System == plan.Fences[1].System {
		return errors.New("укажите разные системы Redfish")
	}
	state.Fences = plan.Fences
	for i, target := range plan.Nodes {
		var before, after struct{ BootID string }
		if err := c.call(ctx, target.Name, "storage.inventory", struct{}{}, &before); err != nil {
			return err
		}
		if before.BootID == "" {
			return errors.New("нет исходного boot ID")
		}
		var proof struct{ OffConfirmed, OnConfirmed bool }
		request := filecluster.FenceTestInput{RequestID: clusterID(), Cluster: plan, Target: target.Name, Confirm: true}
		if err := c.job(ctx, plan.Nodes[1-i].Name, "filecluster.fence.test", request, &proof, log); err != nil {
			return err
		}
		if !proof.OffConfirmed || !proof.OnConfirmed {
			return errors.New("Redfish не подтвердил выключение и включение")
		}
		deadline := time.Now().Add(2 * time.Minute)
		for {
			poll, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := c.call(poll, target.Name, "storage.inventory", struct{}{}, &after)
			cancel()
			if err == nil && after.BootID != "" && after.BootID != before.BootID {
				break
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				return fmt.Errorf("перезагрузка %s не подтверждена", target.Name)
			}
			time.Sleep(time.Second)
		}
		log("Подтверждена перезагрузка " + target.Name)
	}
	return nil
}

func (c clusterRPC) deploy(ctx context.Context, state *fileClusterState, in clusterSetupAction, log func(string)) error {
	stage := state.stage()
	nodes := stage.Cluster.Nodes
	var staged [2]struct{ Revision, Platform, ZFSVersion, HostID string }
	if err := inPair(nodes, func(i int, node string) error {
		request := stage
		request.RequestID = clusterID()
		return c.job(ctx, node, "filecluster.stage", request, &staged[i], log)
	}); err != nil {
		return err
	}
	first, second := staged[0], staged[1]
	if first.Platform != state.Draft.Platform || first.Platform != second.Platform || first.Revision == "" || first.Revision != second.Revision || first.ZFSVersion == "" || first.ZFSVersion != second.ZFSVersion || first.HostID == "" || second.HostID == "" || first.HostID == second.HostID {
		return errors.New("нужны одинаковые платформы и версии ZFS, разные hostid и общая ревизия")
	}
	if err := inPair(nodes, func(_ int, node string) error {
		var answer any
		return c.job(ctx, node, "filecluster.online", filecluster.ActivationInput{RequestID: clusterID(), Name: stage.Cluster.Name, Revision: first.Revision}, &answer, log)
	}); err != nil {
		return err
	}
	primary := nodes[0].Name
	credential := filecluster.CredentialInput{Reference: clusterID(), Kind: "domain-join", Node: primary, Address: stage.Controller, System: stage.Cluster.Name + "." + stage.Cluster.Realm, Username: in.Username, Password: in.Password}
	if err := c.storeCredential(ctx, primary, credential); err != nil {
		return err
	}
	var answer any
	if err := c.job(ctx, primary, "filecluster.initialize", filecluster.ActivationInput{RequestID: clusterID(), Name: stage.Cluster.Name, Revision: first.Revision, CredentialRef: credential.Reference}, &answer, log); err != nil {
		return err
	}
	state.Draft.Revision = first.Revision
	return nil
}
