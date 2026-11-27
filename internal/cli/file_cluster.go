package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	"sambaadm/internal/agent"
	"sambaadm/internal/filecluster"
	"sambaadm/internal/service"
)

type clusterCLI struct {
	client *agent.Client
	output io.Writer
}

func (c clusterCLI) call(ctx context.Context, node, method string, input, result any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	defer clear(data)
	return c.client.Call(ctx, node, method, service.HostOperation{Input: data, Actor: actorName()}, result)
}

func (c clusterCLI) job(ctx context.Context, node, method string, input, result any) error {
	var status filecluster.JobStatus
	if err := c.call(ctx, node, method, input, &status); err != nil {
		return err
	}
	fmt.Fprintf(c.output, "%s %s %s\n", node, method, status.ID)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	displayed := 0
	for {
		if len(status.Log) < displayed {
			displayed = 0
		}
		for _, message := range status.Log[displayed:] {
			fmt.Fprintln(c.output, message)
		}
		displayed = len(status.Log)
		switch status.State {
		case "completed":
			return json.Unmarshal(status.Result, result)
		case "failed", "interrupted":
			return fmt.Errorf("%s %s: %s", node, status.ID, status.Error)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		if err := c.client.Call(ctx, node, "filecluster.job.status", service.HostOperation{Name: status.ID}, &status); err != nil {
			return err
		}
	}
}

func requestID() string {
	var data [16]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(data[:])
}

func readClusterStage(path string) (filecluster.StageInput, error) {
	var stage filecluster.StageInput
	st, err := os.Stat(path)
	if err != nil {
		return stage, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 64<<10 {
		return stage, fmt.Errorf("файл плана должен быть закрытым для других пользователей и не больше 64 КиБ")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return stage, err
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&stage); err != nil {
		return stage, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return stage, fmt.Errorf("обнаружены лишние данные в плане")
	}
	return stage, stage.Cluster.Validate()
}

func init() {
	cluster := &cobra.Command{Use: "file-cluster", Short: "Управление файловым HA-кластером ZFS/iSCSI через helper"}
	rootCmd.AddCommand(cluster)
	add := func(use, short string, args cobra.PositionalArgs, f func(context.Context, clusterCLI, []string) error) {
		cluster.AddCommand(&cobra.Command{Use: use, Short: short, Args: args, RunE: func(cmd *cobra.Command, values []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 45*time.Minute)
			defer cancel()
			return f(ctx, clusterCLI{&agent.Client{Config: rootCfg.Helpers}, cmd.OutOrStdout()}, values)
		}})
	}
	profile := filecluster.Prerequisites{Storage: "iscsi", Filesystem: "zfs", FenceAgents: []string{"redfish"}}
	add("prepare NODE FENCE_AGENT", "Проверить и установить пакеты ZFS/iSCSI", cobra.ExactArgs(2), func(ctx context.Context, c clusterCLI, a []string) error {
		selection := profile
		selection.FenceAgents = []string{a[1]}
		var plan struct {
			Revision string
		}
		if err := c.call(ctx, a[0], "filecluster.prerequisites", selection, &plan); err != nil {
			return err
		}
		var result any
		err := c.job(ctx, a[0], "filecluster.prepare", filecluster.PrepareInput{RequestID: requestID(), Revision: plan.Revision, Profile: selection}, &result)
		return c.print(result, err)
	})
	add("discover NODE PORTAL...", "Найти цели iSCSI", cobra.MinimumNArgs(2), func(ctx context.Context, c clusterCLI, a []string) error {
		var result any
		err := c.call(ctx, a[0], "storage.iscsi.discover", map[string]any{"portals": a[1:]}, &result)
		return c.print(result, err)
	})
	add("connect NODE IQN PORTAL...", "Подключить выбранные порталы iSCSI", cobra.MinimumNArgs(3), func(ctx context.Context, c clusterCLI, a []string) error {
		var result any
		err := c.job(ctx, a[0], "storage.iscsi.connect", filecluster.ISCSIConnectInput{RequestID: requestID(), TargetIQN: a[1], Portals: a[2:]}, &result)
		return c.print(result, err)
	})
	add("multipath NODE NAME WWID IQN", "Подготовить карту multipath выбранного LUN", cobra.ExactArgs(4), func(ctx context.Context, c clusterCLI, a []string) error {
		var result any
		err := c.job(ctx, a[0], "storage.multipath.configure", filecluster.MultipathInput{RequestID: requestID(), Name: a[1], WWID: a[2], TargetIQN: a[3]}, &result)
		return c.print(result, err)
	})
	add("credential NODE REF KIND TARGET ADDRESS SYSTEM USER", "Сохранить реквизиты в защищённом хранилище helper", cobra.ExactArgs(7), func(ctx context.Context, c clusterCLI, a []string) error {
		pass, err := readPassword("Пароль: ")
		if err != nil {
			return err
		}
		credential := filecluster.CredentialInput{Reference: a[1], Kind: a[2], Node: a[3], Address: a[4], System: a[5], Username: a[6], Password: pass}
		var result any
		err = c.call(ctx, a[0], "filecluster.credentials.put", credential, &result)
		return c.print(result, err)
	})
	add("fence-test PLAN.json", "Проверить выключение и включение обоих узлов", cobra.ExactArgs(1), func(ctx context.Context, c clusterCLI, a []string) error {
		stage, err := readClusterStage(a[0])
		if err != nil {
			return err
		}
		for index, node := range stage.Cluster.Nodes {
			var before, after struct{ BootID string }
			if err = c.call(ctx, node.Name, "storage.inventory", struct{}{}, &before); err != nil {
				return err
			}
			var proof struct{ OffConfirmed, OnConfirmed bool }
			input := filecluster.FenceTestInput{RequestID: requestID(), Cluster: stage.Cluster, Target: node.Name, Confirm: true}
			if err = c.job(ctx, stage.Cluster.Nodes[1-index].Name, "filecluster.fence.test", input, &proof); err != nil {
				return err
			}
			for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); {
				poll, cancel := context.WithTimeout(ctx, 5*time.Second)
				err = c.call(poll, node.Name, "storage.inventory", struct{}{}, &after)
				cancel()
				if err == nil && after.BootID != "" && after.BootID != before.BootID {
					break
				}
				time.Sleep(time.Second)
			}
			if err != nil || !proof.OffConfirmed || !proof.OnConfirmed || before.BootID == "" || after.BootID == "" || after.BootID == before.BootID {
				return fmt.Errorf("не подтверждена перезагрузка %s", node.Name)
			}
			fmt.Fprintln(c.output, "Подтверждена перезагрузка "+node.Name)
		}
		return nil
	})
	add("deploy PLAN.json JOIN_REF", "Создать пул на выбранном LUN и запустить виртуальный SMB-сервер", cobra.ExactArgs(2), func(ctx context.Context, c clusterCLI, a []string) error {
		stage, err := readClusterStage(a[0])
		if err != nil {
			return err
		}
		type stagedNode struct {
			Revision, Platform, ZFSVersion, HostID string
		}
		var pair [2]stagedNode
		for index, node := range stage.Cluster.Nodes {
			stage.RequestID = requestID()
			if err = c.job(ctx, node.Name, "filecluster.stage", stage, &pair[index]); err != nil {
				return err
			}
		}
		first, second := pair[0], pair[1]
		if first.Revision != second.Revision || first.Platform != second.Platform || first.ZFSVersion != second.ZFSVersion ||
			first.HostID == "" || second.HostID == "" || first.HostID == second.HostID {
			return fmt.Errorf("helper вернули несовместимые конфигурации ZFS или одинаковый hostid")
		}
		input := filecluster.ActivationInput{Name: stage.Cluster.Name, Revision: first.Revision}
		for _, node := range stage.Cluster.Nodes {
			input.RequestID = requestID()
			var result any
			if err = c.job(ctx, node.Name, "filecluster.online", input, &result); err != nil {
				return err
			}
		}
		input.RequestID, input.CredentialRef = requestID(), a[1]
		var result json.RawMessage
		if err = c.job(ctx, stage.Cluster.Nodes[0].Name, "filecluster.initialize", input, &result); err != nil {
			return err
		}
		return c.print(map[string]any{"revision": first.Revision, "cluster": result}, nil)
	})
	add("snapshot NODE NAME REVISION LABEL", "Создать именной снимок на активном узле", cobra.ExactArgs(4), func(ctx context.Context, c clusterCLI, a []string) error {
		input := filecluster.ActivationInput{RequestID: requestID(), Name: a[1], Revision: a[2], Label: a[3]}
		var result any
		err := c.job(ctx, a[0], "filecluster.snapshot", input, &result)
		return c.print(result, err)
	})
	add("status NODE NAME REVISION", "Проверить владельца, кворум и именные снимки", cobra.ExactArgs(3), func(ctx context.Context, c clusterCLI, a []string) error {
		var result any
		err := c.call(ctx, a[0], "filecluster.status", filecluster.ClusterReadInput{Name: a[1], Revision: a[2]}, &result)
		return c.print(result, err)
	})
	add("job NODE ID", "Открыть журнал задания helper", cobra.ExactArgs(2), func(ctx context.Context, c clusterCLI, a []string) error {
		var status filecluster.JobStatus
		err := c.client.Call(ctx, a[0], "filecluster.job.status", service.HostOperation{Name: a[1]}, &status)
		return c.print(status, err)
	})
}

func (c clusterCLI) print(value any, err error) error {
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(c.output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
