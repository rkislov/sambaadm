package service

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/config"
)

//go:embed printing_worker.py
var printingWorker string

var printingOperations = map[string]bool{"inspect": true, "models": true, "jobs": true, "queue.plan": true, "queue.apply": true, "ppd.upload": true, "ppd.import": true, "job.cancel": true, "service": true, "install.plan": true, "install.start": true, "install.status": true, "security.plan": true, "security.apply": true, "keytab.upload": true, "windows.upload": true, "windows.catalog": true, "windows.register": true}
var printJobID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func PrintingOperationAllowed(operation string) bool { return printingOperations[operation] }
func PrintingCall(ctx context.Context, client *agent.Client, node, operation string, input map[string]any, actor, ip string, out any) error {
	if !printingOperations[operation] || client == nil || !client.Has(node) {
		return fmt.Errorf("недоступная операция или helper сервера печати")
	}
	return client.Call(ctx, node, "printing."+operation, HostOperation{Input: hostInput(input), Actor: actor, IP: ip}, out)
}
func (s *Services) helperPrinting(ctx context.Context, cfg *config.Config, method string, in HostOperation) (any, error) {
	operation := strings.TrimPrefix(method, "printing.")
	if !printingOperations[operation] {
		return nil, fmt.Errorf("неизвестная операция печати")
	}
	var value map[string]any
	if len(in.Input) > 0 {
		if err := json.Unmarshal(in.Input, &value); err != nil {
			return nil, err
		}
	}
	if value == nil {
		value = map[string]any{}
	}
	value["operation"] = operation
	value["_node"] = cfg.Helper.Node
	value["_state"] = cfg.Helper.StateDir
	value["_smbConf"] = cfg.Samba.SMBConf
	if cfg.Helper.StateDir == "" || !filepath.IsAbs(cfg.Helper.StateDir) {
		return nil, fmt.Errorf("не задан абсолютный helper.state_dir")
	}
	if operation == "install.status" {
		id, _ := value["id"].(string)
		if !printJobID.MatchString(id) {
			return nil, fmt.Errorf("неверный ID задания печати")
		}
		raw, err := os.ReadFile(filepath.Join(cfg.Helper.StateDir, "printing", "jobs", id, "status.json"))
		return json.RawMessage(raw), err
	}
	if operation == "install.start" {
		if value["confirm"] != true {
			return nil, fmt.Errorf("подтвердите установку CUPS")
		}
		// Obtain a fresh package plan without accepting any job path from the caller.
		planning := map[string]any{"operation": "install.plan", "_node": cfg.Helper.Node, "_state": cfg.Helper.StateDir}
		raw, err := printingWorkerCall(ctx, planning, false)
		if err != nil {
			return nil, err
		}
		var plan struct {
			Revision string `json:"revision"`
		}
		json.Unmarshal(raw, &plan)
		if plan.Revision == "" || value["revision"] != plan.Revision {
			return nil, ErrTopologyConflict
		}
		random := make([]byte, 16)
		if _, err = rand.Read(random); err != nil {
			return nil, err
		}
		id := hex.EncodeToString(random)
		dir := filepath.Join(cfg.Helper.StateDir, "printing", "jobs", id)
		if err = os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
		value["operation"] = "install.apply"
		input, _ := json.Marshal(value)
		for name, data := range map[string][]byte{"worker.py": []byte(printingWorker), "input.json": input, "status.json": []byte(`{"state":"queued","phase":"Ожидание установки CUPS"}`)} {
			if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
				return nil, err
			}
		}
		if _, err = printingRun(ctx, "systemd-run", "--quiet", "--collect", "--unit=sambaadm-cups-install-"+id, "--property=RuntimeMaxSec=1200", "--property=LimitCORE=0", "/usr/bin/python3", filepath.Join(dir, "worker.py"), "install-job", dir); err != nil {
			return nil, err
		}
		return map[string]string{"id": id, "state": "queued"}, nil
	}
	readonly := operation == "inspect" || operation == "models" || operation == "jobs" || operation == "queue.plan" || operation == "install.plan" || operation == "security.plan" || operation == "windows.catalog"
	result, err := printingWorkerCall(ctx, value, !readonly)
	if err != nil {
		return nil, err
	}
	if operation == "inspect" && s.Printers != nil {
		var observed map[string]any
		if json.Unmarshal(result, &observed) == nil {
			shares, shareErr := s.Printers.List(ctx)
			if shareErr == nil {
				for _, item := range observed["queues"].([]any) {
					row := item.(map[string]any)
					for _, share := range shares {
						if share.InSMBConf && share.PrinterName == row["name"] {
							row["publishSMB"] = true
						}
					}
				}
			}
			result, _ = json.Marshal(observed)
		}
	}
	if operation == "queue.apply" && s.Printers != nil {
		name, _ := value["name"].(string)
		action, _ := value["action"].(string)
		if value["publishSMB"] == true && (action == "save" || action == "") {
			shares, listErr := s.Printers.List(ctx)
			if listErr != nil {
				return nil, fmt.Errorf("очередь CUPS настроена, не удалось проверить SMB: %w", listErr)
			}
			exists := false
			for _, share := range shares {
				if share.InSMBConf && strings.EqualFold(share.Name, name) {
					if share.PrinterName != name {
						return nil, fmt.Errorf("очередь CUPS настроена; SMB-имя занято другой очередью")
					}
					exists = true
				}
			}
			if !exists {
				description, _ := value["description"].(string)
				if _, err = s.Printers.Create(ctx, CreatePrinterInput{Name: name, PrinterName: name, Comment: description, Mode: "1777"}, in.Actor, in.IP); err != nil {
					return nil, fmt.Errorf("очередь CUPS настроена, публикация SMB не завершена: %w", err)
				}
			}
		}
		if action == "delete" && value["removeSMB"] == true {
			if err = s.Printers.Delete(ctx, name, in.Actor, in.IP); err != nil {
				return nil, fmt.Errorf("очередь CUPS удалена, SMB-публикация не удалена: %w", err)
			}
		}
	}
	return result, nil
}
func printingWorkerCall(ctx context.Context, value map[string]any, transient bool) (json.RawMessage, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	ctx, cancel := context.WithTimeout(ctx, 170*time.Second)
	defer cancel()
	program := "/usr/bin/python3"
	args := []string{"-c", printingWorker}
	if transient {
		random := make([]byte, 8)
		if _, err = rand.Read(random); err != nil {
			return nil, err
		}
		program = "/usr/bin/systemd-run"
		args = append([]string{"--quiet", "--wait", "--pipe", "--collect", "--unit=sambaadm-printing-" + hex.EncodeToString(random), "--property=RuntimeMaxSec=165", "--property=LimitCORE=0", "/usr/bin/python3"}, args...)
	}
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	var reply struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if json.Unmarshal(stdout.Bytes(), &reply) != nil {
		return nil, fmt.Errorf("worker печати не вернул результат; проверьте состояние службы")
	}
	if runErr != nil || !reply.OK {
		return nil, fmt.Errorf("%s", reply.Error)
	}
	return reply.Result, nil
}

func printingRun(ctx context.Context, name string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}
