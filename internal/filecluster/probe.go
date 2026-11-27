package filecluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
)

//go:embed worker.py storage.py activate.py snapshots.py restore.py
var files embed.FS

func jobScript() []byte {
	worker, _ := files.ReadFile("worker.py")
	storage, _ := files.ReadFile("storage.py")
	activation, _ := files.ReadFile("activate.py")
	snapshots, _ := files.ReadFile("snapshots.py")
	restore, _ := files.ReadFile("restore.py")
	return bytes.Join([][]byte{storage, activation, snapshots, restore, worker}, []byte("\n"))
}

// Probe runs only bundled read/discovery operations. It never accepts a command.
func Probe(ctx context.Context, operation string, input any, stateDirs ...string) (json.RawMessage, error) {
	if operation != "inventory" && operation != "repository" && operation != "discover" && operation != "credential-put" && operation != "fence-test" && operation != "cluster-status" && operation != "cluster-monitor" && operation != "cluster-catalog" {
		return nil, fmt.Errorf("недопустимая операция проверки хранилища")
	}
	script, _ := files.ReadFile("worker.py")
	if operation == "cluster-status" || operation == "cluster-monitor" || operation == "cluster-catalog" {
		script = jobScript()
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	args := []string{"-c", string(script), operation}
	if len(stateDirs) > 0 {
		args = append(args, stateDirs[0])
	}
	program := "/usr/bin/python3"
	if operation == "repository" {
		program = "systemd-run"
		args = append([]string{"--quiet", "--collect", "--wait", "--pipe", "--property=RuntimeMaxSec=180", "/usr/bin/python3"}, args...)
	}
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdin = bytes.NewReader(raw)
	output, err := cmd.Output()
	var result map[string]json.RawMessage
	if json.Unmarshal(output, &result) != nil {
		return nil, fmt.Errorf("проверка хранилища не завершена: %w", err)
	}
	if message := result["error"]; len(message) > 0 {
		var text string
		_ = json.Unmarshal(message, &text)
		return nil, fmt.Errorf("%s", text)
	}
	if err != nil {
		return nil, fmt.Errorf("проверка хранилища не завершена: %w", err)
	}
	hash := sha256.Sum256(jobScript())
	encoded, _ := json.Marshal(hex.EncodeToString(hash[:]))
	result["workerHash"] = encoded
	if len(stateDirs) > 0 {
		root, _ := json.Marshal(stateDirs[0])
		result["stateDir"] = root
	}
	raw, err = json.Marshal(result)
	return json.RawMessage(raw), err
}
