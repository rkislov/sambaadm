package filecluster

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

type JobStatus struct {
	ID     string          `json:"id"`
	State  string          `json:"state"`
	Phase  string          `json:"phase,omitempty"`
	Error  string          `json:"error,omitempty"`
	Log    []string        `json:"log"`
	Result json.RawMessage `json:"result,omitempty"`
	PID    int             `json:"pid,omitempty"`
}

var validJob = regexp.MustCompile(`^[a-f0-9]{32}$`)

func jobBase(stateDir string) (string, error) {
	if !filepath.IsAbs(stateDir) {
		return "", fmt.Errorf("нужен абсолютный каталог helper")
	}
	base := filepath.Join(stateDir, "filecluster", "jobs")
	if err := os.MkdirAll(base, 0700); err != nil {
		return "", err
	}
	info, err := os.Lstat(base)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("каталог заданий требует 0700")
	}
	for _, path := range []string{base, filepath.Dir(base), stateDir} {
		dir, e := os.Open(path)
		if e != nil {
			return "", e
		}
		e = errors.Join(dir.Sync(), dir.Close())
		if e != nil {
			return "", e
		}
	}
	return base, nil
}

// StartJob launches only bundled workflows in a transient systemd service.
// A browser disconnect or helper restart does not interrupt power restoration.
func StartJob(stateDir, action string, input any, id string) (*JobStatus, error) {
	if !validJob.MatchString(id) {
		return nil, fmt.Errorf("нужен постоянный requestID задания")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil, fmt.Errorf("задание требует Linux helper от root")
	}
	switch action {
	case "fence-test", "packages", "iscsi-connect", "multipath", "cluster-stage", "cluster-online", "cluster-initialize", "cluster-snapshot", "cluster-snapshot-timer", "cluster-snapshot-schedule", "cluster-restore-browse", "cluster-restore-preview", "cluster-restore-apply":
	default:
		return nil, fmt.Errorf("неподдерживаемое задание кластера")
	}
	base, err := jobBase(stateDir)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	digest := sha256.Sum256(append([]byte(action+"\n"), payload...))
	hash := hex.EncodeToString(digest[:])
	folder := filepath.Join(base, id)
	if err = os.Mkdir(folder, 0700); errors.Is(err, os.ErrExist) {
		root, e := os.OpenRoot(base)
		if e != nil {
			return nil, e
		}
		defer root.Close()
		previous, e := root.ReadFile(id + "/request.sha256")
		if e != nil || string(previous) != hash {
			return nil, fmt.Errorf("requestID уже занят другим или незавершённым заданием")
		}
		return ReadJob(stateDir, id)
	} else if err != nil {
		return nil, err
	}
	parent, e := os.Open(base)
	if e != nil {
		return nil, e
	}
	e = errors.Join(parent.Sync(), parent.Close())
	if e != nil {
		return nil, e
	}
	if err = durableJobFile(filepath.Join(folder, "request.sha256"), []byte(hash)); err != nil {
		return nil, err
	}
	if err = durableJobFile(filepath.Join(folder, "request.json"), payload); err != nil {
		return nil, err
	}
	status := &JobStatus{ID: id, State: "queued", Log: []string{"Проверка принята; результат будет сохранён на helper"}}
	raw, _ := json.Marshal(status)
	if err = durableJobFile(filepath.Join(folder, "status.json"), raw); err != nil {
		return nil, err
	}
	script := jobScript()
	workerPath := filepath.Join(folder, "worker.py")
	if err = durableJobFile(workerPath, script); err != nil {
		return nil, err
	}
	limit := "--property=RuntimeMaxSec=600"
	if action == "packages" || action == "cluster-restore-apply" {
		limit = "--property=RuntimeMaxSec=3600"
	}
	cmd := exec.Command("systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--unit=sambaadm-filecluster-"+id, limit, "--property=LimitCORE=0", "--property=NoNewPrivileges=yes", "/usr/bin/python3", workerPath, "job", stateDir, id, action)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		stdin.Close()
		return nil, err
	}
	_, err = stdin.Write(payload)
	err = errors.Join(err, stdin.Close())
	go func() { _ = cmd.Wait() }()
	if err != nil {
		return nil, fmt.Errorf("параметры задания не подтверждены; проверьте журнал %s", id)
	}
	return status, nil
}
func durableJobFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	err = errors.Join(err, file.Sync(), file.Close())
	if err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func ReadJob(stateDir, id string) (*JobStatus, error) {
	if !validJob.MatchString(id) {
		return nil, fmt.Errorf("неверный номер задания")
	}
	base, err := jobBase(stateDir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	raw, err := root.ReadFile(id + "/status.json")
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("слишком большой журнал")
	}
	var status JobStatus
	if err = json.Unmarshal(raw, &status); err != nil {
		return nil, err
	}
	if status.State == "queued" {
		if info, e := root.Stat(id + "/status.json"); e == nil && time.Since(info.ModTime()) > time.Minute {
			status.State = "interrupted"
			status.Error = "Запуск рабочего процесса не подтверждён; проверьте systemd и состояние питания целевого узла"
		}
	}
	if status.State == "running" && status.PID > 0 {
		if info, e := root.Stat(id + "/status.json"); e == nil && time.Since(info.ModTime()) > 15*time.Second {
			cmdline, e := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", status.PID))
			expected := append([]byte(filepath.Join(base, id, "worker.py")), 0)
			if e != nil || !bytes.Contains(cmdline, expected) {
				status.State = "interrupted"
				status.Error = "Рабочий процесс остановился; проверьте питание второго узла перед продолжением"
			}
		}
	}
	return &status, nil
}
