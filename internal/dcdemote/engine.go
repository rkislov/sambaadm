// Package dcdemote performs a fixed, journalled DC-to-member transition.
package dcdemote

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sambaadm/internal/domaininit"
	"strings"
	"sync"
	"time"
)

//go:embed worker.py
var files embed.FS
var ident = regexp.MustCompile(`^[a-f0-9]{32}$`)
var revision = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Manifest struct {
	Node   string `json:"node"`
	Realm  string `json:"realm"`
	GUID   string `json:"guid"`
	Digest string `json:"digest"`
}
type Input struct {
	Reference Manifest `json:"-"`
	Node      string   `json:"node"`
	Source    string   `json:"source"`
	Realm     string   `json:"realm"`
	Username  string   `json:"username"`
	Password  string   `json:"password"`
	Revision  string   `json:"revision,omitempty"`
	Confirm   string   `json:"confirm,omitempty"`
	ID        string   `json:"id,omitempty"`
}

func (Input) String() string   { return "[DC retirement credentials redacted]" }
func (Input) GoString() string { return "[DC retirement credentials redacted]" }
func (in Input) Validate() error {
	if !domaininit.DNS(in.Realm) || !domaininit.DNS(in.Node) || !domaininit.DNS(in.Source) || in.Source == in.Node || !strings.HasSuffix(in.Node, "."+in.Realm) || !strings.HasSuffix(in.Source, "."+in.Realm) {
		return fmt.Errorf("Выберите разные контроллеры одного домена")
	}
	if strings.TrimSpace(in.Username) == "" || len(in.Username) > 256 || in.Password == "" || len(in.Password) > 1024 || strings.ContainsAny(in.Username+in.Password, "\x00\r\n") {
		return fmt.Errorf("Введите учётные данные администратора домена")
	}
	return nil
}

type Plan struct {
	Addresses []string `json:"addresses"`
	Revision  string   `json:"revision"`
	Checks    []string `json:"checks"`
	Steps     []string `json:"steps"`
	Packages  []string `json:"packages"`
}
type Status struct {
	ID     string   `json:"id"`
	Node   string   `json:"node"`
	Source string   `json:"source"`
	State  string   `json:"state"`
	Phase  string   `json:"phase,omitempty"`
	Log    []string `json:"log"`
	Error  string   `json:"error,omitempty"`
}
type Engine struct {
	Dir, Config string
	mu          sync.Mutex
}

func (e *Engine) script() (string, error) {
	if !filepath.IsAbs(e.Dir) || !filepath.IsAbs(e.Config) {
		return "", fmt.Errorf("Требуется абсолютный путь состояния и конфигурации helper")
	}
	if err := os.MkdirAll(e.Dir, 0700); err != nil {
		return "", err
	}
	st, err := os.Lstat(e.Dir)
	if err != nil {
		return "", err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("Каталог снятия роли должен иметь права 0700")
	}
	raw, _ := files.ReadFile("worker.py")
	f, err := os.CreateTemp(e.Dir, ".worker-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	path := filepath.Join(e.Dir, "worker.py")
	return path, os.Rename(f.Name(), path)
}
func (e *Engine) Plan(ctx context.Context, in Input) (*Plan, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := in.Validate(); err != nil {
		return nil, err
	}
	path, err := e.script()
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(struct {
		Input
		Reference Manifest `json:"reference"`
	}{in, in.Reference})
	defer clear(raw)
	cmd := exec.CommandContext(ctx, "systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--property=RuntimeMaxSec=180", "/usr/bin/python3", path, "plan", e.Dir, e.Config)
	cmd.Stdin = bytes.NewReader(raw)
	output, err := cmd.Output()
	var out struct {
		Plan
		Error string `json:"error"`
	}
	if json.Unmarshal(output, &out) != nil {
		return nil, fmt.Errorf("Проверка не завершена; проверьте журнал helper и доступность сервера")
	}
	if err != nil || out.Error != "" {
		return nil, fmt.Errorf("%s", out.Error)
	}
	return &out.Plan, nil
}
func (e *Engine) Read(id string) (*Status, error) {
	if !ident.MatchString(id) {
		return nil, fmt.Errorf("Некорректный номер задания")
	}
	root, err := os.OpenRoot(e.Dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	raw, err := root.ReadFile(id + "/status.json")
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("Журнал превышает лимит")
	}
	var out Status
	err = json.Unmarshal(raw, &out)
	if err == nil && (out.State == "running" || out.State == "queued") {
		info, _ := root.Stat(id + "/status.json")
		if info != nil && time.Since(info.ModTime()) > 30*time.Second {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "sambaadm-dc-demote-"+id+".service").Run() != nil {
				ledgerRaw, readErr := root.ReadFile(id + "/ledger.json")
				var ledger struct {
					Attempted bool `json:"attempted"`
					Demoted   bool `json:"demoted"`
				}
				if readErr == nil && json.Unmarshal(ledgerRaw, &ledger) == nil {
					out.State = "cancelled"
					if ledger.Attempted {
						out.State = "needs_review"
					}
					if ledger.Demoted {
						out.State = "needs_member"
					}
				} else {
					out.State = "needs_review"
				}
				out.Error = "Процесс прерван. Проверьте журнал; продолжение не повторяет снятие роли DC."
			}
		}
	}
	return &out, err
}
func (e *Engine) Start(ctx context.Context, in Input, resume bool) (*Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := in.Validate(); err != nil {
		return nil, err
	}
	if in.Confirm != in.Node || (!resume && !revision.MatchString(in.Revision)) {
		return nil, fmt.Errorf("Повторите проверку и введите DNS-имя снимаемого контроллера")
	}
	path, err := e.script()
	if err != nil {
		return nil, err
	}
	id := in.ID
	if resume {
		if !ident.MatchString(id) {
			return nil, fmt.Errorf("Некорректный номер задания")
		}
		st, err := e.Read(id)
		if err != nil {
			return nil, err
		}
		if st.Node != in.Node || st.Source != in.Source || st.State == "completed" {
			return nil, fmt.Errorf("Задание не допускает продолжения")
		}
	}
	entries, err := os.ReadDir(e.Dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !ident.MatchString(entry.Name()) {
			continue
		}
		st, err := e.Read(entry.Name())
		if err != nil {
			return nil, err
		}
		if st.State != "completed" && st.State != "cancelled" && (!resume || entry.Name() != id) {
			return nil, fmt.Errorf("Сначала проверьте незавершённое задание %s", st.ID)
		}
	}
	if !resume {
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return nil, err
		}
		id = hex.EncodeToString(nonce[:])
		if err = os.Mkdir(filepath.Join(e.Dir, id), 0700); err != nil {
			return nil, err
		}
	}
	st := &Status{ID: id, Node: in.Node, Source: in.Source, State: "queued", Log: []string{"Задание принято. Пароль не сохраняется."}}
	if resume {
		previous, err := e.Read(id)
		if err != nil {
			return nil, err
		}
		// A live unit must never have its journal reset by a duplicate resume click.
		if exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "sambaadm-dc-demote-"+id+".service").Run() == nil {
			return nil, fmt.Errorf("Задание уже выполняется; дождитесь результата")
		}
		st.Log = previous.Log
		st.Phase = previous.Phase
	}
	{
		raw, _ := json.Marshal(st)
		if err = os.WriteFile(filepath.Join(e.Dir, id, "status.json"), raw, 0600); err != nil {
			return nil, err
		}
	}
	raw, _ := json.Marshal(struct {
		Input
		Reference Manifest `json:"reference"`
	}{in, in.Reference})
	defer clear(raw)
	mode := "apply"
	if resume {
		mode = "resume"
	}
	// systemd owns the process; neither helper restarts nor browser disconnects kill it.
	cmd := exec.Command("systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--unit=sambaadm-dc-demote-"+id, "--property=RuntimeMaxSec=7200", "/usr/bin/python3", path, mode, e.Dir, e.Config, id)
	detach(cmd)
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
	_, err = stdin.Write(raw)
	closeErr := stdin.Close()
	go func() { _ = cmd.Wait() }()
	if err != nil || closeErr != nil {
		return nil, fmt.Errorf("Проверьте журнал %s: ответ запуска не подтверждён", id)
	}
	return st, nil
}

func (e *Engine) Manifest(ctx context.Context, node, realm string) (*Manifest, error) {
	path, err := e.script()
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(map[string]string{"node": node, "realm": realm})
	cmd := exec.CommandContext(ctx, "systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--property=RuntimeMaxSec=180", "/usr/bin/python3", path, "manifest", e.Dir, e.Config)
	cmd.Stdin = bytes.NewReader(raw)
	output, err := cmd.Output()
	var out struct {
		Manifest
		Error string `json:"error"`
	}
	if json.Unmarshal(output, &out) != nil {
		return nil, fmt.Errorf("Не получен эталон SYSVOL от helper RWDC")
	}
	if err != nil || out.Error != "" {
		return nil, fmt.Errorf("%s", out.Error)
	}
	return &out.Manifest, nil
}
