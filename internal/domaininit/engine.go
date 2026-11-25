// Package domaininit implements the fixed, local AD deployment workflow used
// by the first-forest wizard and signed helper requests. It never accepts a command.
package domaininit

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

//go:embed worker.py existing.py assets/*
var Files embed.FS

// Administrator passwords are passed to Start/Resume through stdin and never saved.
type Input struct {
	ServiceUser   string `json:"serviceUser,omitempty"`
	TransferRoles bool   `json:"transferRoles,omitempty"`
	Certificate   []byte `json:"certificate,omitempty"`
	CA            []byte `json:"ca,omitempty"`
	Mode          string `json:"mode"`
	Realm         string `json:"realm"`
	NetBIOS       string `json:"netbios"`
	Hostname      string `json:"hostname"`
	Address       string `json:"address"`
	Site          string `json:"site"`
	Source        string `json:"source"`
	Forwarder     string `json:"forwarder"`
	Level         string `json:"level"`
	PanelName     string `json:"panelName"`
	Revision      string `json:"revision,omitempty"`
	Confirm       bool   `json:"confirm,omitempty"`
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
}

func (Input) GoString() string { return "[domain deployment input]" }
func (Input) String() string   { return "[domain deployment input]" }

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var shortName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,14}$`)
var jobID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func DNS(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for _, p := range strings.Split(name, ".") {
		if !label.MatchString(p) {
			return false
		}
	}
	return true
}
func (in Input) Validate() error {
	if !DNS(in.Realm) || !shortName.MatchString(in.Hostname) || !(shortName.MatchString(in.NetBIOS) || (in.Mode == "existing" && in.NetBIOS == "")) {
		return fmt.Errorf("Укажите DNS-имя домена, короткое имя контроллера и NetBIOS (до 15 знаков)")
	}
	if strings.EqualFold(in.Hostname, in.NetBIOS) || !DNS(strings.ToLower(in.Hostname)+"."+in.Realm) {
		return fmt.Errorf("Имя контроллера должно отличаться от NetBIOS домена и образовывать корректное DNS-имя")
	}
	if in.Mode != "forest" && in.Mode != "DC" && in.Mode != "RODC" && in.Mode != "existing" {
		return fmt.Errorf("Выберите новый лес, RWDC или RODC")
	}
	if (strings.TrimSpace(in.Site) == "" && in.Mode != "existing") || utf8.RuneCountInString(in.Site) > 64 || strings.ContainsAny(in.Site, "\x00\r\n/\\") {
		return fmt.Errorf("Укажите корректное имя сайта")
	}
	if in.Mode != "forest" && (!DNS(in.Source) || !strings.HasSuffix(in.Source, "."+in.Realm)) {
		return fmt.Errorf("Выберите исходный RWDC этого домена")
	}
	if (in.Mode == "forest" || in.Mode == "existing") && (!DNS(in.PanelName) || !strings.HasSuffix(in.PanelName, "."+in.Realm)) {
		return fmt.Errorf("Укажите HTTPS-имя панели в новом домене")
	}
	if (in.Mode == "existing" && in.Level != "auto") || (in.Mode != "existing" && in.Level != "2008_R2" && in.Level != "2008" && in.Level != "2003") {
		return fmt.Errorf("Выберите поддерживаемый уровень леса")
	}
	if in.ServiceUser != "" && in.Mode != "existing" {
		return fmt.Errorf("Имя служебной записи задаётся только для существующего домена")
	}
	if in.TransferRoles && in.Mode != "existing" {
		return fmt.Errorf("Перенос ролей доступен в мастере присоединения к существующему домену")
	}
	if in.Mode == "existing" && !regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,19}$`).MatchString(in.ServiceUser) {
		return fmt.Errorf("Укажите имя новой служебной записи до 20 знаков")
	}
	ip, e := netip.ParseAddr(in.Address)
	if e != nil || !ip.Is4() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("Укажите IPv4 интерфейса сервера")
	}
	dns, e := netip.ParseAddr(in.Forwarder)
	if e != nil || dns.IsLoopback() || dns.IsMulticast() || dns.IsUnspecified() || dns == ip {
		return fmt.Errorf("Укажите адрес внешнего DNS-пересыльщика")
	}
	if len(in.Password) > 1024 || strings.ContainsAny(in.Password+in.Username, "\x00\r\n") || len(in.Username) > 256 {
		return fmt.Errorf("Недопустимые учётные данные")
	}
	return nil
}

type Plan struct {
	CSR         []byte   `json:"csr,omitempty"`
	Certificate []byte   `json:"certificate,omitempty"`
	CA          []byte   `json:"ca,omitempty"`
	Revision    string   `json:"revision"`
	Checks      []string `json:"checks"`
	Packages    []string `json:"packages"`
	Steps       []string `json:"steps"`
}
type Status struct {
	Resumable bool           `json:"resumable,omitempty"`
	Report    map[string]any `json:"report,omitempty"`
	Realm     string         `json:"realm,omitempty"`
	Node      string         `json:"node,omitempty"`
	Site      string         `json:"site,omitempty"`
	Mode      string         `json:"mode,omitempty"`
	CA        []byte         `json:"ca,omitempty"`
	ID        string         `json:"id"`
	State     string         `json:"state"`
	Phase     string         `json:"phase,omitempty"`
	Log       []string       `json:"log"`
	Error     string         `json:"error,omitempty"`
	PID       int            `json:"pid,omitempty"`
	PanelURL  string         `json:"panelURL,omitempty"`
}
type Engine struct {
	Dir string
	mu  sync.Mutex
}

func (e *Engine) base() error {
	if !filepath.IsAbs(e.Dir) {
		return fmt.Errorf("Каталог заданий должен быть абсолютным")
	}
	if err := os.MkdirAll(e.Dir, 0700); err != nil {
		return err
	}
	st, err := os.Lstat(e.Dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("Каталог заданий требует прав 0700")
	}
	return nil
}
func (e *Engine) script() (string, error) {
	if err := e.base(); err != nil {
		return "", err
	}
	extra, _ := Files.ReadFile("existing.py")
	extraFile, err := os.CreateTemp(e.Dir, ".existing-")
	if err != nil {
		return "", err
	}
	defer os.Remove(extraFile.Name())
	if _, err = extraFile.Write(extra); err != nil {
		extraFile.Close()
		return "", err
	}
	if err = extraFile.Close(); err != nil {
		return "", err
	}
	if err = os.Rename(extraFile.Name(), filepath.Join(e.Dir, "existing.py")); err != nil {
		return "", err
	}
	raw, _ := Files.ReadFile("worker.py")
	path := filepath.Join(e.Dir, "worker.py")
	// Only this process writes the fixed script; no request controls its contents.
	f, err := os.CreateTemp(e.Dir, ".worker-")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(raw)
	err = errors.Join(err, f.Close())
	if err != nil {
		return "", err
	}
	return path, os.Rename(f.Name(), path)
}
func (e *Engine) Plan(ctx context.Context, in Input) (*Plan, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := in.Validate(); err != nil {
		return nil, err
	}
	in.Password = ""
	in.Username = ""
	in.Revision = ""
	in.Confirm = false
	in.Certificate = nil
	in.CA = nil
	path, err := e.script()
	if err != nil {
		return nil, err
	}
	data, _ := json.Marshal(in)
	cmd := exec.CommandContext(ctx, "systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--property=RuntimeMaxSec=180", "/usr/bin/python3", path, "plan", e.Dir)
	cmd.Stdin = bytes.NewReader(data)
	output, err := cmd.Output()
	var result struct {
		Plan
		Error string `json:"error"`
	}
	if json.Unmarshal(output, &result) != nil {
		return nil, fmt.Errorf("Проверка не завершена; проверьте ALT Linux, Python 3 и репозитории")
	}
	if err != nil || result.Error != "" {
		return nil, fmt.Errorf("%s", result.Error)
	}
	_, csr, err := e.certificateKey(result.Revision, in)
	if err != nil {
		return nil, err
	}
	result.CSR = csr
	return &result.Plan, nil
}
func (e *Engine) Read(id string) (*Status, error) {
	if !jobID.MatchString(id) {
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
		st, _ := root.Stat(id + "/status.json")
		if st != nil && time.Since(st.ModTime()) > 30*time.Second {
			dead := out.PID == 0
			if out.PID > 0 {
				p, e := os.FindProcess(out.PID)
				dead = e != nil || p.Signal(syscall.Signal(0)) != nil
			}
			if dead {
				out.State = "interrupted"
				out.Error = "Процесс задания завершился без результата. Проверьте сервер перед повтором."
			}
		}
	}
	return &out, err
}
func (e *Engine) Start(ctx context.Context, in Input) (*Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := in.Validate(); err != nil {
		return nil, err
	}
	if !in.Confirm || len(in.Revision) != 64 || in.Password == "" || (in.Mode == "forest" && utf8.RuneCountInString(in.Password) < 8) || (in.Mode != "forest" && strings.TrimSpace(in.Username) == "") {
		return nil, fmt.Errorf("Повторите проверку, введите пароль и подтвердите развёртывание")
	}
	if in.Mode == "forest" {
		var groups [4]bool
		for _, r := range in.Password {
			switch {
			case unicode.IsUpper(r):
				groups[0] = true
			case unicode.IsLower(r):
				groups[1] = true
			case unicode.IsDigit(r):
				groups[2] = true
			case !unicode.IsLetter(r) && !unicode.IsNumber(r):
				groups[3] = true
			}
		}
		classes := 0
		for _, present := range groups {
			if present {
				classes++
			}
		}
		if classes < 3 {
			return nil, fmt.Errorf("Пароль Administrator должен содержать не менее трёх групп: прописные, строчные, цифры, специальные знаки")
		}
	}
	path, err := e.script()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(e.Dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !jobID.MatchString(entry.Name()) {
			continue
		}
		status, err := e.Read(entry.Name())
		if err != nil {
			return nil, err
		}
		if status.State == "queued" || status.State == "running" {
			return nil, fmt.Errorf("Уже выполняется задание %s; проверьте журнал", status.ID)
		}
	}
	tlsFiles, err := e.deploymentTLS(in)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	id := hex.EncodeToString(nonce[:])
	dir := filepath.Join(e.Dir, id)
	if err = os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	for name, data := range tlsFiles {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return nil, err
		}
	}
	clear(tlsFiles["tls.key"])
	status := &Status{Realm: in.Realm, Node: in.Hostname + "." + in.Realm, Site: in.Site, Mode: in.Mode, CA: in.CA, ID: id, State: "queued", Log: []string{"Задание принято; до установки будут повторно проверены репозитории и пакеты"}}
	if in.Mode == "existing" {
		saved := in
		saved.Username, saved.Password, saved.Revision = "", "", ""
		saved.Certificate, saved.CA, saved.Confirm = nil, nil, false
		raw, _ := json.Marshal(saved)
		if err := os.WriteFile(filepath.Join(dir, "request.json"), raw, 0600); err != nil {
			return nil, err
		}
	}
	raw, _ := json.Marshal(status)
	if err = os.WriteFile(filepath.Join(dir, "status.json"), raw, 0600); err != nil {
		return nil, err
	}
	return e.launch(in, status, path, "apply")
}

// Resume completes panel configuration only after AD and SYSVOL were verified.
// It loads immutable target parameters from the original root-owned request.
func (e *Engine) Resume(ctx context.Context, id, username, password string) (*Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !jobID.MatchString(id) {
		return nil, fmt.Errorf("Некорректный номер задания")
	}
	st, err := e.Read(id)
	if err != nil {
		return nil, err
	}
	if st.Mode != "existing" || !st.Resumable || (st.State != "failed" && st.State != "interrupted") {
		return nil, fmt.Errorf("Задание не допускает продолжение; проверьте журнал")
	}
	raw, err := os.ReadFile(filepath.Join(e.Dir, id, "request.json"))
	if err != nil {
		return nil, err
	}
	var in Input
	if err = json.Unmarshal(raw, &in); err != nil {
		return nil, err
	}
	in.Username, in.Password, in.CA = username, password, st.CA
	if err = in.Validate(); err != nil {
		return nil, err
	}
	if password == "" || strings.TrimSpace(username) == "" {
		return nil, fmt.Errorf("Введите доменную учётную запись и пароль")
	}
	path, err := e.script()
	if err != nil {
		return nil, err
	}
	st.State, st.Error, st.PID = "queued", "", 0
	return e.launch(in, st, path, "resume")
}

func (e *Engine) launch(in Input, status *Status, path, mode string) (*Status, error) {
	id := status.ID
	dir := filepath.Join(e.Dir, id)
	raw, _ := json.Marshal(status)
	if err := os.WriteFile(filepath.Join(dir, "status.json"), raw, 0600); err != nil {
		return nil, err
	}
	payload, _ := json.Marshal(in)
	defer clear(payload)
	// Detached worker survives browser disconnect and service reconfiguration.
	cmd := exec.Command("systemd-run", "--quiet", "--collect", "--wait", "--pipe", "--unit=sambaadm-domain-init-"+id, "--property=RuntimeMaxSec=7200", "/usr/bin/python3", path, mode, e.Dir, id)
	detach(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		stdin.Close()
		status.State = "failed"
		status.Error = "Не удалось запустить Python"
		raw, _ := json.Marshal(status)
		_ = os.WriteFile(filepath.Join(dir, "status.json"), raw, 0600)
		return nil, err
	}
	_, err = stdin.Write(payload)
	err = errors.Join(err, stdin.Close())
	go func() {
		if err := cmd.Wait(); err != nil {
			e.mu.Lock()
			defer e.mu.Unlock()
			current, readErr := e.Read(id)
			if readErr != nil || current.State == "failed" || current.State == "completed" {
				return
			}
			if current.PID > 0 {
				process, e := os.FindProcess(current.PID)
				if e == nil && process.Signal(syscall.Signal(0)) == nil {
					return
				}
			}
			current.State = "interrupted"
			current.Error = "Процесс развёртывания завершился без подтверждённого результата. Проверьте сервер перед повтором."
			current.Log = append(current.Log, current.Error)
			data, _ := json.Marshal(current)
			_ = os.WriteFile(filepath.Join(dir, "status.json"), data, 0600)
		}
	}()
	if err != nil {
		return nil, fmt.Errorf("Передача параметров не подтверждена; проверьте журнал %s", id)
	}
	return status, nil
}

// Latest allows a new bootstrap console to recover a job whose browser response
// was lost. It only reads the root-owned journal, never repeats an operation.
func (e *Engine) Latest() (*Status, error) {
	entries, err := os.ReadDir(e.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var latest *Status
	var when time.Time
	for _, entry := range entries {
		if !entry.IsDir() || !jobID.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if latest != nil && !info.ModTime().After(when) {
			continue
		}
		st, err := e.Read(entry.Name())
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		latest = st
		when = info.ModTime()
	}
	return latest, nil
}
