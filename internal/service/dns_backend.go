package service

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sambaadm/internal/config"
	"strings"
	"time"
)

//go:embed helper_dns_backend.py
var dnsBackendWorker string

//go:embed helper_dns_bind_config.py
var dnsBindConfigWorker string

type DNSBackendInput struct {
	Target    string `json:"target"`
	Reinstall bool   `json:"reinstall"`
	Revision  string `json:"revision"`
	Confirm   bool   `json:"confirm"`
	ID        string `json:"id"`
}
type DNSBackendPlan struct {
	Backend     string   `json:"backend"`
	Target      string   `json:"target"`
	Reinstall   bool     `json:"reinstall"`
	Revision    string   `json:"revision"`
	Steps       []string `json:"steps"`
	Warning     string   `json:"warning"`
	SMBPath     string   `json:"smbPath"`
	BindPath    string   `json:"bindPath"`
	ProposedSMB string   `json:"-"`
	SMBHash     string   `json:"-"`
	BindHash    string   `json:"-"`
}

var dnsJobID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func backendBase(cfg *config.Config) (*os.Root, error) {
	if !filepath.IsAbs(cfg.Helper.StateDir) {
		return nil, fmt.Errorf("helper.state_dir должен быть абсолютным")
	}
	root, e := os.OpenRoot(cfg.Helper.StateDir)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	if e = root.Mkdir("dns-backend", 0700); e != nil && !os.IsExist(e) {
		return nil, e
	}
	st, e := root.Lstat("dns-backend")
	if e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("каталог заданий DNS должен иметь права 0700")
	}
	return root.OpenRoot("dns-backend")
}
func dnsBackendStatus(cfg *config.Config, id string) (any, error) {
	if !dnsJobID.MatchString(id) {
		return nil, fmt.Errorf("недопустимое задание DNS")
	}
	root, e := backendBase(cfg)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	raw, e := root.ReadFile(id + "/status.json")
	if e != nil {
		return nil, e
	}
	if len(raw) > 1<<20 {
		return nil, fmt.Errorf("журнал DNS превышает лимит")
	}
	var out map[string]any
	e = json.Unmarshal(raw, &out)
	if e != nil {
		return nil, e
	}
	if out["state"] == "running" || out["state"] == "queued" {
		st, err := root.Stat(id + "/status.json")
		if err == nil && time.Since(st.ModTime()) > 15*time.Second {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			active, err := runTimeCommand(ctx, "systemctl", "show", "--property=ActiveState", "--value", "sambaadm-dns-backend-"+id+".service")
			if err == nil && active != "active" && active != "activating" && active != "reloading" {
				out["state"] = "interrupted"
				out["warning"] = "Служба задания остановлена. Проверьте DNS и резервные копии перед повторным запуском."
				data, _ := json.Marshal(out)
				_ = root.WriteFile(id+"/status.json", data, 0600)
			}
		}
	}
	return out, nil
}
func planDNSBackend(ctx context.Context, cfg *config.Config, in DNSBackendInput) (*DNSBackendPlan, error) {
	if in.Target != "BIND9_DLZ" && in.Target != "SAMBA_INTERNAL" {
		return nil, fmt.Errorf("выберите BIND9_DLZ или SAMBA_INTERNAL")
	}
	if in.Reinstall && in.Target != "BIND9_DLZ" {
		return nil, fmt.Errorf("переустановка пакетов доступна для BIND")
	}
	osRelease, e := os.ReadFile("/etc/os-release")
	if e != nil || !strings.Contains(strings.ToLower(string(osRelease)), "altlinux") {
		return nil, fmt.Errorf("мастер переключения DNS пока поддерживает ALT Linux")
	}
	role, e := runTimeCommand(ctx, "testparm", "-s", "--parameter-name=server role")
	if e != nil || !strings.Contains(strings.ToLower(role), "active directory domain controller") {
		return nil, fmt.Errorf("узел должен быть контроллером Samba AD")
	}
	services, e := runTimeCommand(ctx, "testparm", "-s", "--parameter-name=server services")
	if e != nil {
		return nil, e
	}
	backend := "BIND9_DLZ"
	hasDNS := false
	list := []string{}
	for _, v := range strings.FieldsFunc(services, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if v == "dns" {
			hasDNS = true
			continue
		}
		list = append(list, v)
	}
	if hasDNS {
		backend = "SAMBA_INTERNAL"
	}
	if in.Target == "SAMBA_INTERNAL" {
		list = append(list, "dns")
	}
	smb := cfg.Samba.SMBConf
	if smb == "" {
		smb = "/etc/samba/smb.conf"
	}
	smb, e = filepath.EvalSymlinks(smb)
	if e != nil {
		return nil, e
	}
	h := &dnsForwardHost{path: smb}
	raw, _, e := h.read()
	if e != nil {
		return nil, e
	}
	proposed, e := patchGlobal(raw, map[string]string{"server services": strings.Join(list, ", ")})
	if e != nil {
		return nil, e
	}
	bind := cfg.Helper.DNSConfig
	if bind == "" {
		bind = "/etc/bind/named.conf"
	}
	bind, e = filepath.EvalSymlinks(bind)
	if e != nil {
		if !os.IsNotExist(e) {
			return nil, e
		}
		bind = "/etc/bind/named.conf"
	}
	bindRaw := []byte{}
	if _, e = os.Lstat(bind); e == nil {
		bindRaw, _, e = (&dnsForwardHost{path: bind}).read()
		if e != nil {
			return nil, e
		}
	}
	if in.Target == "BIND9_DLZ" {
		// APT may rebuild its cache even in simulation mode. Keep this inside
		// StateDirectory instead of granting the helper global APT write access.
		root, err := os.OpenRoot(cfg.Helper.StateDir)
		if err != nil {
			return nil, err
		}
		err = root.MkdirAll("dns-apt-cache/archives/partial", 0700)
		root.Close()
		if err != nil {
			return nil, err
		}
		cache := filepath.Join(cfg.Helper.StateDir, "dns-apt-cache")
		if output, e := runTimeCommand(ctx, "apt-get", "-o", "Dir::Cache="+cache, "-s", "install", "bind", "bind-utils"); e != nil {
			return nil, fmt.Errorf("пакеты BIND недоступны в настроенных репозиториях: %s", output)
		} else if strings.Contains(output, "Remv ") || strings.Contains(output, "Inst samba") {
			return nil, fmt.Errorf("план пакетов удаляет пакеты или обновляет Samba; сначала обновите систему отдельно")
		}
	}
	steps := []string{"Сохранить конфигурацию и состояние служб в закрытый каталог helper"}
	if in.Target == "BIND9_DLZ" {
		steps = append(steps, "Обновить индексы настроенных репозиториев ALT и повторно проверить план пакетов", "Установить bind и bind-utils (переустановить при выбранной опции)")
	}
	steps = append(steps, "Остановить DNS и Samba на выбранном контроллере", "Запустить samba_upgradedns --dns-backend="+in.Target, "Подготовить BIND для AD: chroot, Kerberos и сетевые параметры новой установки", "Проверить конфигурацию и запустить выбранный DNS-бэкенд", "Проверить SOA домена и SRV LDAP; при ошибке попытаться восстановить прежний бэкенд")
	rev := configRevision(append(append(append([]byte{}, raw...), bindRaw...), []byte(services+in.Target+fmt.Sprint(in.Reinstall))...))
	return &DNSBackendPlan{Backend: backend, Target: in.Target, Reinstall: in.Reinstall, Revision: rev, Steps: steps, Warning: "Будет кратковременный перерыв DNS и служб этого DC. AD-зоны сохраняются. Условные пересылки BIND не работают во встроенном DNS; конфигурация BIND сохраняется. Изменения выполняются только на выбранном DC.", SMBPath: smb, BindPath: bind, ProposedSMB: string(proposed), SMBHash: configRevision(raw), BindHash: configRevision(bindRaw)}, nil
}
func helperDNSBackend(ctx context.Context, cfg *config.Config, method string, in HostOperation) (any, error) {
	var req DNSBackendInput
	if e := decodeHost(in.Input, &req); e != nil {
		return nil, e
	}
	p, e := planDNSBackend(ctx, cfg, req)
	if e != nil {
		return nil, e
	}
	if method == "dns.backend.plan" {
		return p, nil
	}
	if method != "dns.backend.start" {
		return nil, fmt.Errorf("неизвестная операция DNS")
	}
	if !req.Confirm || req.Revision == "" || req.Revision != p.Revision {
		return nil, fmt.Errorf("повторите предпросмотр и подтвердите переключение DNS")
	}
	root, e := backendBase(cfg)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	entries, e := root.Open(".")
	if e != nil {
		return nil, e
	}
	names, e := entries.Readdirnames(-1)
	entries.Close()
	if e != nil {
		return nil, e
	}
	for _, name := range names {
		if !dnsJobID.MatchString(name) {
			continue
		}
		state, e := dnsBackendStatus(cfg, name)
		if e != nil {
			return nil, e
		}
		data, _ := json.Marshal(state)
		var st struct {
			State string `json:"state"`
		}
		if json.Unmarshal(data, &st) != nil {
			return nil, fmt.Errorf("повреждён журнал задания DNS")
		}
		if st.State == "running" || st.State == "queued" {
			return nil, fmt.Errorf("уже выполняется задание DNS %s; проверьте его журнал", name)
		}
	}
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return nil, e
	}
	id := hex.EncodeToString(nonce[:])
	if e = root.Mkdir(id, 0700); e != nil {
		return nil, e
	}
	job, e := root.OpenRoot(id)
	if e != nil {
		return nil, e
	}
	defer job.Close()
	data, _ := json.Marshal(map[string]any{"id": id, "state": "queued", "log": []string{"Задание подготовлено"}, "created": time.Now().UTC()})
	payload, _ := json.Marshal(map[string]any{"id": id, "plan": p, "smb": p.ProposedSMB, "actor": in.Actor, "stateDir": cfg.Helper.StateDir, "smbHash": p.SMBHash, "bindHash": p.BindHash})
	for name, raw := range map[string][]byte{"status.json": data, "request.json": payload, "worker.py": []byte(dnsBackendWorker), "helper_dns_bind_config.py": []byte(dnsBindConfigWorker)} {
		f, e := job.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		_, e = f.Write(raw)
		ce := f.Close()
		if e != nil {
			return nil, e
		}
		if ce != nil {
			return nil, ce
		}
	}
	folder := filepath.Join(cfg.Helper.StateDir, "dns-backend", id)
	if output, e := runTimeCommand(ctx, "systemd-run", "--quiet", "--collect", "--unit=sambaadm-dns-backend-"+id, "--property=RuntimeMaxSec=900", "/usr/bin/python3", filepath.Join(folder, "worker.py"), folder); e != nil {
		data, _ = json.Marshal(map[string]any{"id": id, "state": "failed", "log": []string{"Не удалось запустить задание: " + output}})
		_ = job.WriteFile("status.json", data, 0600)
		return nil, e
	}
	return map[string]any{"id": id, "state": "queued"}, nil
}
