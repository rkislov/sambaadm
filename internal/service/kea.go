package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
)

const keaConfigLimit = 1 << 20

type KeaRequest struct {
	GSSSecret           string           `json:"gssSecret,omitempty"`
	GSSJoin             bool             `json:"gssJoin,omitempty"`
	GSS                 *KeaGSSSettings  `json:"gss,omitempty"`
	JobID               string           `json:"jobID,omitempty"`
	DDNS                *KeaDDNSSettings `json:"ddns,omitempty"`
	Search              string           `json:"search,omitempty"`
	From                string           `json:"from,omitempty"`
	SubnetID            uint32           `json:"subnetID,omitempty"`
	Lease               *KeaLeaseRef     `json:"lease,omitempty"`
	UpdateDDNS          bool             `json:"updateDDNS,omitempty"`
	ReservationHostname *string          `json:"reservationHostname,omitempty"`
	Family              string           `json:"family"`
	Config              string           `json:"config,omitempty"`
	Revision            string           `json:"revision,omitempty"`
	ProposedRevision    string           `json:"proposedRevision,omitempty"`
	Confirm             bool             `json:"confirm,omitempty"`
	Action              string           `json:"action,omitempty"`
}
type KeaStatus struct {
	Node     string            `json:"node"`
	Family   string            `json:"family"`
	Path     string            `json:"path"`
	Unit     string            `json:"unit"`
	Version  string            `json:"version"`
	Service  string            `json:"service"`
	Enabled  string            `json:"enabled"`
	Config   string            `json:"config"`
	Revision string            `json:"revision"`
	Document json.RawMessage   `json:"document,omitempty"`
	Warning  string            `json:"warning,omitempty"`
	Hooks    map[string]string `json:"hooks"`
}
type KeaPlan struct {
	Family           string `json:"family"`
	Revision         string `json:"revision"`
	ProposedRevision string `json:"proposedRevision"`
	Before           string `json:"before"`
	Proposed         string `json:"proposed"`
	Validation       string `json:"validation"`
	Action           string `json:"action"`
}
type KeaResult struct {
	Backup string     `json:"backup,omitempty"`
	Detail string     `json:"detail,omitempty"`
	Status *KeaStatus `json:"status,omitempty"`
}
type KeaService struct {
	Helpers *agent.Client
	Audit   *audit.Logger
}

func (s KeaService) Call(ctx context.Context, node, method string, req KeaRequest, actor, ip string, out any) (err error) {
	switch method {
	case "kea.gss.install.plan", "kea.gss.install.start", "kea.gss.install.status", "kea.gss.ad.plan", "kea.gss.ad.apply", "kea.inspect", "kea.plan", "kea.apply", "kea.service", "kea.install.plan", "kea.install", "kea.leases", "kea.lease.delete", "kea.lease.reserve.plan", "kea.ddns.inspect", "kea.ddns.plan", "kea.ddns.apply", "kea.ddns.service":
	default:
		return fmt.Errorf("неизвестная операция Kea")
	}
	if s.Helpers == nil || !s.Helpers.Has(node) {
		return fmt.Errorf("для сервера не зарегистрирован sambaadm-helper")
	}
	defer func() {
		if s.Audit != nil && (method == "kea.apply" || method == "kea.service" || method == "kea.install" || method == "kea.lease.delete" || method == "kea.ddns.apply" || method == "kea.ddns.service" || method == "kea.gss.install.start" || method == "kea.gss.ad.apply") {
			if err != nil {
				s.Audit.Failure(actor, method, keaAuditTarget(node, req), ip, err)
			} else {
				s.Audit.Success(actor, method, keaAuditTarget(node, req), ip)
			}
		}
	}()
	return s.Helpers.Call(ctx, node, method, HostOperation{Input: hostInput(req), Actor: actor, IP: ip}, out)
}

func keaAuditTarget(node string, req KeaRequest) string {
	target := node + " IPv" + req.Family
	if req.Lease != nil {
		target += " " + req.Lease.Address
	}
	return target
}

type keaHost struct {
	cfg                        *config.Config
	path, unit, binary, family string
	run                        func(context.Context, string, ...string) (string, error)
}

func newKeaHost(cfg *config.Config, family string) (*keaHost, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("для Kea нужен Linux-helper")
	}
	return configuredKeaHost(cfg, family)
}
func configuredKeaHost(cfg *config.Config, family string) (*keaHost, error) {
	if family != "4" && family != "6" {
		return nil, fmt.Errorf("выберите IPv4 или IPv6")
	}
	p := cfg.Helper.Kea4Config
	if family == "6" {
		p = cfg.Helper.Kea6Config
	}
	if p == "" {
		p = "/etc/kea/kea-dhcp" + family + ".conf"
	}
	if !filepath.IsAbs(p) || filepath.Clean(p) != p {
		return nil, fmt.Errorf("путь конфигурации Kea должен быть абсолютным")
	}
	return &keaHost{cfg: cfg, path: p, unit: "kea-dhcp" + family + ".service", binary: "kea-dhcp" + family, family: family, run: runKeaCommand}, nil
}
func runKeaCommand(ctx context.Context, name string, args ...string) (string, error) {
	if name != "systemd-run" {
		return runTimeCommand(ctx, name, args...)
	}
	ctx, cancel := context.WithTimeout(ctx, 170*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	var out probeOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return out.buf.String(), err
}
func (h *keaHost) read() ([]byte, os.FileMode, error) {
	st, e := os.Lstat(h.path)
	if errors.Is(e, os.ErrNotExist) {
		return []byte{}, 0640, nil
	}
	if e != nil {
		return nil, 0, e
	}
	if !st.Mode().IsRegular() || st.Size() > keaConfigLimit {
		return nil, 0, fmt.Errorf("конфигурация должна быть обычным файлом до 1 МиБ")
	}
	f, e := os.Open(h.path)
	if e != nil {
		return nil, 0, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, keaConfigLimit+1))
	if len(b) > keaConfigLimit {
		return nil, 0, fmt.Errorf("конфигурация слишком велика")
	}
	return b, st.Mode().Perm(), e
}

// Normalize only for the visual editor. Expert editing keeps the original text.
// Includes are refused: their independent revisions cannot be covered by this plan.
func keaDocument(raw string, family string) (json.RawMessage, error) {
	b := []byte(raw)
	quoted, escape := false, false
	for i := 0; i < len(b); i++ {
		if quoted {
			if escape {
				escape = false
			} else if b[i] == '\\' {
				escape = true
			} else if b[i] == '"' {
				quoted = false
			}
			continue
		}
		if b[i] == '"' {
			quoted = true
			continue
		}
		if b[i] == '<' && i+1 < len(b) && b[i+1] == '?' {
			return nil, fmt.Errorf("include-файлы требуют ручного управления; объедините конфигурацию в один файл")
		}
		if b[i] == '#' || (b[i] == '/' && i+1 < len(b) && b[i+1] == '/') {
			for ; i < len(b) && b[i] != '\n'; i++ {
				b[i] = ' '
			}
			continue
		}
		if b[i] == '/' && i+1 < len(b) && b[i+1] == '*' {
			b[i] = ' '
			i++
			b[i] = ' '
			closed := false
			for i++; i < len(b); i++ {
				if b[i] == '*' && i+1 < len(b) && b[i+1] == '/' {
					b[i] = ' '
					i++
					b[i] = ' '
					closed = true
					break
				}
				if b[i] != '\n' {
					b[i] = ' '
				}
			}
			if !closed {
				return nil, fmt.Errorf("незакрытый комментарий")
			}
		}
	}
	quoted, escape = false, false
	for i := 0; i < len(b); i++ {
		if quoted {
			if escape {
				escape = false
			} else if b[i] == '\\' {
				escape = true
			} else if b[i] == '"' {
				quoted = false
			}
			continue
		}
		if b[i] == '"' {
			quoted = true
		}
		if b[i] == ',' {
			j := i + 1
			for j < len(b) && strings.ContainsRune(" \r\n\t", rune(b[j])) {
				j++
			}
			if j < len(b) && (b[j] == '}' || b[j] == ']') {
				b[i] = ' '
			}
		}
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(b, &doc) != nil {
		return nil, fmt.Errorf("неверная структура JSON Kea")
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(doc["Dhcp"+family], &root) != nil || root == nil {
		return nil, fmt.Errorf("требуется объект Dhcp%s", family)
	}
	out, e := json.Marshal(doc)
	return out, e
}
func (h *keaHost) hooks() map[string]string {
	out := map[string]string{}
	for _, name := range []string{"libdhcp_ha.so", "libdhcp_lease_cmds.so", "libddns_gss_tsig.so"} {
		for _, dir := range []string{"/usr/lib64/kea/hooks", "/usr/lib/kea/hooks", "/usr/lib64/kea", "/usr/lib/kea"} {
			p := filepath.Join(dir, name)
			if st, e := os.Stat(p); e == nil && st.Mode().IsRegular() {
				out[name] = p
				break
			}
		}
	}
	return out
}
func (h *keaHost) inspect(ctx context.Context) *KeaStatus {
	s := &KeaStatus{Node: h.cfg.Helper.Node, Family: h.family, Path: h.path, Unit: h.unit, Hooks: h.hooks()}
	s.Version, _ = h.run(ctx, h.binary, "-v")
	s.Service, _ = h.run(ctx, "systemctl", "is-active", h.unit)
	s.Enabled, _ = h.run(ctx, "systemctl", "is-enabled", h.unit)
	raw, _, e := h.read()
	if e != nil {
		s.Warning = e.Error()
		return s
	}
	s.Config = string(raw)
	s.Revision = configRevision(raw)
	if len(raw) == 0 {
		s.Warning = "Конфигурация отсутствует. Создайте её в мастере."
		return s
	}
	s.Document, e = keaDocument(s.Config, h.family)
	if e != nil {
		s.Warning = e.Error()
	}
	return s
}
func (h *keaHost) stage(raw []byte, mode os.FileMode) (string, error) {
	// timeHost.stage retains ownership and fsyncs the candidate in the same directory.
	if _, e := os.Lstat(h.path); !errors.Is(e, os.ErrNotExist) {
		return (&timeHost{path: h.path}).stage(raw, mode)
	}
	f, e := os.CreateTemp(filepath.Dir(h.path), ".sambaadm-kea-*")
	if e != nil {
		return "", e
	}
	name := f.Name()
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(name)
		}
	}()
	if _, e = f.Write(raw); e != nil {
		return "", e
	}
	dirInfo, e := os.Stat(filepath.Dir(h.path))
	if e != nil {
		return "", e
	}
	if e = preserveConfigOwner(f, dirInfo); e != nil {
		return "", e
	}
	if e = f.Chmod(mode); e != nil {
		return "", e
	}
	if e = f.Sync(); e != nil {
		return "", e
	}
	if e = f.Close(); e != nil {
		return "", e
	}
	ok = true
	return name, nil
}
func (h *keaHost) validate(ctx context.Context, raw string) (string, error) {
	if len(raw) == 0 || len(raw) > keaConfigLimit {
		return "", fmt.Errorf("конфигурация должна содержать от 1 байта до 1 МиБ")
	}
	if _, e := keaDocument(raw, h.family); e != nil {
		return "", e
	}
	name, e := h.stage([]byte(raw), 0600)
	if e != nil {
		return "", e
	}
	defer os.Remove(name)
	out, e := h.run(ctx, h.binary, "-t", name)
	if e != nil {
		return "", fmt.Errorf("Kea отклонил конфигурацию: %s: %w", out, e)
	}
	return out, nil
}
func (h *keaHost) plan(ctx context.Context, in KeaRequest) (*KeaPlan, error) {
	raw, _, e := h.read()
	if e != nil {
		return nil, e
	}
	if in.Revision != "" && configRevision(raw) != in.Revision {
		return nil, ErrTopologyConflict
	}
	if len(raw) > 0 {
		if _, e = keaDocument(string(raw), h.family); e != nil {
			return nil, e
		}
	}
	validation, e := h.validate(ctx, in.Config)
	if e != nil {
		return nil, e
	}
	return &KeaPlan{Family: h.family, Revision: configRevision(raw), ProposedRevision: configRevision([]byte(in.Config)), Before: string(raw), Proposed: in.Config, Validation: validation, Action: "apply"}, nil
}
func (h *keaHost) apply(ctx context.Context, in KeaRequest) (*KeaResult, error) {
	if !in.Confirm {
		return nil, fmt.Errorf("подтвердите запись конфигурации и перезапуск Kea")
	}
	if in.Lease != nil {
		lease, e := h.currentLease(ctx, in.Lease)
		if e != nil {
			return nil, e
		}
		if !lease.active(time.Now()) {
			return nil, fmt.Errorf("аренда больше не активна; обновите список")
		}
	}
	p, e := h.plan(ctx, in)
	if e != nil {
		return nil, e
	}
	if in.Revision == "" || p.Revision != in.Revision || p.ProposedRevision != in.ProposedRevision {
		return nil, ErrTopologyConflict
	}
	if p.Revision == p.ProposedRevision {
		return &KeaResult{Status: h.inspect(ctx)}, nil
	}
	raw, mode, e := h.read()
	if e != nil {
		return nil, e
	}
	if configRevision(raw) != p.Revision {
		return nil, ErrTopologyConflict
	}
	prior, stateErr := h.run(ctx, "systemctl", "is-active", h.unit)
	if prior != "active" && prior != "inactive" && prior != "failed" {
		return nil, fmt.Errorf("состояние службы не позволяет применить конфигурацию (%s): %v", prior, stateErr)
	}
	candidate, e := h.stage([]byte(in.Config), mode)
	if e != nil {
		return nil, e
	}
	defer os.Remove(candidate)
	backup, e := h.stage(raw, 0600)
	if e != nil {
		return nil, e
	}
	// Check again after staging; an external editor may have changed the file.
	current, _, e := h.read()
	if e != nil || configRevision(current) != p.Revision {
		return nil, ErrTopologyConflict
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = os.Rename(candidate, h.path); e != nil {
		return nil, fmt.Errorf("копия %s: %w", backup, e)
	}
	if prior == "active" {
		_, e = h.run(ctx, "systemctl", "restart", h.unit)
		if e == nil {
			_, e = h.run(ctx, "systemctl", "is-active", h.unit)
		}
	}
	if e != nil {
		rollback, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		current, _, readErr := h.read()
		if readErr != nil || configRevision(current) != p.ProposedRevision {
			return nil, fmt.Errorf("ошибка перезапуска; файл изменён извне, копия %s: %w", backup, e)
		}
		restore, re := h.stage(raw, mode)
		if re == nil {
			defer os.Remove(restore)
			re = os.Rename(restore, h.path)
		}
		if re == nil {
			_, re = h.run(rollback, "systemctl", "restart", h.unit)
		}
		if re == nil {
			_, re = h.run(rollback, "systemctl", "is-active", h.unit)
		}
		return nil, fmt.Errorf("ошибка применения; откат: %v; копия %s: %w", re, backup, e)
	}
	return &KeaResult{Backup: backup, Status: h.inspect(ctx)}, nil
}
func (h *keaHost) service(ctx context.Context, in KeaRequest) (*KeaResult, error) {
	if !in.Confirm {
		return nil, fmt.Errorf("подтвердите изменение службы")
	}
	switch in.Action {
	case "start", "restart", "enable":
		raw, _, e := h.read()
		if e != nil {
			return nil, e
		}
		if in.Revision == "" || configRevision(raw) != in.Revision {
			return nil, ErrTopologyConflict
		}
		if _, e = h.validate(ctx, string(raw)); e != nil {
			return nil, e
		}
	case "stop", "disable":
	default:
		return nil, fmt.Errorf("неизвестное действие службы")
	}
	var args []string
	if in.Action == "enable" {
		args = []string{"enable", "--now", h.unit}
	} else {
		args = []string{in.Action, h.unit}
	}
	out, e := h.run(ctx, "systemctl", args...)
	if e != nil {
		return nil, fmt.Errorf("%s: %w", out, e)
	}
	return &KeaResult{Detail: out, Status: h.inspect(ctx)}, nil
}
func (h *keaHost) installPlan(ctx context.Context) (*KeaPlan, error) {
	// ALT has both split packages and older monolithic Kea builds. Never substitute ISC DHCP.
	packages := []string{"kea-dhcp" + h.family}
	if _, e := h.run(ctx, "apt-cache", "show", packages[0]); e != nil {
		packages = []string{"kea"}
		if _, e = h.run(ctx, "apt-cache", "show", "kea"); e != nil {
			return nil, fmt.Errorf("Kea отсутствует в подключённых репозиториях; проверьте ветку АЛЬТ и apt-get update")
		}
	}
	if packages[0] != "kea" {
		packages = append(packages, "kea-dhcp-ddns")
	}
	packages = append(packages, "kea-hooks")
	args := append([]string{"-s", "install"}, packages...)
	out, e := h.run(ctx, "apt-get", args...)
	if e != nil {
		return nil, fmt.Errorf("установка недоступна: %s: %w", out, e)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Remv ") {
			return nil, fmt.Errorf("план установки удаляет пакеты; устраните конфликт зависимостей вручную")
		}
	}
	selected := strings.Join(packages, " ")
	return &KeaPlan{Family: h.family, Action: "install", Revision: configRevision([]byte(out)), ProposedRevision: configRevision([]byte(selected)), Proposed: selected, Validation: out}, nil
}
func (h *keaHost) install(ctx context.Context, in KeaRequest) (*KeaResult, error) {
	if !in.Confirm {
		return nil, fmt.Errorf("подтвердите установку пакета")
	}
	p, e := h.installPlan(ctx)
	if e != nil {
		return nil, e
	}
	if in.Revision != p.Revision || in.ProposedRevision != p.ProposedRevision {
		return nil, ErrTopologyConflict
	}
	// A transient unit runs outside the helper's read-only filesystem namespace.
	args := []string{"--quiet", "--wait", "--pipe", "--collect", "--property=Type=exec", "--property=RuntimeMaxSec=150", "--property=TimeoutStopSec=5", "--property=Environment=DEBIAN_FRONTEND=noninteractive", "/usr/bin/apt-get", "-y", "install"}
	args = append(args, strings.Fields(p.Proposed)...)
	out, e := h.run(ctx, "systemd-run", args...)
	if e != nil {
		return nil, fmt.Errorf("установка завершилась ошибкой: %s: %w; проверьте состояние RPM перед повтором", out, e)
	}
	return &KeaResult{Detail: out, Status: h.inspect(ctx)}, nil
}
func helperKea(ctx context.Context, cfg *config.Config, method string, in HostOperation) (any, error) {
	var req KeaRequest
	if e := decodeHost(in.Input, &req); e != nil {
		return nil, e
	}
	h, e := newKeaHost(cfg, req.Family)
	if e != nil {
		return nil, e
	}
	switch method {
	case "kea.gss.install.plan", "kea.gss.install.start", "kea.gss.install.status", "kea.gss.ad.plan", "kea.gss.ad.apply":
		return helperKeaGSS(ctx, h, method, req)
	case "kea.ddns.inspect":
		return h.ddnsInspect(ctx), nil
	case "kea.ddns.plan":
		plan, _, err := h.ddnsPlan(ctx, req)
		return plan, err
	case "kea.ddns.apply":
		return h.ddnsApply(ctx, req)
	case "kea.ddns.service":
		return h.ddnsService(ctx, req)
	case "kea.leases":
		return h.leases(ctx, req)
	case "kea.lease.delete":
		return h.deleteLease(ctx, req)
	case "kea.lease.reserve.plan":
		return h.reserveLeasePlan(ctx, req)
	case "kea.inspect":
		return h.inspect(ctx), nil
	case "kea.plan":
		return h.plan(ctx, req)
	case "kea.apply":
		return h.apply(ctx, req)
	case "kea.service":
		return h.service(ctx, req)
	case "kea.install.plan":
		return h.installPlan(ctx)
	case "kea.install":
		return h.install(ctx, req)
	}
	return nil, errors.New("неизвестная операция Kea")
}
