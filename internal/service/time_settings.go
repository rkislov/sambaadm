package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
)

const timeConfigLimit = 64 << 10

// TimeSettings describes only the directives managed by this panel. Other
// chrony directives are preserved; advanced source configurations are read-only.
type TimeSettings struct {
	Mode           string   `json:"mode"`
	Sources        []string `json:"sources"`
	Allow          []string `json:"allow"`
	LocalReference bool     `json:"localReference"`
	Stratum        int      `json:"stratum"`
}
type TimeStatus struct {
	Node       string            `json:"node"`
	Observed   time.Time         `json:"observed"`
	Clock      string            `json:"clock"`
	Tracking   SurveyObservation `json:"tracking"`
	Sources    SurveyObservation `json:"sources"`
	Service    SurveyObservation `json:"service"`
	Settings   TimeSettings      `json:"settings"`
	ConfigPath string            `json:"configPath"`
	Editable   bool              `json:"editable"`
	Warning    string            `json:"warning,omitempty"`
}
type TimePlan struct {
	Node             string       `json:"node"`
	Path             string       `json:"path"`
	Revision         string       `json:"revision"`
	ProposedRevision string       `json:"proposedRevision"`
	Before           string       `json:"before"`
	Proposed         string       `json:"proposed"`
	Settings         TimeSettings `json:"settings"`
	Ready            bool         `json:"ready"`
}
type TimeRequest struct {
	Settings         TimeSettings `json:"settings"`
	Revision         string       `json:"revision,omitempty"`
	ProposedRevision string       `json:"proposedRevision,omitempty"`
	Confirm          bool         `json:"confirm,omitempty"`
}
type TimeApplyResult struct {
	Backup string      `json:"backup"`
	Status *TimeStatus `json:"status"`
}

// TimeService never operates on the web server's own OS as a fallback.
type TimeService struct {
	Helpers *agent.Client
	Audit   *audit.Logger
}

func (s TimeService) Call(ctx context.Context, node, method string, req TimeRequest, actor, ip string, out any) (err error) {
	if s.Helpers == nil || !s.Helpers.Has(node) {
		return fmt.Errorf("для узла не настроен sambaadm-helper")
	}
	if method != "time.inspect" && method != "time.plan" && method != "time.apply" {
		return fmt.Errorf("unsupported time operation")
	}
	defer func() {
		if method == "time.apply" && s.Audit != nil {
			if err != nil {
				s.Audit.Failure(actor, method, node, ip, err)
			} else {
				s.Audit.Success(actor, method, node, ip)
			}
		}
	}()
	return s.Helpers.Call(ctx, node, method, HostOperation{Input: hostInput(req), Actor: actor, IP: ip}, out)
}

type timeHost struct {
	cfg  *config.Config
	path string
	unit string
	run  func(context.Context, string, ...string) (string, error)
}

func newTimeHost(cfg *config.Config) (*timeHost, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("управление chrony требует Linux-helper")
	}
	unit := cfg.Helper.TimeService
	if unit == "" {
		unit = "chronyd.service"
	}
	if unit != "chronyd.service" && unit != "chrony.service" {
		return nil, fmt.Errorf("helper.time_service: разрешены chronyd.service или chrony.service")
	}
	path := cfg.Helper.TimeConfig
	if path == "" {
		for _, p := range []string{"/etc/chrony.conf", "/etc/chrony/chrony.conf"} {
			if st, e := os.Lstat(p); e == nil && st.Mode().IsRegular() {
				path = p
				break
			}
		}
	}
	return &timeHost{cfg: cfg, path: path, unit: unit, run: runTimeCommand}, nil
}
func runTimeCommand(ctx context.Context, name string, args ...string) (string, error) {
	var executable string
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p := filepath.Join(dir, name)
		if st, e := os.Stat(p); e == nil && st.Mode().IsRegular() {
			executable = p
			break
		}
	}
	if executable == "" {
		return "", fmt.Errorf("%s unavailable", name)
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	var output probeOutput
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if output.truncated && !(name == "chronyd" && len(args) > 0 && args[0] == "-p") {
		return "", fmt.Errorf("%s output exceeds limit", name)
	}
	return strings.TrimSpace(output.buf.String()), err
}
func (h *timeHost) read() ([]byte, os.FileMode, error) {
	if !filepath.IsAbs(h.path) {
		return nil, 0, fmt.Errorf("файл конфигурации chrony не обнаружен")
	}
	st, e := os.Lstat(h.path)
	if e != nil {
		return nil, 0, e
	}
	if !st.Mode().IsRegular() || st.Size() > timeConfigLimit {
		return nil, 0, fmt.Errorf("chrony config must be a regular file up to 64 KiB")
	}
	f, e := os.Open(h.path)
	if e != nil {
		return nil, 0, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, timeConfigLimit+1))
	if len(raw) > timeConfigLimit {
		return nil, 0, fmt.Errorf("chrony config exceeds limit")
	}
	return raw, st.Mode().Perm(), e
}
func chronyFields(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsRune("!;#%", rune(line[0])) {
		return nil
	}
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		line = line[:i]
	}
	return strings.Fields(line)
}
func parseTimeSettings(raw []byte) (TimeSettings, error) {
	s := TimeSettings{Mode: "sources", Stratum: 10, Sources: []string{}, Allow: []string{}}
	var advanced error
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "# sambaadm-time-mode isolated" {
			s.Mode = "isolated"
		}
		fields := chronyFields(line)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		switch key {
		case "server", "pool", "peer":
			normalized, e := validateTimeSource(strings.Join(fields, " "))
			if e != nil {
				advanced = fmt.Errorf("сложные параметры источника требуют ручного редактирования")
			} else {
				s.Sources = append(s.Sources, normalized)
			}
		case "allow":
			if len(fields) != 2 {
				advanced = fmt.Errorf("общий allow требует ручного редактирования")
			} else if p, e := netip.ParsePrefix(fields[1]); e != nil {
				advanced = fmt.Errorf("allow должен содержать явную CIDR-подсеть")
			} else {
				s.Allow = append(s.Allow, p.Masked().String())
			}
		case "local":
			s.LocalReference = true
			if len(fields) != 3 || strings.ToLower(fields[1]) != "stratum" {
				advanced = fmt.Errorf("сложная директива local требует ручного редактирования")
			} else if n, e := strconv.Atoi(fields[2]); e != nil || n < 1 || n > 15 {
				advanced = fmt.Errorf("неизвестный local stratum")
			} else {
				s.Stratum = n
			}
		case "include", "confdir", "sourcedir", "refclock", "initstepslew", "deny":
			advanced = fmt.Errorf("включённые файлы, refclock, initstepslew или deny требуют ручного редактирования")
		}
	}
	return s, advanced
}
func validateTimeSource(line string) (string, error) {
	f := strings.Fields(line)
	if len(f) < 2 || len(f) > 4 || len(line) > 300 {
		return "", fmt.Errorf("источник: server|pool|peer адрес [iburst] [prefer]")
	}
	f[0] = strings.ToLower(f[0])
	if f[0] != "server" && f[0] != "pool" && f[0] != "peer" {
		return "", fmt.Errorf("неизвестный тип источника")
	}
	host := f[1]
	if _, e := netip.ParseAddr(host); e != nil {
		if len(host) > 253 || strings.HasPrefix(host, "-") {
			return "", fmt.Errorf("неверный адрес источника")
		}
		for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", fmt.Errorf("неверное имя источника")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return "", fmt.Errorf("неверное имя источника")
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, v := range f[2:] {
		if (v != "iburst" && v != "prefer") || seen[v] {
			return "", fmt.Errorf("разрешены только iburst и prefer")
		}
		seen[v] = true
	}
	return strings.Join(f, " "), nil
}
func patchTimeConfig(raw []byte, s TimeSettings) ([]byte, error) {
	if _, e := parseTimeSettings(raw); e != nil {
		return nil, e
	}
	if s.Mode != "isolated" && s.Mode != "sources" {
		return nil, fmt.Errorf("выберите режим времени")
	}
	if len(s.Sources) > 16 || len(s.Allow) > 16 {
		return nil, fmt.Errorf("не более 16 источников и подсетей")
	}
	if s.LocalReference && (s.Mode != "isolated" || s.Stratum < 8 || s.Stratum > 14 || len(s.Allow) == 0) {
		return nil, fmt.Errorf("локальная опора: изолированный режим, stratum 8–14 и явные подсети клиентов")
	}
	if !s.LocalReference && len(s.Sources) == 0 {
		return nil, fmt.Errorf("укажите внутренний источник либо локальную опору")
	}
	out := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "# sambaadm-time-mode ") {
			continue
		}
		f := chronyFields(line)
		if len(f) > 0 {
			switch strings.ToLower(f[0]) {
			case "server", "pool", "peer", "local", "allow":
				continue
			}
		}
		out = append(out, line)
	}
	out = append(out, "# sambaadm-time-mode "+s.Mode)
	seen := map[string]bool{}
	for _, line := range s.Sources {
		v, e := validateTimeSource(line)
		if e != nil {
			return nil, e
		}
		if seen[v] {
			return nil, fmt.Errorf("источник указан повторно")
		}
		seen[v] = true
		out = append(out, v)
	}
	if s.LocalReference {
		out = append(out, fmt.Sprintf("local stratum %d", s.Stratum))
	}
	for _, cidr := range s.Allow {
		prefix, e := netip.ParsePrefix(cidr)
		if e != nil {
			return nil, fmt.Errorf("неверная CIDR-подсеть клиента")
		}
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("подсеть /0 не допускается")
		}
		out = append(out, "allow "+prefix.Masked().String())
	}
	result := []byte(strings.TrimSpace(strings.Join(out, "\n")) + "\n")
	if len(result) > timeConfigLimit {
		return nil, fmt.Errorf("chrony config exceeds limit")
	}
	return result, nil
}
func (h *timeHost) inspect(ctx context.Context) *TimeStatus {
	out := &TimeStatus{Node: h.cfg.Helper.Node, Observed: time.Now().UTC(), Clock: time.Now().Format(time.RFC3339), ConfigPath: h.path}
	probe := func(name string, args ...string) SurveyObservation {
		v, e := h.run(ctx, name, args...)
		o := SurveyObservation{Source: strings.Join(append([]string{name}, args...), " "), Observed: time.Now().UTC(), Status: "observed", Detail: v}
		if e != nil {
			o.Status = "unknown"
			if v == "" {
				o.Detail = e.Error()
			}
		}
		return o
	}
	out.Tracking = probe("chronyc", "-n", "tracking")
	out.Sources = probe("chronyc", "-n", "sources")
	out.Service = probe("systemctl", "is-active", h.unit)
	raw, _, err := h.read()
	if err == nil {
		out.Settings, err = parseTimeSettings(raw)
	}
	if err != nil {
		out.Warning = err.Error()
	} else if h.cfg.Helper.TimeConfig == "" {
		out.Warning = "Изменения выключены: задайте helper.time_config и helper.time_service на выбранном узле."
	} else {
		out.Editable = true
	}
	return out
}
func (h *timeHost) plan(ctx context.Context, in TimeRequest) (*TimePlan, error) {
	if h.cfg.Helper.TimeConfig == "" {
		return nil, fmt.Errorf("изменения времени не включены в конфигурации helper")
	}
	raw, _, e := h.read()
	if e != nil {
		return nil, e
	}
	proposed, e := patchTimeConfig(raw, in.Settings)
	if e != nil {
		return nil, e
	}
	name, e := h.stage(proposed, 0600)
	if e != nil {
		return nil, e
	}
	defer os.Remove(name)
	if _, e = h.run(ctx, "chronyd", "-p", "-f", name); e != nil {
		return nil, fmt.Errorf("chronyd не подтвердил синтаксис конфигурации: %w", e)
	}
	return &TimePlan{Node: h.cfg.Helper.Node, Path: h.path, Revision: configRevision(raw), ProposedRevision: configRevision(proposed), Before: string(raw), Proposed: string(proposed), Settings: in.Settings, Ready: true}, nil
}
func (h *timeHost) stage(raw []byte, mode os.FileMode) (string, error) {
	f, e := os.CreateTemp(filepath.Dir(h.path), ".sambaadm-time-*")
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
	info, e := os.Stat(h.path)
	if e != nil {
		return "", e
	}
	if e = preserveConfigOwner(f, info); e != nil {
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
func (h *timeHost) apply(ctx context.Context, in TimeRequest) (*TimeApplyResult, error) {
	if !in.Confirm {
		return nil, fmt.Errorf("подтвердите перезапуск службы времени")
	}
	plan, e := h.plan(ctx, in)
	if e != nil {
		return nil, e
	}
	if in.Revision == "" || in.Revision != plan.Revision || in.ProposedRevision != plan.ProposedRevision {
		return nil, ErrTopologyConflict
	}
	raw, mode, e := h.read()
	if e != nil {
		return nil, e
	}
	if configRevision(raw) != plan.Revision {
		return nil, ErrTopologyConflict
	}
	staged, e := h.stage([]byte(plan.Proposed), mode)
	if e != nil {
		return nil, e
	}
	defer os.Remove(staged)
	backup, e := h.stage(raw, 0600)
	if e != nil {
		return nil, e
	}
	// Retain the private backup even if applying or rolling back fails.
	if e = os.Rename(staged, h.path); e != nil {
		return nil, fmt.Errorf("backup %s: %w", backup, e)
	}
	if _, e = h.run(ctx, "systemctl", "restart", h.unit); e == nil {
		_, e = h.run(ctx, "systemctl", "is-active", h.unit)
	}
	if e != nil {
		rollback, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		current, _, readErr := h.read()
		if readErr != nil || configRevision(current) != plan.ProposedRevision {
			return nil, fmt.Errorf("служба не запущена; конфигурация изменилась, автоматический откат остановлен; backup %s", backup)
		}
		restore, restoreErr := h.stage(raw, mode)
		if restoreErr == nil {
			defer os.Remove(restore)
			restoreErr = os.Rename(restore, h.path)
		}
		if restoreErr == nil {
			_, restoreErr = h.run(rollback, "systemctl", "restart", h.unit)
		}
		if restoreErr == nil {
			_, restoreErr = h.run(rollback, "systemctl", "is-active", h.unit)
		}
		if restoreErr != nil {
			return nil, fmt.Errorf("сбой применения и отката; backup %s: %w", backup, errors.Join(e, restoreErr))
		}
		return nil, fmt.Errorf("служба не приняла изменения; конфигурация восстановлена, backup %s: %w", backup, e)
	}
	return &TimeApplyResult{Backup: backup, Status: h.inspect(ctx)}, nil
}
func helperTime(ctx context.Context, cfg *config.Config, method string, in HostOperation) (any, error) {
	h, e := newTimeHost(cfg)
	if e != nil {
		return nil, e
	}
	if method == "time.inspect" {
		return h.inspect(ctx), nil
	}
	var req TimeRequest
	if e = decodeHost(in.Input, &req); e != nil {
		return nil, e
	}
	switch method {
	case "time.plan":
		return h.plan(ctx, req)
	case "time.apply":
		return h.apply(ctx, req)
	}
	return nil, fmt.Errorf("unsupported time method")
}
