package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sambaadm/internal/config"
)

// Forwarding rules are local to a DNS helper, never AD-replicated settings.
type DNSForwardRule struct {
	Domain  string   `json:"domain"`
	Servers []string `json:"servers"`
	Mode    string   `json:"mode"`
}
type DNSForwardRequest struct {
	Rules            []DNSForwardRule `json:"rules"`
	Revision         string           `json:"revision"`
	ProposedRevision string           `json:"proposedRevision"`
	Confirm          bool             `json:"confirm"`
}
type DNSForwardStatus struct {
	Node     string           `json:"node"`
	Backend  string           `json:"backend"`
	Editable bool             `json:"editable"`
	Warning  string           `json:"warning,omitempty"`
	Path     string           `json:"path,omitempty"`
	Revision string           `json:"revision,omitempty"`
	Rules    []DNSForwardRule `json:"rules"`
}
type DNSForwardPlan struct {
	Revision         string           `json:"revision"`
	ProposedRevision string           `json:"proposedRevision"`
	Before           string           `json:"before"`
	Proposed         string           `json:"proposed"`
	Rules            []DNSForwardRule `json:"rules"`
}
type DNSForwardResult struct {
	Backup string            `json:"backup"`
	Status *DNSForwardStatus `json:"status"`
}

const forwardStart = "// BEGIN SAMBAADM DNS FORWARDING\n"
const forwardEnd = "// END SAMBAADM DNS FORWARDING\n"

func dnsHostName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if len(name) == 0 || len(name) > 253 {
		return "", fmt.Errorf("укажите полное DNS-имя")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("недопустимое DNS-имя")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("DNS-имя должно содержать латинские буквы, цифры и дефис")
			}
		}
	}
	return name, nil
}
func normalizeForwardRules(rules []DNSForwardRule) ([]DNSForwardRule, error) {
	if len(rules) > 64 {
		return nil, fmt.Errorf("не более 64 правил пересылки")
	}
	out := make([]DNSForwardRule, 0, len(rules))
	seen := map[string]bool{}
	for _, r := range rules {
		name, e := dnsHostName(r.Domain)
		if e != nil {
			return nil, e
		}
		if !strings.Contains(name, ".") {
			return nil, fmt.Errorf("пересылка корневой зоны и одноуровневых имён запрещена")
		}
		if seen[name] {
			return nil, fmt.Errorf("домен %s указан повторно", name)
		}
		seen[name] = true
		if r.Mode != "only" && r.Mode != "first" {
			return nil, fmt.Errorf("режим пересылки: only или first")
		}
		if len(r.Servers) == 0 || len(r.Servers) > 8 {
			return nil, fmt.Errorf("укажите от 1 до 8 IP-адресов DNS-серверов")
		}
		servers := []string{}
		ips := map[string]bool{}
		for _, v := range r.Servers {
			ip, e := netip.ParseAddr(strings.TrimSpace(v))
			if e != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.Zone() != "" {
				return nil, fmt.Errorf("недопустимый IP-адрес DNS-сервера: %s", v)
			}
			v = ip.Unmap().String()
			if ips[v] {
				return nil, fmt.Errorf("IP-адрес указан повторно")
			}
			ips[v] = true
			servers = append(servers, v)
		}
		out = append(out, DNSForwardRule{Domain: name, Servers: servers, Mode: r.Mode})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out, nil
}
func renderForwardBlock(rules []DNSForwardRule) string {
	data, _ := json.Marshal(rules)
	var b strings.Builder
	b.WriteString(forwardStart)
	b.WriteString("// data: " + base64.StdEncoding.EncodeToString(data) + "\n")
	for _, r := range rules {
		fmt.Fprintf(&b, "zone %q IN {\n    type forward;\n    forward %s;\n    forwarders { %s; };\n};\n", r.Domain, r.Mode, strings.Join(r.Servers, "; "))
	}
	b.WriteString(forwardEnd)
	return b.String()
}
func splitForwardConfig(raw []byte) (string, string, []DNSForwardRule, error) {
	s := string(raw)
	a := strings.Index(s, forwardStart)
	if a < 0 {
		if strings.Contains(s, "SAMBAADM DNS FORWARDING") {
			return "", "", nil, fmt.Errorf("повреждены границы управляемого блока DNS")
		}
		return s, "", []DNSForwardRule{}, nil
	}
	tail := s[a+len(forwardStart):]
	end := strings.Index(tail, forwardEnd)
	if end < 0 || strings.Count(s, forwardStart) != 1 || strings.Count(s, forwardEnd) != 1 {
		return "", "", nil, fmt.Errorf("повреждён управляемый блок DNS")
	}
	block := s[a : a+len(forwardStart)+end+len(forwardEnd)]
	line, _, ok := strings.Cut(tail, "\n")
	if !ok || !strings.HasPrefix(line, "// data: ") {
		return "", "", nil, fmt.Errorf("неизвестный формат блока DNS")
	}
	data, e := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "// data: "))
	var rules []DNSForwardRule
	if e != nil || json.Unmarshal(data, &rules) != nil {
		return "", "", nil, fmt.Errorf("повреждены правила пересылки")
	}
	rules, e = normalizeForwardRules(rules)
	if e != nil || renderForwardBlock(rules) != block {
		return "", "", nil, fmt.Errorf("блок пересылки изменён вручную; проверьте конфигурацию")
	}
	return s[:a] + s[a+len(block):], block, rules, nil
}

type dnsForwardHost struct {
	cfg  *config.Config
	path string
	run  func(context.Context, string, ...string) (string, error)
}

func newDNSForwardHost(ctx context.Context, cfg *config.Config) (*dnsForwardHost, error) {
	status, e := runTimeCommand(ctx, "rndc", "status")
	if e != nil {
		return nil, fmt.Errorf("условная пересылка требует работающий BIND с rndc; для встроенного DNS Samba используйте делегирование")
	}
	name := cfg.Helper.DNSConfig
	if name == "" {
		for _, line := range strings.Split(status, "\n") {
			if strings.HasPrefix(line, "configuration file: ") {
				name = strings.TrimSpace(strings.TrimPrefix(line, "configuration file: "))
			}
		}
	}
	if !filepath.IsAbs(name) {
		return nil, fmt.Errorf("не удалось определить конфигурацию BIND; задайте helper.dns_config")
	}
	name, e = filepath.EvalSymlinks(name)
	if e != nil {
		return nil, e
	}
	return &dnsForwardHost{cfg: cfg, path: name, run: runDNSCommand}, nil
}
func (h *dnsForwardHost) read() ([]byte, os.FileMode, error) {
	st, e := os.Lstat(h.path)
	if e != nil {
		return nil, 0, e
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 || st.Mode().Perm()&0022 != 0 {
		return nil, 0, fmt.Errorf("конфигурация BIND должна быть обычным файлом до 1 МиБ без прав записи группы и остальных")
	}
	raw, e := os.ReadFile(h.path)
	return raw, st.Mode().Perm(), e
}
func (h *dnsForwardHost) revision(ctx context.Context, raw []byte) (string, error) {
	flat, e := h.run(ctx, "named-checkconf", "-p", h.path)
	if e != nil {
		return "", fmt.Errorf("named-checkconf: проверьте существующую конфигурацию BIND")
	}
	return configRevision(append(append([]byte{}, raw...), []byte(flat)...)), nil
}
func (h *dnsForwardHost) inspect(ctx context.Context) (*DNSForwardStatus, error) {
	raw, _, e := h.read()
	if e != nil {
		return nil, e
	}
	_, _, rules, e := splitForwardConfig(raw)
	if e != nil {
		return nil, e
	}
	rev, e := h.revision(ctx, raw)
	if e != nil {
		return nil, e
	}
	return &DNSForwardStatus{Node: h.cfg.Helper.Node, Backend: "bind", Editable: true, Path: h.path, Revision: rev, Rules: rules}, nil
}
func (h *dnsForwardHost) stage(raw []byte, mode os.FileMode) (string, error) {
	return (&timeHost{path: h.path}).stage(raw, mode)
}
func (h *dnsForwardHost) plan(ctx context.Context, in DNSForwardRequest) (*DNSForwardPlan, error) {
	rules, e := normalizeForwardRules(in.Rules)
	if e != nil {
		return nil, e
	}
	local, _ := net.InterfaceAddrs()
	for _, r := range rules {
		for _, v := range r.Servers {
			for _, a := range local {
				prefix, err := netip.ParsePrefix(a.String())
				if err == nil && prefix.Addr().Unmap().String() == v {
					return nil, fmt.Errorf("пересылка на собственный адрес %s создаёт петлю DNS", v)
				}
			}
		}
	}
	raw, _, e := h.read()
	if e != nil {
		return nil, e
	}
	outside, before, _, e := splitForwardConfig(raw)
	if e != nil {
		return nil, e
	}
	proposed := renderForwardBlock(rules)
	next := outside
	if before != "" {
		next = strings.Replace(string(raw), before, proposed, 1)
	} else {
		next = strings.TrimRight(outside, "\n") + "\n" + proposed
	}
	rev, e := h.revision(ctx, raw)
	if e != nil {
		return nil, e
	}
	if in.Revision != "" && in.Revision != rev {
		return nil, ErrTopologyConflict
	}
	name, e := h.stage([]byte(next), 0600)
	if e != nil {
		return nil, e
	}
	defer os.Remove(name)
	if output, e := h.run(ctx, "named-checkconf", name); e != nil {
		return nil, fmt.Errorf("BIND не принял правила (возможен конфликт с существующей зоной): %s", output)
	}
	return &DNSForwardPlan{Revision: rev, ProposedRevision: configRevision([]byte(next)), Before: before, Proposed: proposed, Rules: rules}, nil
}
func (h *dnsForwardHost) apply(ctx context.Context, in DNSForwardRequest) (*DNSForwardResult, error) {
	if !in.Confirm {
		return nil, fmt.Errorf("подтвердите применение правил пересылки")
	}
	p, e := h.plan(ctx, in)
	if e != nil {
		return nil, e
	}
	if in.Revision == "" || in.Revision != p.Revision || in.ProposedRevision != p.ProposedRevision {
		return nil, ErrTopologyConflict
	}
	raw, mode, e := h.read()
	if e != nil {
		return nil, e
	}
	rev, e := h.revision(ctx, raw)
	if e != nil {
		return nil, e
	}
	if rev != p.Revision {
		return nil, ErrTopologyConflict
	}
	_, block, _, e := splitForwardConfig(raw)
	if e != nil {
		return nil, e
	}
	next := string(raw)
	if block != "" {
		next = strings.Replace(next, block, p.Proposed, 1)
	} else {
		next = strings.TrimRight(next, "\n") + "\n" + p.Proposed
	}
	staged, e := h.stage([]byte(next), mode)
	if e != nil {
		return nil, e
	}
	defer os.Remove(staged)
	backup, e := h.stage(raw, 0600)
	if e != nil {
		return nil, e
	}
	if e = os.Rename(staged, h.path); e != nil {
		return nil, e
	}
	if _, e = h.run(ctx, "rndc", "reconfig"); e == nil {
		_, e = h.run(ctx, "rndc", "status")
	}
	if e != nil {
		current, _, re := h.read()
		if re != nil || configRevision(current) != p.ProposedRevision {
			return nil, fmt.Errorf("сбой BIND; файл изменён извне, откат остановлен; резервная копия %s", backup)
		}
		restore, re := h.stage(raw, mode)
		if re == nil {
			defer os.Remove(restore)
			re = os.Rename(restore, h.path)
		}
		recovery, cancel := context.WithTimeout(context.Background(), 20e9)
		defer cancel()
		if re == nil {
			_, re = h.run(recovery, "rndc", "reconfig")
		}
		if re != nil {
			return nil, fmt.Errorf("ошибка применения и отката; резервная копия %s: %w", backup, errors.Join(e, re))
		}
		return nil, fmt.Errorf("ошибка применения; прежняя конфигурация восстановлена, резервная копия %s: %w", backup, e)
	}
	status, e := h.inspect(ctx)
	if e != nil {
		return nil, fmt.Errorf("правила применены, повторное чтение недоступно; резервная копия %s: %w", backup, e)
	}
	return &DNSForwardResult{Backup: backup, Status: status}, nil
}
func helperDNSForward(ctx context.Context, cfg *config.Config, method string, in HostOperation) (any, error) {
	h, e := newDNSForwardHost(ctx, cfg)
	if e != nil {
		if method == "dns.forward.inspect" {
			return &DNSForwardStatus{Node: cfg.Helper.Node, Backend: "unsupported", Warning: e.Error(), Rules: []DNSForwardRule{}}, nil
		}
		return nil, e
	}
	if method == "dns.forward.inspect" {
		return h.inspect(ctx)
	}
	var req DNSForwardRequest
	if e = decodeHost(in.Input, &req); e != nil {
		return nil, e
	}
	switch method {
	case "dns.forward.plan":
		return h.plan(ctx, req)
	case "dns.forward.apply":
		return h.apply(ctx, req)
	}
	return nil, fmt.Errorf("неизвестная операция DNS")
}

// BIND's expanded configuration can exceed the small diagnostic-output limit.
// Hash it locally; never return the expanded configuration (it may contain keys).
type dnsConfigOutput struct {
	bytes.Buffer
	truncated bool
}

func (w *dnsConfigOutput) Write(p []byte) (int, error) {
	n := len(p)
	left := (1 << 20) - w.Len()
	if len(p) > left {
		p = p[:left]
		w.truncated = true
	}
	_, e := w.Buffer.Write(p)
	return n, e
}
func runDNSCommand(ctx context.Context, name string, args ...string) (string, error) {
	if name != "testparm" && (name != "named-checkconf" || len(args) == 0 || args[0] != "-p") {
		return runTimeCommand(ctx, name, args...)
	}
	executable := ""
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		p := filepath.Join(dir, name)
		if st, e := os.Stat(p); e == nil && st.Mode().IsRegular() {
			executable = p
			break
		}
	}
	if executable == "" {
		return "", fmt.Errorf("%s недоступен", name)
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = time.Second
	return dnsCommandOutput(cmd)
}

// Value-producing commands must never mix diagnostics into configuration data.
func dnsCommandOutput(cmd *exec.Cmd) (string, error) {
	var output, diagnostics dnsConfigOutput
	cmd.Stdout = &output
	cmd.Stderr = &diagnostics
	err := cmd.Run()
	if output.truncated || diagnostics.truncated {
		return "", fmt.Errorf("вывод DNS-команды превышает 1 МиБ")
	}
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(diagnostics.String()))
	}
	return strings.TrimSpace(output.String()), nil
}
