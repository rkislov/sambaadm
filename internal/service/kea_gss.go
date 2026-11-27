package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	"sambaadm/internal/agent"
)

//go:embed kea_gss_worker.py
var keaGSSWorker string

type KeaGSSSettings struct {
	Members    []string `json:"members,omitempty"`
	Controller string   `json:"controller"`
	DNSHost    string   `json:"dnsHost,omitempty"`
	Rotate     bool     `json:"rotate,omitempty"`
}
type KeaGSSJob struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	Phase   string `json:"phase"`
	Detail  string `json:"detail,omitempty"`
	Updated string `json:"updated,omitempty"`
}

var keaGSSJobID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (h *keaHost) checkDNSAddress(value string) error {
	ip, e := netip.ParseAddr(value)
	if e != nil || ip.IsUnspecified() || ip.IsMulticast() {
		return fmt.Errorf("укажите IP-адрес DNS-сервера")
	}
	return nil
}

func (h *keaHost) gssWorkerCall(ctx context.Context, action string, request KeaRequest, transient bool) (json.RawMessage, error) {
	input := map[string]any{"action": action}
	var credentials agent.Credentials
	if action == "ad-plan" || action == "ad-apply" {
		if request.GSS == nil || request.DDNS == nil {
			return nil, fmt.Errorf("задайте параметры Samba AD и DDNS")
		}
		if _, e := keaZone(request.DDNS.ForwardZone); e != nil {
			return nil, e
		}
		if len(request.DDNS.ReverseZones) == 0 || len(request.DDNS.ReverseZones) > 512 {
			return nil, fmt.Errorf("задайте обратные DNS-зоны")
		}
		for _, name := range request.DDNS.ReverseZones {
			if _, e := keaZone(name); e != nil {
				return nil, e
			}
		}
		if request.DDNS.DNSPort < 1 || request.DDNS.DNSPort > 65535 {
			return nil, fmt.Errorf("неверный порт DNS")
		}
		if e := h.checkDNSAddress(request.DDNS.DNSAddress); e != nil {
			return nil, e
		}
		if h.cfg.Helper.Node == "" || h.cfg.LDAP.BaseDN == "" {
			return nil, fmt.Errorf("в helper не заданы node и ldap.base_dn")
		}
		var present bool
		var e error
		credentials, present, e = agent.OperationCredentials(ctx)
		if e != nil {
			return nil, e
		}
		if present {
			input["user"] = credentials.Username
			input["secret"] = credentials.Password
		}
		d2 := newKeaDDNSHost(h.cfg)
		keytab := h.cfg.Helper.KeaDDNSKeytab
		if keytab == "" {
			keytab = filepath.Join(filepath.Dir(d2.path), "ddns.keytab")
		}
		input["node"] = h.cfg.Helper.Node
		input["baseDN"] = h.cfg.LDAP.BaseDN
		input["ca"] = h.cfg.LDAP.CACert
		input["gss"] = request.GSS
		input["enrollmentSecret"] = request.GSSSecret
		input["enroll"] = request.GSSJoin
		input["ddns"] = request.DDNS
		input["keytab"] = keytab
		input["configDir"] = filepath.Dir(d2.path)
		input["stateDir"] = h.cfg.Helper.StateDir
		input["revision"] = request.Revision
	}
	raw, e := json.Marshal(input)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	ctx, cancel := context.WithTimeout(ctx, 150*time.Second)
	defer cancel()
	args := []string{"-c", keaGSSWorker}
	program := "/usr/bin/python3"
	if transient {
		id := make([]byte, 8)
		rand.Read(id)
		program = "/usr/bin/systemd-run"
		args = append([]string{"--quiet", "--wait", "--pipe", "--collect", "--unit=sambaadm-kea-gss-ad-" + hex.EncodeToString(id), "--property=RuntimeMaxSec=145", "--property=TimeoutStopSec=5", "--property=LimitCORE=0", "--property=NoNewPrivileges=yes", "/usr/bin/python3"}, args...)
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
		return nil, fmt.Errorf("GSS worker не вернул корректный результат; проверьте состояние перед повтором")
	}
	if runErr != nil || !reply.OK {
		if reply.Error == "" {
			reply.Error = "операция GSS не завершена"
		}
		return nil, agent.RedactCredentialError(fmt.Errorf("%s", reply.Error), credentials)
	}
	return reply.Result, nil
}
func (h *keaHost) gssJobBase() (string, error) {
	state := h.cfg.Helper.StateDir
	if state == "" {
		return "", fmt.Errorf("helper.state_dir не задан")
	}
	base := filepath.Join(state, "kea-gss", "jobs")
	if !filepath.IsAbs(base) {
		return "", fmt.Errorf("helper.state_dir должен быть абсолютным")
	}
	if e := os.MkdirAll(base, 0700); e != nil {
		return "", e
	}
	if st, e := os.Lstat(base); e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("некорректный каталог GSS-заданий")
	}
	return base, nil
}
func (h *keaHost) gssInstallStart(ctx context.Context, request KeaRequest) (*KeaGSSJob, error) {
	if !request.Confirm {
		return nil, fmt.Errorf("подтвердите установку GSS-TSIG")
	}
	plan, e := h.gssWorkerCall(ctx, "install-plan", KeaRequest{}, false)
	if e != nil {
		return nil, e
	}
	var expected struct {
		Revision string `json:"revision"`
	}
	if json.Unmarshal(plan, &expected) != nil || expected.Revision == "" {
		return nil, fmt.Errorf("неверный план установки")
	}
	if request.Revision != expected.Revision {
		return nil, ErrTopologyConflict
	}
	base, e := h.gssJobBase()
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	id := hex.EncodeToString(nonce)
	dir := filepath.Join(base, id)
	if e = os.Mkdir(dir, 0700); e != nil {
		return nil, e
	}
	if e = os.WriteFile(filepath.Join(dir, "worker.py"), []byte(keaGSSWorker), 0600); e != nil {
		return nil, e
	}
	data, _ := json.Marshal(map[string]string{"revision": expected.Revision})
	if e = os.WriteFile(filepath.Join(dir, "input.json"), data, 0600); e != nil {
		return nil, e
	}
	job := &KeaGSSJob{ID: id, State: "queued", Phase: "Ожидание установки GSS-TSIG"}
	data, _ = json.Marshal(job)
	if e = os.WriteFile(filepath.Join(dir, "status.json"), data, 0600); e != nil {
		return nil, e
	}
	output, e := h.run(ctx, "systemd-run", "--quiet", "--collect", "--unit=sambaadm-kea-gss-install-"+id, "--property=RuntimeMaxSec=1800", "--property=TimeoutStopSec=10", "--property=LimitCORE=0", "--property=NoNewPrivileges=yes", "/usr/bin/python3", filepath.Join(dir, "worker.py"), "install-job", dir)
	if e != nil {
		return nil, fmt.Errorf("не удалось запустить установку: %s: %w", output, e)
	}
	return job, nil
}
func (h *keaHost) gssJobStatus(ctx context.Context, id string) (*KeaGSSJob, error) {
	if !keaGSSJobID.MatchString(id) {
		return nil, fmt.Errorf("неверный ID GSS-задания")
	}
	base, e := h.gssJobBase()
	if e != nil {
		return nil, e
	}
	data, e := os.ReadFile(filepath.Join(base, id, "status.json"))
	if e != nil {
		return nil, e
	}
	var job KeaGSSJob
	if json.Unmarshal(data, &job) != nil {
		return nil, fmt.Errorf("неверный статус задания")
	}
	if job.State == "running" || job.State == "queued" {
		state, e := h.run(ctx, "systemctl", "is-active", "sambaadm-kea-gss-install-"+id+".service")
		if state == "failed" || state == "inactive" && e != nil {
			if fresh, err := os.ReadFile(filepath.Join(base, id, "status.json")); err == nil {
				var finished KeaGSSJob
				if json.Unmarshal(fresh, &finished) == nil && (finished.State == "complete" || finished.State == "failed") {
					return &finished, nil
				}
			}
			job.State = "failed"
			job.Detail += " Установка остановлена; проверьте журнал systemd и состояние пакетов перед повтором."
		}
	}
	return &job, nil
}
func helperKeaGSS(ctx context.Context, h *keaHost, method string, request KeaRequest) (any, error) {
	switch method {
	case "kea.gss.install.plan":
		return h.gssWorkerCall(ctx, "install-plan", request, false)
	case "kea.gss.install.start":
		return h.gssInstallStart(ctx, request)
	case "kea.gss.install.status":
		return h.gssJobStatus(ctx, request.JobID)
	case "kea.gss.ad.plan":
		return h.gssWorkerCall(ctx, "ad-plan", request, false)
	case "kea.gss.ad.apply":
		if !request.Confirm {
			return nil, fmt.Errorf("подтвердите создание служебной учётной записи, ACL и keytab")
		}
		if h.hooks()["libddns_gss_tsig.so"] == "" {
			return nil, fmt.Errorf("сначала установите GSS-TSIG")
		}
		return h.gssWorkerCall(ctx, "ad-apply", request, true)
	}
	return nil, fmt.Errorf("неизвестная операция GSS")
}
func (h *keaHost) gssProfile() map[string]any {
	path := filepath.Join(filepath.Dir(newKeaDDNSHost(h.cfg).path), "sambaadm-gss-profile.json")
	raw, e := os.ReadFile(path)
	if e != nil || len(raw) > 65536 {
		return nil
	}
	var profile map[string]any
	if json.Unmarshal(raw, &profile) != nil {
		return nil
	}
	delete(profile, "keytabSHA256")
	return profile
}

func (h *keaHost) gssKeytabMatches(path string) bool {
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(newKeaDDNSHost(h.cfg).path), "sambaadm-gss-profile.json"))
	if err != nil {
		return false
	}
	var profile struct {
		Fingerprint string `json:"keytabSHA256"`
	}
	if json.Unmarshal(raw, &profile) != nil || profile.Fingerprint == "" {
		return false
	}
	key, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	defer clear(key)
	hash := sha256.Sum256(key)
	return profile.Fingerprint == hex.EncodeToString(hash[:])
}
