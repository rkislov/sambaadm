package web

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"sambaadm/internal/agent"
	"sambaadm/internal/auth"
	"sambaadm/internal/bootstrap"
	"sambaadm/internal/config"
	"sambaadm/internal/version"
)

type helperInstallNode struct {
	Node        string   `json:"node"`
	Fingerprint string   `json:"fingerprint"`
	Phase       string   `json:"phase"`
	Logs        []string `json:"logs"`
	Error       string   `json:"error,omitempty"`
}
type helperInstallJob struct {
	ID      string              `json:"id"`
	Actor   string              `json:"actor"`
	Created time.Time           `json:"created"`
	Updated time.Time           `json:"updated"`
	Port    int                 `json:"port"`
	Status  string              `json:"status"`
	Nodes   []helperInstallNode `json:"nodes"`
}

var installVersionPattern = regexp.MustCompile(`^v?([0-9]+\.[0-9]+\.[0-9]+)(?:-|$)`)
var installStagePattern = regexp.MustCompile(`^/var/tmp/sambaadm-install\.[A-Za-z0-9]+$`)

func helperInstallVersion() string {
	m := installVersionPattern.FindStringSubmatch(version.Version)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}
func (s *Server) installDir() (string, error) {
	dir := s.cfg.Server.EnrollmentDir
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("Укажите server.enrollment_dir для автоматической регистрации helper")
	}
	dir = filepath.Join(dir, "install-jobs")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	st, e := os.Lstat(dir)
	if e != nil {
		return "", e
	}
	if !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("Каталог установки требует прав 0700")
	}
	return dir, nil
}
func (s *Server) saveInstall(j *helperInstallJob) error {
	dir, e := s.installDir()
	if e != nil {
		return e
	}
	j.Updated = time.Now().UTC()
	data, e := json.MarshalIndent(j, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".job-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	_, e = f.Write(data)
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(dir, j.ID+".json"))
}
func (s *Server) readInstall(id string) (*helperInstallJob, error) {
	if _, e := uuid.Parse(id); e != nil {
		return nil, fmt.Errorf("Некорректный номер установки")
	}
	dir, e := s.installDir()
	if e != nil {
		return nil, e
	}
	raw, e := os.ReadFile(filepath.Join(dir, id+".json"))
	if e != nil {
		return nil, e
	}
	var j helperInstallJob
	e = json.Unmarshal(raw, &j)
	return &j, e
}
func (s *Server) helperPackage(arch string) (string, error) {
	if arch != "x86_64" && arch != "aarch64" {
		return "", fmt.Errorf("Поддерживаются x86_64 и aarch64")
	}
	v := helperInstallVersion()
	if v == "" {
		return "", fmt.Errorf("Для установки нужна релизная версия sambaadm")
	}
	name := "sambaadm-helper-" + v + "-alt1." + arch + ".rpm"
	for _, p := range []string{filepath.Join(s.cfg.Server.EnrollmentDir, "packages", name), filepath.Join("/usr/share/sambaadm/helper-packages", name)} {
		if st, e := os.Stat(p); e == nil && st.Mode().IsRegular() && st.Size() > 0 && st.Size() < 64<<20 {
			return p, nil
		}
	}
	return "", fmt.Errorf("Загрузите RPM helper версии %s для %s в мастере установки", v, arch)
}
func redactInstall(line string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			line = strings.ReplaceAll(line, secret, "[скрыто]")
		}
	}
	line = strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' {
			return -1
		}
		return r
	}, line)
	if len(line) > 2000 {
		line = line[:2000] + "…"
	}
	return line
}
func (s *Server) installLog(j *helperInstallJob, n int, phase, line string, secrets ...string) {
	s.helperInstallMu.Lock()
	defer s.helperInstallMu.Unlock()
	node := &j.Nodes[n]
	if phase != "" {
		node.Phase = phase
	}
	if line != "" {
		node.Logs = append(node.Logs, time.Now().Format("15:04:05")+" · "+redactInstall(line, secrets...))
		if len(node.Logs) > 400 {
			node.Logs = node.Logs[len(node.Logs)-400:]
		}
	}
	_ = s.saveInstall(j)
}
func (s *Server) handleHelperInstall(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if _, e := s.installDir(); e != nil {
		writeJSON(w, 409, map[string]string{"error": e.Error()})
		return
	}
	actor := sessionFrom(r).Username
	if r.Method == http.MethodGet {
		s.helperInstallMu.Lock()
		defer s.helperInstallMu.Unlock()
		dir, _ := s.installDir()
		files, _ := os.ReadDir(dir)
		jobs := []*helperInstallJob{}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			j, e := s.readInstall(strings.TrimSuffix(f.Name(), ".json"))
			if e != nil || j.Actor != actor {
				continue
			}
			if j.Status == "running" && !s.helperInstallActive {
				j.Status = "interrupted"
				_ = s.saveInstall(j)
			}
			jobs = append(jobs, j)
		}
		sort.Slice(jobs, func(i, k int) bool { return jobs[i].Created.After(jobs[k].Created) })
		if len(jobs) > 20 {
			jobs = jobs[:20]
		}
		packages := map[string]bool{}
		for _, a := range []string{"x86_64", "aarch64"} {
			_, e := s.helperPackage(a)
			packages[a] = e == nil
		}
		writeJSON(w, 200, map[string]any{"jobs": jobs, "packages": packages, "version": helperInstallVersion()})
		return
	}
	var in struct {
		Action       string   `json:"action"`
		ID           string   `json:"id"`
		Nodes        []string `json:"nodes"`
		Port         int      `json:"port"`
		User         string   `json:"user"`
		Password     string   `json:"password"`
		RootPassword string   `json:"rootPassword"`
		Confirm      bool     `json:"confirm"`
		Replace      bool     `json:"replace"`
	}
	if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); e != nil {
		writeJSON(w, 400, map[string]string{"error": "Некорректный запрос"})
		return
	}
	if in.Action == "probe" {
		if len(in.Nodes) == 0 || len(in.Nodes) > 16 {
			writeJSON(w, 400, map[string]string{"error": "Выберите от 1 до 16 контроллеров"})
			return
		}
		if in.Port == 0 {
			in.Port = 22
		}
		if in.Port < 1 || in.Port > 65535 {
			writeJSON(w, 400, map[string]string{"error": "Некорректный порт SSH"})
			return
		}
		dcs, e := s.svcs.Sites.Controllers(r.Context())
		if e != nil {
			upstreamError(w, e)
			return
		}
		allowed := map[string]bool{}
		for _, dc := range dcs {
			allowed[strings.ToLower(dc.DNS)] = true
		}
		selected := map[string]bool{}
		for _, n := range in.Nodes {
			if !allowed[n] || !enrollmentDNS(n) || selected[n] {
				writeJSON(w, 400, map[string]string{"error": "Выберите уникальные DNS-имена контроллеров из каталога"})
				return
			}
			selected[n] = true
		}
		j := &helperInstallJob{ID: uuid.NewString(), Actor: actor, Created: time.Now().UTC(), Status: "ready", Port: in.Port, Nodes: []helperInstallNode{}}
		j.Nodes = make([]helperInstallNode, len(in.Nodes))
		var probes sync.WaitGroup
		for i, n := range in.Nodes {
			probes.Add(1)
			go func(i int, n string) {
				defer probes.Done()
				ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
				defer cancel()
				key, e := bootstrap.Probe(ctx, n, in.Port)
				node := helperInstallNode{Node: n, Fingerprint: key, Phase: "ready", Logs: []string{"Ключ SSH получен без передачи пароля"}}
				if e != nil {
					node.Phase = "failed"
					node.Error = "Не удалось получить ключ SSH: " + redactInstall(e.Error())
				}
				j.Nodes[i] = node
			}(i, n)
		}
		probes.Wait()
		ready := false
		for _, node := range j.Nodes {
			if node.Phase == "ready" {
				ready = true
			}
		}
		if !ready {
			j.Status = "failed"
		}
		s.helperInstallMu.Lock()
		e = s.saveInstall(j)
		s.helperInstallMu.Unlock()
		if e != nil {
			upstreamError(w, e)
			return
		}
		writeJSON(w, 200, j)
		return
	}
	if in.Action != "start" || !in.Confirm || strings.TrimSpace(in.User) == "" || len(in.User) > 128 || strings.ContainsAny(in.User, "\x00\r\n") || len(in.Password) == 0 || len(in.Password) > 1024 || len(in.RootPassword) > 1024 || strings.ContainsAny(in.Password+in.RootPassword, "\x00\r\n") || (in.User != "root" && in.RootPassword == "") {
		writeJSON(w, 400, map[string]string{"error": "Укажите SSH-логин и пароли, подтвердите ключи и установку"})
		return
	}
	s.helperInstallMu.Lock()
	j, e := s.readInstall(in.ID)
	if e != nil || j.Actor != actor {
		s.helperInstallMu.Unlock()
		writeJSON(w, 404, map[string]string{"error": "План установки не найден"})
		return
	}
	if s.helperInstallActive || j.Status != "ready" || time.Since(j.Created) > 15*time.Minute {
		s.helperInstallMu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "План уже использован, истёк или другая установка ещё выполняется. Проверьте контроллеры заново."})
		return
	}
	j.Status = "running"
	if e = s.saveInstall(j); e != nil {
		s.helperInstallMu.Unlock()
		upstreamError(w, e)
		return
	}
	s.helperInstallActive = true
	s.helperInstallMu.Unlock()
	snapshot := *j // worker owns the live job; the response has no credentials.
	writeJSON(w, 202, snapshot)
	if s.audit != nil {
		s.audit.Success(actor, "helper.install.start", j.ID, r.RemoteAddr)
	}
	go s.runHelperInstall(j, in.User, in.Password, in.RootPassword, in.Replace, r.RemoteAddr)
}
func (s *Server) handleHelperPackage(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, auth.CanAdmin) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if _, e := s.installDir(); e != nil {
		writeJSON(w, 409, map[string]string{"error": e.Error()})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<20)
	if e := r.ParseMultipartForm(1 << 20); e != nil {
		writeJSON(w, 400, map[string]string{"error": "Размер RPM должен быть не больше 64 МиБ"})
		return
	}
	defer r.MultipartForm.RemoveAll()
	file, _, e := r.FormFile("package")
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": "Выберите RPM helper"})
		return
	}
	defer file.Close()
	dir := filepath.Join(s.cfg.Server.EnrollmentDir, "packages")
	if e = os.MkdirAll(dir, 0700); e != nil {
		upstreamError(w, e)
		return
	}
	tmp, e := os.CreateTemp(dir, ".rpm-*")
	if e != nil {
		upstreamError(w, e)
		return
	}
	defer os.Remove(tmp.Name())
	_, e = io.Copy(tmp, file)
	e = errors.Join(e, tmp.Close())
	if e != nil {
		upstreamError(w, e)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	output, e := exec.CommandContext(ctx, "rpm", "-qp", "--qf", "%{NAME} %{VERSION} %{RELEASE} %{ARCH}", tmp.Name()).Output()
	fields := strings.Fields(string(output))
	if e != nil || len(fields) != 4 || fields[0] != "sambaadm-helper" || fields[1] != helperInstallVersion() || fields[2] != "alt1" || (fields[3] != "x86_64" && fields[3] != "aarch64") {
		writeJSON(w, 400, map[string]string{"error": "Нужен RPM sambaadm-helper той же версии, что панель, для x86_64 или aarch64"})
		return
	}
	name := fmt.Sprintf("%s-%s-%s.%s.rpm", fields[0], fields[1], fields[2], fields[3])
	if e = os.Rename(tmp.Name(), filepath.Join(dir, name)); e != nil {
		upstreamError(w, e)
		return
	}
	if s.audit != nil {
		s.audit.Success(sessionFrom(r).Username, "helper.package.upload", name, r.RemoteAddr)
	}
	writeJSON(w, 200, map[string]string{"status": "ok", "name": name})
}
func (s *Server) runHelperInstall(j *helperInstallJob, user, password, rootPassword string, replace bool, ip string) {
	defer func() {
		password = ""
		rootPassword = ""
		s.helperInstallMu.Lock()
		s.helperInstallActive = false
		s.helperInstallMu.Unlock()
	}()
	success := 0
	for i := range j.Nodes {
		if j.Nodes[i].Phase == "failed" {
			continue
		}
		s.installLog(j, i, "connecting", "Подключение SSH с проверкой подтверждённого ключа")
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		e := s.installOneHelper(ctx, j, i, user, password, rootPassword, replace)
		cancel()
		if e != nil {
			safe := redactInstall(e.Error(), password, rootPassword)
			s.helperInstallMu.Lock()
			j.Nodes[i].Error = safe
			s.helperInstallMu.Unlock()
			s.installLog(j, i, "failed", safe)
			if s.audit != nil {
				s.audit.Failure(j.Actor, "helper.install.node", j.Nodes[i].Node, ip, errors.New(safe))
			}
		} else {
			success++
			s.installLog(j, i, "complete", "Helper установлен, подписанный запрос по HTTPS проверен, привязка готова")
			if s.audit != nil {
				s.audit.Success(j.Actor, "helper.install.node", j.Nodes[i].Node, ip)
			}
		}
	}
	s.helperInstallMu.Lock()
	defer s.helperInstallMu.Unlock()
	j.Status = "failed"
	if success == len(j.Nodes) {
		j.Status = "complete"
	} else if success > 0 {
		j.Status = "partial"
	}
	_ = s.saveInstall(j)
}

// registration files are staged; nodes.json is committed only after a signed
// HTTPS inventory call succeeds against the newly installed helper.
type installRegistration struct {
	config agent.Config
	files  map[string][]byte
	ca     []byte
	caPath string
}

func (s *Server) prepareInstallRegistration(node, csrPEM string) (*installRegistration, error) {
	dir := s.cfg.Server.EnrollmentDir
	c, e := config.ManagedHelpers(dir)
	if e != nil {
		return nil, e
	}
	private := filepath.Join(dir, "management.key")
	key, e := agent.LoadPrivate(private)
	if errors.Is(e, os.ErrNotExist) && len(c.Nodes) == 0 {
		if e = agent.GenerateKey(private, filepath.Join(dir, "management.pub")); e != nil {
			return nil, e
		}
		key, e = agent.LoadPrivate(private)
	}
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("Узел не вернул CSR")
	}
	csr, e := x509.ParseCertificateRequest(block.Bytes)
	if e != nil || csr.CheckSignature() != nil {
		return nil, fmt.Errorf("Некорректная подпись CSR")
	}
	ca, cert, e := helperCertificate(node, csr)
	if e != nil {
		return nil, e
	}
	caPath := filepath.Join(dir, fmt.Sprintf("%x.pem", sha256.Sum256(ca)))
	entry := agent.Node{Name: node, Transport: "https", Endpoint: "https://" + node + ":8444", CACert: caPath}
	found := false
	for i, n := range c.Nodes {
		if n.Name == node {
			c.Nodes[i] = entry
			found = true
		}
	}
	if !found {
		c.Nodes = append(c.Nodes, entry)
	}
	c.PrivateKey = private
	if c.HostNode == "" {
		c.HostNode = node
	}
	if e = c.Validate(); e != nil {
		return nil, e
	}
	domain := dnsFromBaseDN(s.cfg.LDAP.BaseDN)
	files := map[string][]byte{"management.pub": []byte(base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)) + "\n"), "tls.crt": cert}
	ldapSettings := map[string]any{"uri": "ldaps://" + node + ":636", "base_dn": s.cfg.LDAP.BaseDN, "bind": map[string]string{"user": s.cfg.LDAP.Bind.User, "password_env": "SAMBAADM_PASSWORD"}}
	if caFile := s.cfg.LDAP.LDAPCAFile(); caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		var certificates []byte
		for len(raw) > 0 {
			block, rest := pem.Decode(raw)
			if block == nil {
				break
			}
			raw = rest
			if block.Type != "CERTIFICATE" {
				continue
			}
			if _, err = x509.ParseCertificate(block.Bytes); err != nil {
				return nil, fmt.Errorf("Некорректный сертификат доверия LDAP")
			}
			certificates = append(certificates, pem.EncodeToMemory(block)...)
		}
		if len(certificates) == 0 {
			return nil, fmt.Errorf("Не найдены публичные сертификаты доверия LDAP")
		}
		files["domain-ca.pem"] = certificates
		ldapSettings["ca_cert"] = "/etc/sambaadm-helper/domain-ca.pem"
	}
	payload, e := json.MarshalIndent(map[string]any{"helper": map[string]any{"node": node, "trusted_keys": []string{"/etc/sambaadm-helper/management.pub"}, "listen": ":8444", "tls": map[string]string{"cert": "/etc/sambaadm-helper/tls.crt", "key": "/etc/sambaadm-helper/tls.key"}, "sysvol_prefix": domain + "/Policies", "backup_root": "/var/lib/sambaadm-helper/backups", "state_dir": "/var/lib/sambaadm-helper"}, "ldap": ldapSettings, "samba": map[string]string{"shares_root": "/srv/samba"}, "audit": map[string]string{"file": "/var/log/sambaadm-helper/audit.log"}}, "", "  ")
	if e != nil {
		return nil, e
	}
	files["config.yaml"] = payload
	return &installRegistration{config: c, ca: ca, caPath: caPath, files: files}, nil
}
func (s *Server) commitInstallRegistration(p *installRegistration) error {
	dir := s.cfg.Server.EnrollmentDir
	data, e := json.MarshalIndent(p.config, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".nodes-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	_, e = f.Write(data)
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(dir, "nodes.json"))
}
func installTar(files map[string][]byte) ([]byte, error) {
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for name, data := range files {
		if e := w.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); e != nil {
			return nil, e
		}
		if _, e := w.Write(data); e != nil {
			return nil, e
		}
	}
	if e := w.Close(); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}
func (s *Server) installOneHelper(ctx context.Context, j *helperInstallJob, i int, user, password, rootPassword string, replace bool) error {
	node := j.Nodes[i]
	client, e := bootstrap.Dial(ctx, node.Node, j.Port, user, password, node.Fingerprint)
	if e != nil {
		return fmt.Errorf("SSH: %w", e)
	}
	defer client.Close()
	output, e := bootstrap.Run(ctx, client, "uname -m")
	if e != nil {
		return fmt.Errorf("Не удалось определить архитектуру: %w", e)
	}
	arch := strings.TrimSpace(output)
	pkg, e := s.helperPackage(arch)
	if e != nil {
		return e
	}
	rpm, e := os.ReadFile(pkg)
	if e != nil {
		return e
	}
	sha := sha256.Sum256(rpm)
	s.installLog(j, i, "copying", "Архитектура "+arch+". Копирование RPM "+helperInstallVersion())
	temp, e := bootstrap.Run(ctx, client, "umask 077; mktemp -d /var/tmp/sambaadm-install.XXXXXXXX")
	temp = strings.TrimSpace(temp)
	if e != nil || !installStagePattern.MatchString(temp) {
		return fmt.Errorf("Не удалось создать временный каталог SSH")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = bootstrap.Run(cleanup, client, "rm -rf -- "+bootstrap.Quote(temp))
	}()
	if e = bootstrap.Copy(ctx, client, temp+"/helper.rpm", rpm); e != nil {
		return fmt.Errorf("Копирование RPM: %w", e)
	}
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	cfg, e := config.ManagedHelpers(s.cfg.Server.EnrollmentDir)
	if e != nil {
		return e
	}
	registered := false
	for _, n := range cfg.Nodes {
		if strings.EqualFold(n.Name, node.Node) {
			registered = true
		}
	}
	log := func(line string) { s.installLog(j, i, "", line, password, rootPassword) }
	// Preflight is separate from installation: never alter a configured foreign helper silently.
	preflight := "set -eu\nif [ -s /etc/sambaadm-helper/config.yaml ]; then echo SAMBAADM_EXISTING; fi\ncommand -v rpm >/dev/null\ncommand -v systemctl >/dev/null\ncommand -v openssl >/dev/null\n"
	before, e := bootstrap.Su(ctx, client, preflight, rootPassword, nil)
	if e != nil {
		return fmt.Errorf("Повышение прав su - или проверка зависимостей не выполнены: %s", redactInstall(before, password, rootPassword))
	}
	if strings.Contains(before, "SAMBAADM_EXISTING") && !registered && !replace {
		return fmt.Errorf("На узле есть конфигурация helper другой регистрации. Для её замены отметьте перепривязку и подготовьте новый план")
	}
	s.installLog(j, i, "installing", "Права root подтверждены. Проверка SHA-256 и установка RPM")
	metadata := "sambaadm-helper " + helperInstallVersion() + " alt1 " + arch
	script := "set -eu\numask 077\nstage=$(mktemp -d /var/tmp/sambaadm-install.XXXXXXXX)\ntrap 'rm -rf -- \"$stage\"' EXIT\ninstall -m 0600 " + bootstrap.Quote(temp+"/helper.rpm") + " \"$stage/helper.rpm\"\nprintf '%s  %s\\n' " + bootstrap.Quote(hex.EncodeToString(sha[:])) + " \"$stage/helper.rpm\" | sha256sum -c -\ntest \"$(rpm -qp --qf '%{NAME} %{VERSION} %{RELEASE} %{ARCH}' \"$stage/helper.rpm\")\" = " + bootstrap.Quote(metadata) + "\nrpm -Uvh --test --replacepkgs \"$stage/helper.rpm\"\nrpm -Uvh --replacepkgs \"$stage/helper.rpm\"\n/usr/bin/sambaadm-helper version\n"
	if _, e = bootstrap.Su(ctx, client, script, rootPassword, log); e != nil {
		return fmt.Errorf("Установка RPM завершилась ошибкой: %w", e)
	}
	if registered && !replace {
		s.installLog(j, i, "verifying", "Существующие ключи и конфигурация сохранены")
		if _, e = bootstrap.Su(ctx, client, "set -eu\nsystemctl daemon-reload\nsystemctl enable sambaadm-helper\nsystemctl restart sambaadm-helper\nsystemctl is-active sambaadm-helper\n", rootPassword, log); e != nil {
			return e
		}
		verify := &agent.Client{Config: cfg}
		return verifyInstalledHelper(ctx, verify, node.Node)
	}
	s.installLog(j, i, "registering", "Подготовка нового ключа TLS и CSR на контроллере")
	stage, e := bootstrap.Su(ctx, client, "set -eu\numask 077\nstage=$(mktemp -d /var/tmp/sambaadm-install.XXXXXXXX)\ntrap 'rm -rf -- \"$stage\"' EXIT\nopenssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out \"$stage/tls.key\" 2>/dev/null\nprintf 'SAMBAADM_STAGE=%s\\n' \"$stage\"\nopenssl req -new -key \"$stage/tls.key\" -subj /CN=helper -out \"$stage/helper.csr\"\ncat \"$stage/helper.csr\"\ntrap - EXIT\n", rootPassword, nil)
	if e != nil {
		return fmt.Errorf("Не удалось создать ключ TLS на узле: %w", e)
	}
	rootStage := ""
	for _, line := range strings.Split(stage, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "SAMBAADM_STAGE=") {
			rootStage = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "SAMBAADM_STAGE="))
		}
	}
	if !installStagePattern.MatchString(rootStage) {
		return fmt.Errorf("Не получен временный каталог root")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = bootstrap.Su(cleanup, client, "rm -rf -- "+bootstrap.Quote(rootStage), rootPassword, nil)
	}()
	start := strings.Index(stage, "-----BEGIN CERTIFICATE REQUEST-----")
	if start < 0 {
		return fmt.Errorf("Не получен CSR узла")
	}
	p, e := s.prepareInstallRegistration(node.Node, strings.ReplaceAll(stage[start:], "\r", ""))
	if e != nil {
		return e
	}
	bundle, e := installTar(p.files)
	if e != nil {
		return e
	}
	if e = bootstrap.Copy(ctx, client, temp+"/connection.tar", bundle); e != nil {
		return e
	}
	bundleHash := sha256.Sum256(bundle)
	caInstall := ""
	if _, ok := p.files["domain-ca.pem"]; ok {
		caInstall = "install -o root -g root -m 0600 " + bootstrap.Quote(rootStage+"/domain-ca.pem") + " /etc/sambaadm-helper/domain-ca.pem\n"
	}
	script = "set -eu\numask 077\ninstall -m 0600 " + bootstrap.Quote(temp+"/connection.tar") + " " + bootstrap.Quote(rootStage+"/connection.tar") + "\nprintf '%s  %s\\n' " + bootstrap.Quote(hex.EncodeToString(bundleHash[:])) + " " + bootstrap.Quote(rootStage+"/connection.tar") + " | sha256sum -c -\ntar -xf " + bootstrap.Quote(rootStage+"/connection.tar") + " -C " + bootstrap.Quote(rootStage) + "\ninstall -d -m 0700 /etc/sambaadm-helper\nbackup=$(mktemp -d /var/lib/sambaadm-helper/before-install.XXXXXXXX)\ncp -a /etc/sambaadm-helper/. \"$backup/\"\nprintf 'Резервная копия конфигурации: %s\\n' \"$backup\"\ninstall -o root -g root -m 0600 " + bootstrap.Quote(rootStage) + "/config.yaml " + bootstrap.Quote(rootStage) + "/management.pub " + bootstrap.Quote(rootStage) + "/tls.crt " + bootstrap.Quote(rootStage) + "/tls.key /etc/sambaadm-helper/\n" + caInstall + "systemctl daemon-reload\nsystemctl enable sambaadm-helper\nsystemctl restart sambaadm-helper\nsystemctl is-active sambaadm-helper\n"
	if _, e = bootstrap.Su(ctx, client, script, rootPassword, log); e != nil {
		return fmt.Errorf("Настройка сервиса не завершена; исходная конфигурация сохранена в before-install: %w", e)
	}
	if e = os.WriteFile(p.caPath, p.ca, 0600); e != nil {
		return e
	}
	s.installLog(j, i, "verifying", "Проверка HTTPS, сертификата и подписи запроса helper")
	verify := &agent.Client{Config: p.config}
	if e = verifyInstalledHelper(ctx, verify, node.Node); e != nil {
		return fmt.Errorf("Helper установлен, но проверка связи не пройдена. Привязка не сохранена: %w", e)
	}
	if e = s.commitInstallRegistration(p); e != nil {
		return fmt.Errorf("Проверка пройдена, но не удалось сохранить привязку: %w", e)
	}
	return nil
}

func verifyInstalledHelper(ctx context.Context, client *agent.Client, node string) error {
	var last error
	for attempt := 0; attempt < 10; attempt++ {
		var inventory struct {
			Controller string `json:"controller"`
		}
		probe, cancel := context.WithTimeout(ctx, 12*time.Second)
		last = client.Call(probe, node, "host.inventory", map[string]any{}, &inventory)
		cancel()
		if last == nil {
			if !strings.EqualFold(inventory.Controller, node) {
				return fmt.Errorf("Helper вернул другую идентичность контроллера")
			}
			return nil
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}
