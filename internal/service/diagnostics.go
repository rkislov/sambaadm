package service

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"sambaadm/internal/adremote"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/policy"
	"sambaadm/internal/smbconf"
)

// DiagnosticCheck reports only observed capabilities; no write probes are made.
type DiagnosticCheck struct {
	ID         string `json:"id"`
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	Hint       string `json:"hint,omitempty"`
	DurationMS int64  `json:"durationMs"`
}
type DiagnosticReport struct {
	ServiceUser string            `json:"serviceUser"`
	GPO         string            `json:"gpo,omitempty"`
	Started     time.Time         `json:"started"`
	Finished    time.Time         `json:"finished"`
	Platform    string            `json:"platform"`
	Checks      []DiagnosticCheck `json:"checks"`
}
type DiagnosticService struct {
	cfg  *config.Config
	gate chan struct{}
}

func NewDiagnosticService(cfg *config.Config) *DiagnosticService {
	return &DiagnosticService{cfg: cfg, gate: make(chan struct{}, 1)}
}

// Run uses an isolated connection so checks never change the application's LDAP identity.
func (s *DiagnosticService) Run(ctx context.Context) (*DiagnosticReport, error) {
	return s.RunFor(ctx, "")
}

func (s *DiagnosticService) RunFor(ctx context.Context, gpo string) (*DiagnosticReport, error) {
	if gpo != "" && !looksLikeGUID(gpo) {
		return nil, fmt.Errorf("%w: select a GPO GUID", policy.ErrInvalidValue)
	}
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	default:
		return nil, fmt.Errorf("diagnostics already running")
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	cfg := s.cfg
	report := &DiagnosticReport{Started: time.Now().UTC(), Platform: runtime.GOOS + "/" + runtime.GOARCH, ServiceUser: s.clean(cfg.LDAP.Bind.User), GPO: gpo}
	type probe struct {
		id  string
		run func(context.Context) (string, string, string)
	}
	host := hostnameFromURI(cfg.LDAP.URI)
	domain := dnsFromBaseDN(cfg.LDAP.BaseDN)
	probes := []probe{
		{"drs", s.checkDRSPermissions},
		{"ldap_permissions", func(ctx context.Context) (string, string, string) { return s.checkLDAPPolicyPermissions(ctx, gpo) }},
		{"sysvol_permissions", func(ctx context.Context) (string, string, string) { return s.checkSYSVOLPolicyPermissions(ctx, gpo) }},
		{"ldap", func(ctx context.Context) (string, string, string) {
			if cfg.LDAP.BaseDN == "" || cfg.LDAP.Bind.User == "" || cfg.BindPassword() == "" {
				return "error", "LDAP service configuration is incomplete", "Configure ldap.base_dn, ldap.bind.user and the password environment variable."
			}
			client := ldapproto.NewServiceClient(cfg.LDAP, cfg.BindPassword)
			defer client.Close()
			if err := client.Connect(ctx); err != nil {
				return "error", s.clean(err.Error()), "Check controller resolution, LDAP port/socket, CA trust, hostname and service credentials."
			}
			_, err := client.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: cfg.LDAP.BaseDN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"objectClass"}})
			if err != nil {
				return "error", s.clean(err.Error()), "Check Base DN and service-account read permissions."
			}
			if strings.HasPrefix(strings.ToLower(cfg.LDAP.URI), "ldap://") {
				return "warning", "LDAP bind and Base DN read succeeded; connection is unencrypted", "Configure LDAPS with a trusted CA or a local LDAPI socket."
			}
			return "ok", "Service bind and Base DN read succeeded over " + transportName(cfg.LDAP.URI), "This confirms read access only; administrative write permissions were not tested."
		}},
		{"controller_dns", func(ctx context.Context) (string, string, string) {
			if host == "" {
				return "skipped", "LDAPI uses a local socket; no remote LDAP hostname is configured", ""
			}
			addresses, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return "error", s.clean(err.Error()), "Configure the domain DNS resolver on the sambaadm host."
			}
			return "ok", host + ": " + strings.Join(addresses, ", "), ""
		}},
		{"domain_srv", func(ctx context.Context) (string, string, string) {
			if domain == "" {
				return "skipped", "No DNS domain could be derived from Base DN", "Configure ldap.base_dn."
			}
			_, records, err := net.DefaultResolver.LookupSRV(ctx, "ldap", "tcp", "dc._msdcs."+domain)
			if err != nil || len(records) == 0 {
				return "error", "Domain-controller SRV records are unavailable", "Check _ldap._tcp.dc._msdcs." + domain + " on the domain DNS resolver."
			}
			targets := []string{}
			for _, r := range records {
				targets = append(targets, fmt.Sprintf("%s:%d", r.Target, r.Port))
			}
			return "ok", strings.Join(targets, ", "), "Discovery confirms DNS registration, not availability of each controller."
		}},
		{"sysvol", func(ctx context.Context) (string, string, string) {
			if domain == "" || cfg.LDAP.Bind.User == "" || cfg.BindPassword() == "" {
				return "skipped", "SYSVOL domain or service credentials are not configured", "Configure Base DN and service credentials before checking SMB."
			}
			target := host
			if target == "" {
				target = "localhost"
			}
			remote := &adremote.Client{Host: target, User: cfg.LDAP.Bind.User, Password: cfg.BindPassword}
			err := remote.SYSVOL(ctx, cfg.GPO.SMBPort, func(share *smb2.Share) error { _, err := share.ReadDir(domain + "/Policies"); return err })
			if err != nil {
				return "error", s.clean(err.Error()), "Check SMB port, service credentials and read access to SYSVOL/<domain>/Policies."
			}
			return "ok", "SYSVOL/" + domain + "/Policies is readable on " + target, "Write access, replication and policy application were not tested."
		}},
		{"smb_conf", func(ctx context.Context) (string, string, string) {
			if cfg.Samba.SMBConf == "" {
				return "skipped", "Local smb.conf is not configured", ""
			}
			if _, err := smbconf.ParseFile(cfg.Samba.SMBConf); err != nil {
				return "warning", s.clean(err.Error()), "Local file-server management requires readable samba.smb_conf on this host."
			}
			path, err := exec.LookPath("testparm")
			if err != nil {
				return "warning", "smb.conf is readable; testparm is unavailable", "Install Samba tools on the local file-server host for semantic validation."
			}
			if err := exec.CommandContext(ctx, path, "-s", cfg.Samba.SMBConf).Run(); err != nil {
				return "error", "testparm rejected the local configuration or could not run", "Run testparm -s with the configured smb.conf and inspect the local Samba configuration."
			}
			return "ok", "Local smb.conf is readable and testparm accepted it", "This does not confirm write/reload privileges."
		}},
		{"shares_root", func(ctx context.Context) (string, string, string) {
			if cfg.Samba.SharesRoot == "" {
				return "skipped", "Local share root is not configured", ""
			}
			f, err := os.Open(cfg.Samba.SharesRoot)
			if err != nil {
				return "warning", s.clean(err.Error()), "Create samba.shares_root and grant the service account the required local access."
			}
			defer f.Close()
			info, err := f.Stat()
			if err != nil || !info.IsDir() {
				return "error", "Share root is not a readable directory", "Check samba.shares_root."
			}
			return "ok", fmt.Sprintf("%s · mode %04o", cfg.Samba.SharesRoot, info.Mode().Perm()), "Directory existence is confirmed. Creation, ownership changes and ACL write permissions require a separate acceptance test."
		}},
		{"local_tools", func(ctx context.Context) (string, string, string) {
			if runtime.GOOS != "linux" {
				return "skipped", "POSIX ACL/CUPS dependencies apply to the Linux file-server host", ""
			}
			missing := []string{}
			for _, name := range []string{"testparm", "smbcontrol", "getfacl", "setfacl", "getfattr", "setfattr", "lpstat"} {
				if _, err := exec.LookPath(name); err != nil {
					missing = append(missing, name)
				}
			}
			if len(missing) > 0 {
				return "warning", "Missing optional local tools: " + strings.Join(missing, ", "), "Install tools needed for local shares, ACL/xattr or printers. Remote AD operations use native protocols."
			}
			return "ok", "Local Samba, POSIX ACL, xattr and CUPS tools are present", "Presence does not confirm execution privileges."
		}},
		{"local_write_access", func(ctx context.Context) (string, string, string) {
			if runtime.GOOS != "linux" {
				return "skipped", "Effective local write-access checks are available on Linux", ""
			}
			if cfg.Samba.SMBConf == "" || cfg.Samba.SharesRoot == "" {
				return "skipped", "Local Samba paths are not configured", ""
			}
			denied := []string{}
			for _, path := range []string{cfg.Samba.SMBConf, filepath.Dir(cfg.Samba.SMBConf), cfg.Samba.SharesRoot} {
				info, err := os.Stat(path)
				if err != nil {
					denied = append(denied, path)
					continue
				}
				allowed, _ := diagnosticWriteAccess(path, info.IsDir())
				if !allowed {
					denied = append(denied, path)
				}
			}
			if len(denied) > 0 {
				return "warning", "No effective write access or path missing: " + strings.Join(denied, ", "), "Review service identity, directory ACLs and systemd filesystem restrictions for local file-server management."
			}
			return "ok", "Effective write access to smb.conf, its parent and share root is allowed", "No files were created. Ownership/ACL changes, Samba reload and successful atomic replacement still need an acceptance test."
		}},

		{"service_identity", func(ctx context.Context) (string, string, string) {
			return "info", fmt.Sprintf("sambaadm process PID %d; config directory %s", os.Getpid(), filepath.Dir(cfg.Source)), "Checks run as this process, including inside systemd/container restrictions. They do not prove that a systemd unit is installed or enabled."
		}},
	}
	report.Checks = make([]DiagnosticCheck, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Add(1)
		go func(i int, p probe) {
			defer wg.Done()
			start := time.Now()
			checkCtx, done := context.WithTimeout(ctx, 10*time.Second)
			defer done()
			status, detail, hint := p.run(checkCtx)
			report.Checks[i] = DiagnosticCheck{p.id, status, s.clean(detail), s.clean(hint), time.Since(start).Milliseconds()}
		}(i, p)
	}
	wg.Wait()
	report.Finished = time.Now().UTC()
	return report, nil
}
func transportName(uri string) string {
	if strings.HasPrefix(strings.ToLower(uri), "ldaps://") {
		return "LDAPS (certificate validation enabled)"
	}
	return "LDAPI"
}
func (s *DiagnosticService) clean(message string) string {
	if p := s.cfg.BindPassword(); p != "" {
		message = strings.ReplaceAll(message, p, "[redacted]")
	}
	if u, err := url.Parse(s.cfg.LDAP.URI); err == nil && u.User != nil {
		message = strings.ReplaceAll(message, u.User.String(), "[redacted]")
	}
	return message
}
