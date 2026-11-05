package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var hostLabel = regexp.MustCompile("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

func discoveryName(s string) (string, error) {
	s = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if len(s) > 253 || !strings.Contains(s, ".") {
		return "", fmt.Errorf("требуется полное DNS-имя: %q", s)
	}
	for _, label := range strings.Split(s, ".") {
		if !hostLabel.MatchString(label) {
			return "", fmt.Errorf("неверное DNS-имя: %q", s)
		}
	}
	return s, nil
}

func resolverDomains(data string) []string {
	var domains []string
	for _, line := range strings.Split(data, "\n") {
		line, _, _ = strings.Cut(line, "#")
		line, _, _ = strings.Cut(line, ";")
		fields := strings.Fields(line)
		if len(fields) > 1 && (fields[0] == "search" || fields[0] == "domain") {
			domains = fields[1:]
		}
	}
	return domains
}

func discoverAD(ctx context.Context, domain, dc string) (string, string, error) {
	if domain == "" {
		probe, cancel := context.WithTimeout(ctx, 3*time.Second)
		raw, err := exec.CommandContext(probe, "testparm", "-s", "--parameter-name=realm").Output()
		cancel()
		if err == nil {
			domain = strings.TrimSpace(string(raw))
		}
	}
	candidates := []string{domain}
	if domain == "" {
		raw, _ := os.ReadFile("/etc/resolv.conf")
		candidates = resolverDomains(string(raw))
	}
	return resolveCandidates(ctx, candidates, domain, dc, net.DefaultResolver.LookupSRV)
}

func resolveCandidates(ctx context.Context, candidates []string, domain, dc string, lookup func(context.Context, string, string, string) (string, []*net.SRV, error)) (string, string, error) {
	matches := map[string]string{}
	for _, candidate := range candidates {
		name, err := discoveryName(candidate)
		if err != nil {
			continue
		}
		if domain != "" && dc != "" {
			target, err := discoveryName(dc)
			return name, target, err
		}
		_, records, err := lookup(ctx, "ldap", "tcp", "dc._msdcs."+name)
		if err != nil {
			continue
		}
		for _, rr := range records {
			target, err := discoveryName(rr.Target)
			if err == nil {
				matches[name] = target
				break
			}
		}
	}
	if len(matches) == 1 {
		for name, target := range matches {
			if dc != "" {
				override, err := discoveryName(dc)
				return name, override, err
			}
			return name, target, nil
		}
	}
	return "", "", fmt.Errorf("не удалось однозначно определить домен и DC по Samba/DNS; укажите --realm и --dc")

}

func init() {
	var dc, group, ca string
	cmd := &cobra.Command{Use: "discover", Short: "Определить конфигурацию сервера по Samba и DNS", Args: cobra.NoArgs,
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()
			domain, target, err := discoverAD(ctx, realm, dc)
			if err != nil {
				return err
			}
			base := "DC=" + strings.Join(strings.Split(domain, "."), ",DC=")
			bind := user
			if bind == "" {
				bind = "svc-sambaadm@" + domain
			}
			admins := group
			if admins == "" {
				admins = "CN=Domain Admins,CN=Users," + base
			}
			if ca != "" && !filepath.IsAbs(ca) {
				return fmt.Errorf("для CA требуется абсолютный путь")
			}
			cfg := map[string]any{"server": map[string]string{"listen": "127.0.0.1:8080", "enrollment_dir": "/var/lib/sambaadm/enrollment"},
				"ldap":  map[string]any{"uri": "ldaps://" + target + ":636", "base_dn": base, "ca_cert": ca, "bind": map[string]string{"type": "simple", "user": bind, "password_env": "SAMBAADM_PASSWORD"}},
				"auth":  map[string]any{"roles": map[string][]string{"admins": {admins}}},
				"audit": map[string]string{"file": "/var/log/sambaadm/audit.log"}, "logging": map[string]string{"file": "/var/log/sambaadm/events.log"}}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(cfg)
		}}
	cmd.Flags().StringVar(&dc, "dc", "", "FQDN контроллера LDAPS")
	cmd.Flags().StringVar(&group, "admin-group", "", "DN группы администраторов")
	cmd.Flags().StringVar(&ca, "ca", "", "абсолютный путь к CA для LDAPS")
	rootCmd.AddCommand(cmd)
}
