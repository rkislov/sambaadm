package service

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sambaadm/internal/config"
	"sambaadm/internal/version"
)

var workstationLabel = regexp.MustCompile("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

func surveyHostname(name string) bool {
	if len(name) > 253 || !strings.Contains(name, ".") {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if !workstationLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// Read cache metadata only. Identity and credential databases never leave the host.
func cacheMetadata(path string) SurveyObservation {
	o := SurveyObservation{Source: path, Observed: time.Now().UTC(), Status: "unknown", Detail: "Метаданные файла недоступны"}
	st, err := os.Lstat(path)
	if err == nil && st.Mode().IsRegular() {
		o.Status = "observed"
		o.Detail = fmt.Sprintf("%d байт; mtime %s", st.Size(), st.ModTime().UTC().Format(time.RFC3339))
	}
	return o
}

func CollectWorkstationSurvey(ctx context.Context, cfg *config.Config, site, account string) (*NodeSurvey, error) {
	return CollectWorkstationSurveyWithOptions(ctx, cfg, site, account, WorkstationSurveyOptions{})
}
func CollectWorkstationSurveyWithOptions(ctx context.Context, cfg *config.Config, site, account string, options WorkstationSurveyOptions) (*NodeSurvey, error) {
	if err := validateSurveyDNSOptions(options); err != nil {
		return nil, err
	}
	node := strings.TrimSuffix(cfg.Helper.Node, ".")
	if !surveyHostname(node) || len(site) > 256 {
		return nil, fmt.Errorf("укажите FQDN рабочей станции в helper.node и площадку до 256 байт")
	}
	if strings.HasPrefix(account, "-") || len(account) > 256 || strings.ContainsAny(account, "\x00\r\n") {
		return nil, fmt.Errorf("недопустимое имя учётной записи")
	}
	s := &NodeSurvey{Format: SurveyFormat, Profile: "alt-workstation", Helper: version.String(), Node: node, Site: site, Started: time.Now().UTC(), Checks: surveySystemFiles()}
	probe := func(name string, args ...string) SurveyObservation {
		o := surveyProbe(ctx, name, args...)
		if o.Detail == "-- No entries --" {
			o.Status = "unknown"
		}
		s.Checks = append(s.Checks, o)
		return o
	}
	configs, warnings := collectWorkstationConfigs("/etc/sssd/sssd.conf", "/etc/krb5.conf", strings.FieldsFunc(os.Getenv("KRB5_CONFIG"), func(r rune) bool { return r == ':' }))
	s.Workstation = &WorkstationDiagnostics{Format: 1, Configs: configs, Warnings: warnings, DNS: []SurveyDNSResult{}}
	configCheck := surveyProbe(ctx, "sssctl", "config-check")
	// Validator output may quote arbitrary configuration values. Export only availability.
	configCheck.Detail = "Проверка конфигурации не подтверждена; подробности доступны локально на станции"
	if configCheck.Status == "observed" {
		configCheck.Detail = "Команда проверки завершилась успешно; полный вывод не экспортируется"
	}
	s.Checks = append(s.Checks, configCheck)
	for _, pkg := range []string{"sssd", "krb5", "krb5-libs", "gpupdate", "chrony"} {
		probe("rpm", "-q", pkg)
	}
	probe("chronyc", "-n", "tracking")
	probe("chronyc", "-n", "sources")
	for _, plugin := range []string{"/usr/lib64/krb5/plugins/libkrb5/sssd_krb5_locator_plugin.so", "/usr/lib/krb5/plugins/libkrb5/sssd_krb5_locator_plugin.so", "/usr/lib/x86_64-linux-gnu/krb5/plugins/libkrb5/sssd_krb5_locator_plugin.so"} {
		s.Checks = append(s.Checks, cacheMetadata(plugin))
	}
	probe("resolvectl", "status")
	// Snapshot connected peers before issuing any diagnostic DNS queries.
	probe("ss", "-Hntu", "state", "established", "( dport = :53 or dport = :88 or dport = :389 or dport = :636 )")
	domains := probe("sssctl", "domain-list")
	var names []string
	if domains.Status == "observed" {
		names = strings.Fields(domains.Detail)
	} else {
		caches, _ := filepath.Glob("/var/lib/sss/db/cache_*.ldb")
		for _, cache := range caches {
			names = append(names, strings.TrimSuffix(strings.TrimPrefix(filepath.Base(cache), "cache_"), ".ldb"))
		}
	}
	if len(names) == 0 {
		s.Checks = append(s.Checks, SurveyObservation{Source: "SSSD cache / KDC locator", Observed: time.Now().UTC(), Status: "unknown", Detail: "Домены SSSD не обнаружены; состояние кэша и выбор KDC неизвестны"})
	}
	for i, domain := range names {
		if i >= 8 {
			break
		}
		if !surveyHostname(domain) {
			continue
		}
		probe("sssctl", "domain-status", domain)
		s.Checks = append(s.Checks, cacheMetadata(filepath.Join("/var/lib/sss/db", "cache_"+domain+".ldb")))
		// Limit to validated locator addresses; these are candidates, not ticket issuers.
		locator := filepath.Join("/var/lib/sss/pubconf", "kdcinfo."+strings.ToUpper(domain))
		o := SurveyObservation{Source: locator, Observed: time.Now().UTC(), Status: "unknown", Detail: "Нет доступных адресов KDC"}
		if st, err := os.Lstat(locator); err == nil && st.Mode().IsRegular() && st.Size() <= 4096 {
			if raw, err := os.ReadFile(locator); err == nil {
				var addresses []string
				for _, a := range strings.Fields(string(raw)) {
					if net.ParseIP(strings.Trim(a, "[]")) != nil || surveyHostname(a) {
						addresses = append(addresses, a)
					}
				}
				if len(addresses) > 0 {
					o.Status = "observed"
					o.Detail = strings.Join(addresses, "\n")
				}
			}
		}
		s.Checks = append(s.Checks, o)
	}
	if account != "" {
		probe("sssctl", "user-show", account)
	}
	probe("gpresult", "-c", "-m")
	probe("ip", "-brief", "address", "show", "up")
	for _, kind := range []string{"A", "AAAA"} {
		probe("dig", "+time=1", "+tries=1", "+noall", "+comments", "+answer", "+stats", node+".", kind)
	}
	probe("journalctl", "--no-pager", "--since=-24h", "-n", "20", "-u", "sssd", "--grep=nsupdate|[Dd]ynamic DNS|[Dd]yndns")
	s.Workstation.DNS = collectSurveyDNS(ctx, options, exchangeSurveyDNS)
	s.Finished = time.Now().UTC()
	return s, ctx.Err()
}
