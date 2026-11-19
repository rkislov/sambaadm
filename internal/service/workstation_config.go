package service

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const workstationConfigLimit = 64 << 10
const workstationFilesLimit = 16

type SurveySetting struct {
	Section string `json:"section"`
	Key     string `json:"key"`
	Value   string `json:"value"`
}
type SurveyConfigFile struct {
	Path     string          `json:"path"`
	Kind     string          `json:"kind"`
	Observed time.Time       `json:"observed"`
	Status   string          `json:"status"`
	Mode     string          `json:"mode,omitempty"`
	Owner    string          `json:"owner,omitempty"`
	Settings []SurveySetting `json:"settings"`
	Omitted  int             `json:"omitted"`
	Issues   []string        `json:"issues"`
}
type WorkstationDiagnostics struct {
	Format   int                `json:"format"`
	Configs  []SurveyConfigFile `json:"configs"`
	DNS      []SurveyDNSResult  `json:"dns"`
	Warnings []string           `json:"warnings"`
}

// Only typed values from a small allowlist leave the host. Unknown assignments,
// comments and parse failures are counted, never retained as raw text.
func surveyConfigValue(kind, section, key, value string) bool {
	if len(value) > 512 || strings.ContainsAny(value, "\x00\r\n\"'#$;{}=") {
		return false
	}
	boolean := func() bool { return value == "true" || value == "false" || value == "True" || value == "False" }
	realm := func(s string) bool { return surveyHostname(strings.TrimPrefix(s, ".")) }
	servers := func() bool {
		for _, v := range strings.Split(value, ",") {
			v = strings.TrimSpace(v)
			if v == "_srv_" {
				continue
			}
			if !surveyServerName(v) {
				return false
			}
		}
		return value != ""
	}
	if kind == "sssd" {
		if !strings.HasPrefix(section, "domain/") || !realm(strings.TrimPrefix(section, "domain/")) {
			return false
		}
		switch key {
		case "ad_server", "ad_backup_server", "krb5_server", "krb5_backup_server":
			return servers()
		case "ad_domain", "krb5_realm", "ad_site":
			return realm(value) || (key == "ad_site" && workstationLabel.MatchString(value))
		case "id_provider", "auth_provider", "access_provider":
			return map[string]bool{"ad": true, "ldap": true, "krb5": true, "ipa": true, "proxy": true, "simple": true, "permit": true, "deny": true, "files": true, "none": true}[value]
		case "ad_enable_dns_sites", "krb5_use_kdcinfo", "krb5_use_enterprise_principal", "krb5_use_subdomain_realm", "cache_credentials", "use_fully_qualified_names":
			return boolean()
		}
	}
	if kind == "krb5" {
		switch section {
		case "libdefaults":
			switch key {
			case "default_realm":
				return realm(value)
			case "dns_lookup_kdc", "dns_lookup_realm", "dns_uri_lookup", "rdns":
				return boolean()
			case "dns_canonicalize_hostname":
				return boolean() || value == "fallback"
			}
		case "domain_realm":
			return realm(key) && realm(value)
		default:
			if strings.HasPrefix(section, "realms/") && realm(strings.TrimPrefix(section, "realms/")) {
				return (key == "kdc" || key == "admin_server" || key == "kpasswd_server") && surveyServerName(value)
			}
		}
	}
	return false
}
func surveyServerName(v string) bool {
	if v == "" {
		return false
	}
	if _, e := netip.ParseAddr(v); e == nil {
		return true
	}
	host, port, e := net.SplitHostPort(v)
	if e == nil {
		if p, e := net.LookupPort("tcp", port); e != nil || p < 1 || p > 65535 {
			return false
		}
		return surveyHostname(host) || net.ParseIP(host) != nil
	}
	return surveyHostname(v)
}

type configSurveyReader struct {
	files    []SurveyConfigFile
	visited  map[string]bool
	warnings []string
}

func collectWorkstationConfigs(sssd, krb5 string, extra []string) ([]SurveyConfigFile, []string) {
	r := configSurveyReader{visited: map[string]bool{}}
	r.read(sssd, "sssd")
	entries, _ := filepath.Glob(filepath.Join(filepath.Dir(sssd), "conf.d", "*.conf"))
	for _, p := range entries {
		r.read(p, "sssd")
	}
	r.read(krb5, "krb5")
	for _, p := range extra {
		r.read(p, "krb5")
	}
	return r.files, r.warnings
}
func (r *configSurveyReader) read(path, kind string) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		r.warn("Конфигурация содержит относительный include; файл не прочитан")
		return
	}
	if r.visited[path] {
		return
	}
	r.visited[path] = true
	if len(r.files) >= workstationFilesLimit {
		r.warn("Достигнут лимит 16 файлов конфигурации; охват неполный")
		return
	}
	o := SurveyConfigFile{Path: path, Kind: kind, Observed: time.Now().UTC(), Status: "unknown", Settings: []SurveySetting{}, Issues: []string{}}
	index := len(r.files)
	r.files = append(r.files, o)
	st, e := os.Lstat(path)
	if e != nil {
		r.files[index].Issues = append(r.files[index].Issues, "Файл недоступен")
		return
	}
	o.Mode = fmt.Sprintf("%04o", st.Mode().Perm())
	if owner, ok := fileOwner(st); ok {
		o.Owner = owner.uidName + ":" + owner.gidName
	}
	if !st.Mode().IsRegular() || st.Size() > workstationConfigLimit {
		o.Issues = append(o.Issues, "Требуется обычный файл до 64 КиБ без символьной ссылки")
		r.files[index] = o
		return
	}
	if kind == "sssd" && (o.Mode != "0600" || o.Owner != "root:root") {
		o.Issues = append(o.Issues, "Проверить владельца root:root и права 0600 для SSSD")
	}
	f, e := os.Open(path)
	if e != nil {
		o.Issues = append(o.Issues, "Файл недоступен")
		r.files[index] = o
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, workstationConfigLimit+1))
	scanner.Buffer(make([]byte, 4096), workstationConfigLimit+1)
	section := ""
	var includes []string
	total := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		total += len(scanner.Bytes()) + 1
		if total > workstationConfigLimit {
			break
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if kind == "krb5" && (strings.HasPrefix(line, "include ") || strings.HasPrefix(line, "includedir ")) {
			fields := strings.Fields(line)
			if len(fields) != 2 || !filepath.IsAbs(fields[1]) {
				o.Omitted++
				o.Issues = append(o.Issues, "Не удалось разобрать include")
				continue
			}
			if fields[0] == "includedir" {
				ds, e := os.Lstat(fields[1])
				if e != nil || !ds.IsDir() || ds.Mode()&os.ModeSymlink != 0 {
					o.Issues = append(o.Issues, "Каталог include недоступен")
					continue
				}
				directory, e := os.Open(fields[1])
				if e != nil {
					o.Issues = append(o.Issues, "Каталог include недоступен")
					continue
				}
				entries, e := directory.ReadDir(129)
				directory.Close()
				if len(entries) > 128 {
					entries = entries[:128]
					o.Issues = append(o.Issues, "Каталог include прочитан не полностью")
				}
				sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
				if e != nil && e != io.EOF {
					o.Issues = append(o.Issues, "Каталог include недоступен")
					continue
				}
				for _, entry := range entries {
					if entry.Type().IsRegular() && kerberosIncludeName(entry.Name()) {
						includes = append(includes, filepath.Join(fields[1], entry.Name()))
					}
					if len(includes) >= 32 {
						o.Issues = append(o.Issues, "Список include ограничен")
						break
					}
				}
			} else {
				includes = append(includes, fields[1])
			}
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if kind == "krb5" && section == "realms" && strings.HasSuffix(line, "{") {
			realm, _, ok := strings.Cut(line, "=")
			realm = strings.TrimSpace(realm)
			if ok && surveyHostname(realm) {
				section = "realms/" + realm
				continue
			}
		}
		if kind == "krb5" && (line == "}" || line == "}*") && strings.HasPrefix(section, "realms/") {
			section = "realms"
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if i := strings.IndexAny(value, "#;"); i >= 0 {
			value = strings.TrimSpace(value[:i])
		}
		if ok && surveyConfigValue(kind, section, key, value) && len(o.Settings) < 128 {
			o.Settings = append(o.Settings, SurveySetting{section, key, value})
		} else {
			o.Omitted++
			if key == "ad_backup_server" && strings.ContainsAny(value, "\"'") {
				o.Issues = append(o.Issues, "Список ad_backup_server заключён в кавычки; значение не экспортировано")
			}
		}
	}
	o.Status = "observed"
	if scanner.Err() != nil || total > workstationConfigLimit {
		o.Status = "partial"
		o.Issues = append(o.Issues, "Файл прочитан не полностью")
	}
	if o.Omitted > 0 {
		o.Issues = append(o.Issues, "Неподдерживаемые параметры не экспортированы; это не полный файл")
	}
	unique := []string{}
	for _, issue := range o.Issues {
		seen := false
		for _, existing := range unique {
			if issue == existing {
				seen = true
				break
			}
		}
		if !seen && len(unique) < 32 {
			unique = append(unique, issue)
		}
	}
	o.Issues = unique
	r.files[index] = o
	for _, p := range includes {
		r.read(p, "krb5")
	}
}
func kerberosIncludeName(name string) bool {
	name = strings.TrimSuffix(name, ".conf")
	if name == "" {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
func (r *configSurveyReader) warn(v string) {
	for _, w := range r.warnings {
		if w == v {
			return
		}
	}
	r.warnings = append(r.warnings, v)
}

func validateWorkstationDiagnostics(w *WorkstationDiagnostics, profile string) error {
	if w == nil {
		return nil
	}
	invalid := fmt.Errorf("invalid workstation diagnostics")
	if profile != "alt-workstation" || w.Format != 1 || len(w.Configs) > workstationFilesLimit || len(w.DNS) > 64 || len(w.Warnings) > 32 {
		return invalid
	}
	for _, warning := range w.Warnings {
		if len(warning) > 512 {
			return invalid
		}
	}
	for _, f := range w.Configs {
		if f.Path == "" || len(f.Path) > 4096 || f.Observed.IsZero() || (f.Kind != "sssd" && f.Kind != "krb5") || !surveyObservationStatus(f.Status) || len(f.Settings) > 128 || len(f.Issues) > 256 || len(f.Owner) > 256 || len(f.Mode) > 8 || f.Omitted < 0 || f.Omitted > 65536 {
			return invalid
		}
		for _, i := range f.Issues {
			if len(i) > 512 {
				return invalid
			}
		}
		for _, s := range f.Settings {
			if !surveyConfigValue(f.Kind, s.Section, s.Key, s.Value) {
				return invalid
			}
		}
	}
	for _, r := range w.DNS {
		if _, e := netip.ParseAddr(r.Resolver); e != nil {
			return invalid
		}
		if _, _, e := surveyDNSQuery(r.Name + "/" + r.Type); e != nil {
			return invalid
		}
		if !surveyObservationStatus(r.Status) || r.Observed.IsZero() || (r.Transport != "udp" && r.Transport != "tcp") || r.DurationMS < 0 || len(r.RCode) > 32 || len(r.Answers) > 32 {
			return invalid
		}
		for _, answer := range r.Answers {
			if len(answer) > 2048 {
				return invalid
			}
		}
	}
	return nil
}
func surveyObservationStatus(s string) bool {
	return s == "observed" || s == "partial" || s == "unknown"
}
