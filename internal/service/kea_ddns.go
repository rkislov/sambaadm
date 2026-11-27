package service

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"sambaadm/internal/config"
)

type KeaDDNSSettings struct {
	ForwardZone     string   `json:"forwardZone"`
	ReverseZones    []string `json:"reverseZones"`
	DNSAddress      string   `json:"dnsAddress"`
	DNSPort         int      `json:"dnsPort"`
	NCRPort         int      `json:"ncrPort"`
	Auth            string   `json:"auth"`
	KeyName         string   `json:"keyName"`
	Secret          string   `json:"secret,omitempty"`
	ClientPrincipal string   `json:"clientPrincipal,omitempty"`
	ServerPrincipal string   `json:"serverPrincipal,omitempty"`
	OverrideClient  bool     `json:"overrideClient"`
}
type KeaDDNSStatus struct {
	CredentialTimer      string          `json:"credentialTimer,omitempty"`
	CredentialResult     string          `json:"credentialResult,omitempty"`
	CredentialLastRun    string          `json:"credentialLastRun,omitempty"`
	CredentialCacheValid *bool           `json:"credentialCacheValid,omitempty"`
	GSSProfile           map[string]any  `json:"gssProfile,omitempty"`
	Path                 string          `json:"path"`
	Version              string          `json:"version"`
	Service              string          `json:"service"`
	Enabled              string          `json:"enabled"`
	Revision             string          `json:"revision"`
	GSSHook              string          `json:"gssHook,omitempty"`
	Keytab               string          `json:"keytab"`
	Settings             KeaDDNSSettings `json:"settings"`
	ZoneHints            []string        `json:"zoneHints"`
	Warning              string          `json:"warning,omitempty"`
}
type KeaDDNSFilePlan struct {
	Family           string `json:"family"`
	Path             string `json:"path"`
	Before           string `json:"before"`
	Proposed         string `json:"proposed"`
	Validation       string `json:"validation"`
	Revision         string `json:"revision"`
	ProposedRevision string `json:"proposedRevision"`
}
type KeaDDNSPlan struct {
	Files            []KeaDDNSFilePlan `json:"files"`
	Revision         string            `json:"revision"`
	ProposedRevision string            `json:"proposedRevision"`
	ZoneHints        []string          `json:"zoneHints"`
	DNSInstructions  string            `json:"dnsInstructions"`
}
type KeaDDNSResult struct {
	Backups map[string]string `json:"backups"`
	Status  *KeaDDNSStatus    `json:"status"`
	Detail  string            `json:"detail,omitempty"`
}

func newKeaDDNSHost(cfg *config.Config) *keaHost {
	path := cfg.Helper.KeaDDNSConfig
	if path == "" {
		path = "/etc/kea/kea-dhcp-ddns.conf"
	}
	return &keaHost{cfg: cfg, path: path, unit: "kea-dhcp-ddns.service", binary: "kea-dhcp-ddns", family: "Ddns", run: runKeaCommand}
}
func keaZone(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".") + "."
	if value == "." || len(value) > 254 || strings.ContainsAny(value, "*\\\"; \r\n\t") {
		return "", fmt.Errorf("укажите полное имя DNS-зоны")
	}
	if _, ok := dns.IsDomainName(value); !ok {
		return "", fmt.Errorf("неверное имя DNS-зоны")
	}
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return "", fmt.Errorf("используйте ASCII-имя DNS-зоны")
			}
		}
	}
	return value, nil
}

// Reverse zones follow DNS label boundaries. IPv4 /25 uses its parent /24;
// RFC2317 delegation needs an administrator-selected zone/authority arrangement.
func keaReverseZones(cidr string) ([]string, error) {
	prefix, e := netip.ParsePrefix(cidr)
	if e != nil {
		return nil, e
	}
	prefix = prefix.Masked()
	bits := prefix.Bits()
	if bits == 0 {
		return nil, fmt.Errorf("для /0 обратная зона задаётся вручную")
	}
	var result []string
	if prefix.Addr().Is4() {
		target := ((bits + 7) / 8) * 8
		if target > 24 {
			target = 24
		}
		count := 1
		if bits < target {
			count = 1 << (target - bits)
		}
		a := prefix.Addr().As4()
		start := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		for i := 0; i < count; i++ {
			n := start + uint32(i)*(uint32(1)<<(32-target))
			octets := []uint32{n >> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255}
			parts := []string{}
			for j := target/8 - 1; j >= 0; j-- {
				parts = append(parts, fmt.Sprint(octets[j]))
			}
			result = append(result, strings.Join(parts, ".")+".in-addr.arpa.")
		}
	} else {
		target := ((bits + 3) / 4) * 4
		count := 1 << (target - bits)
		a := prefix.Addr().As16()
		for i := 0; i < count; i++ {
			b := a
			for k := 0; k < target-bits; k++ {
				bit := target - 1 - k
				if i&(1<<k) != 0 {
					b[bit/8] |= 1 << uint(7-bit%8)
				}
			}
			text := hex.EncodeToString(b[:])[:target/4]
			parts := make([]string, 0, len(text))
			for j := len(text) - 1; j >= 0; j-- {
				parts = append(parts, string(text[j]))
			}
			result = append(result, strings.Join(parts, ".")+".ip6.arpa.")
		}
	}
	return result, nil
}
func keaSubnets(root map[string]any, family string) []map[string]any {
	var out []map[string]any
	add := func(v any) {
		list, _ := v.([]any)
		for _, entry := range list {
			if subnet, ok := entry.(map[string]any); ok {
				out = append(out, subnet)
			}
		}
	}
	add(root["subnet"+family])
	networks, _ := root["shared-networks"].([]any)
	for _, entry := range networks {
		if network, ok := entry.(map[string]any); ok {
			add(network["subnet"+family])
		}
	}
	return out
}
func (h *keaHost) ddnsZoneHints() []string {
	unique := map[string]bool{}
	for _, family := range []string{"4", "6"} {
		host, e := configuredKeaHost(h.cfg, family)
		if e != nil {
			continue
		}
		raw, _, e := host.read()
		if e != nil || len(raw) == 0 {
			continue
		}
		_, root, e := keaRoot(raw, family)
		if e != nil {
			continue
		}
		for _, subnet := range keaSubnets(root, family) {
			cidr, _ := subnet["subnet"].(string)
			zones, e := keaReverseZones(cidr)
			if e == nil {
				for _, zone := range zones {
					unique[zone] = true
				}
			}
		}
	}
	out := []string{}
	for zone := range unique {
		out = append(out, zone)
	}
	sort.Strings(out)
	return out
}
func (h *keaHost) ddnsInspect(ctx context.Context) *KeaDDNSStatus {
	d2 := newKeaDDNSHost(h.cfg)
	d2.run = h.run
	out := &KeaDDNSStatus{Path: d2.path, Keytab: h.cfg.Helper.KeaDDNSKeytab, Settings: KeaDDNSSettings{Auth: "tsig", DNSPort: 53, NCRPort: 53001, KeyName: "sambaadm-kea.", OverrideClient: true}, ZoneHints: h.ddnsZoneHints()}
	if out.Keytab == "" {
		out.Keytab = "/etc/kea/ddns.keytab"
	}
	out.GSSProfile = h.gssProfile()
	out.GSSHook = h.hooks()["libddns_gss_tsig.so"]
	out.Version, _ = h.run(ctx, d2.binary, "-v")
	out.Service, _ = h.run(ctx, "systemctl", "is-active", d2.unit)
	out.Enabled, _ = h.run(ctx, "systemctl", "is-enabled", d2.unit)
	raw, _, e := d2.read()
	if e != nil {
		out.Warning = e.Error()
		return out
	}
	out.Revision = configRevision(raw)
	if len(raw) == 0 {
		return out
	}
	_, root, e := keaRoot(raw, "Ddns")
	if e != nil {
		out.Warning = e.Error()
		return out
	}
	if port, ok := root["port"].(json.Number); ok {
		if value, e := port.Int64(); e == nil {
			out.Settings.NCRPort = int(value)
		}
	}
	if section, ok := root["forward-ddns"].(map[string]any); ok {
		if domains, ok := section["ddns-domains"].([]any); ok && len(domains) > 0 {
			if entry, ok := domains[0].(map[string]any); ok {
				out.Settings.ForwardZone, _ = entry["name"].(string)
				if key, ok := entry["key-name"].(string); ok && key != "" {
					out.Settings.KeyName = key
				}
				if servers, ok := entry["dns-servers"].([]any); ok && len(servers) > 0 {
					if server, ok := servers[0].(map[string]any); ok {
						out.Settings.DNSAddress, _ = server["ip-address"].(string)
						if port, ok := server["port"].(json.Number); ok {
							if value, e := port.Int64(); e == nil {
								out.Settings.DNSPort = int(value)
							}
						}
					}
				}
			}
		}
	}
	if section, ok := root["reverse-ddns"].(map[string]any); ok {
		if domains, ok := section["ddns-domains"].([]any); ok {
			for _, entry := range domains {
				if entry, ok := entry.(map[string]any); ok {
					if name, ok := entry["name"].(string); ok {
						out.Settings.ReverseZones = append(out.Settings.ReverseZones, name)
					}
				}
			}
		}
	}
	if hooks, ok := root["hooks-libraries"].([]any); ok {
		for _, entry := range hooks {
			if hook, ok := entry.(map[string]any); ok && strings.HasSuffix(fmt.Sprint(hook["library"]), "/libddns_gss_tsig.so") {
				out.Settings.Auth = "gss-tsig"
				if params, ok := hook["parameters"].(map[string]any); ok {
					out.Settings.ClientPrincipal, _ = params["client-principal"].(string)
					out.Settings.ServerPrincipal, _ = params["server-principal"].(string)
					if servers, ok := params["servers"].([]any); ok && len(servers) > 0 {
						if server, ok := servers[0].(map[string]any); ok {
							if value, ok := server["server-principal"].(string); ok {
								out.Settings.ServerPrincipal = value
							}
						}
					}
				}
			}
		}
	}
	settingsRaw, _ := root["user-context"].(map[string]any)
	if settingsRaw != nil {
		if saved, ok := settingsRaw["sambaadm-ddns"].(map[string]any); ok {
			bytes, _ := json.Marshal(saved)
			json.Unmarshal(bytes, &out.Settings)
		}
	}
	out.Settings.Secret = ""
	if out.GSSProfile != nil {
		out.CredentialTimer, _ = h.run(ctx, "systemctl", "is-active", "sambaadm-kea-ddns-credentials.timer")
		out.CredentialResult, _ = h.run(ctx, "systemctl", "show", "--value", "--property=Result", "sambaadm-kea-ddns-credentials.service")
		out.CredentialLastRun, _ = h.run(ctx, "systemctl", "show", "--value", "--property=ExecMainStartTimestamp", "sambaadm-kea-ddns-credentials.service")
		_, err := h.run(ctx, "klist", "-s", "-c", "FILE:/run/kea/sambaadm-ddns/ccache")
		valid := err == nil
		out.CredentialCacheValid = &valid
		if out.CredentialTimer != "active" || !valid || out.CredentialResult != "success" {
			out.Warning = strings.TrimSpace(out.Warning + " Таймер Kerberos или билет DDNS требуют проверки; откройте журнал sambaadm-kea-ddns-credentials.service.")
		}
	}
	return out
}
func redactKeaDDNS(raw string) string {
	if raw == "" {
		return raw
	}
	doc, _, e := keaRoot([]byte(raw), "Ddns")
	if e != nil {
		return "[существующая конфигурация недоступна для предпросмотра]"
	}
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for key, item := range v {
				if key == "secret" || key == "password" {
					v[key] = "[скрыто]"
				} else {
					walk(item)
				}
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(doc)
	out, _ := json.MarshalIndent(doc, "", "  ")
	return string(out) + "\n"
}
func mergeDDNSDomains(root map[string]any, key string, names []string, server map[string]any, keyName string) {
	section, _ := root[key].(map[string]any)
	if section == nil {
		section = map[string]any{}
		root[key] = section
	}
	existing, _ := section["ddns-domains"].([]any)
	wanted := map[string]bool{}
	for _, name := range names {
		wanted[name] = true
	}
	entries := []any{}
	for _, entry := range existing {
		domain, ok := entry.(map[string]any)
		if !ok {
			entries = append(entries, entry)
			continue
		}
		name, _ := domain["name"].(string)
		normalized, _ := keaZone(name)
		if wanted[normalized] {
			domain["name"] = normalized
			domain["dns-servers"] = []any{server}
			domain["key-name"] = keyName
			entries = append(entries, domain)
			delete(wanted, normalized)
		} else {
			entries = append(entries, entry)
		}
	}
	for _, name := range names {
		if wanted[name] {
			entries = append(entries, map[string]any{"name": name, "key-name": keyName, "dns-servers": []any{server}})
			delete(wanted, name)
		}
	}
	section["ddns-domains"] = entries
}

type keaDDNSCandidate struct {
	host              *keaHost
	plan              *KeaPlan
	raw               []byte
	mode              os.FileMode
	existed           bool
	candidate, backup string
	prior, enabled    string
	committed         bool
	wrote             bool
	originalInfo      os.FileInfo
}

func (h *keaHost) ddnsPlan(ctx context.Context, in KeaRequest) (*KeaDDNSPlan, []*keaDDNSCandidate, error) {
	if in.DDNS == nil {
		return nil, nil, fmt.Errorf("задайте параметры DDNS")
	}
	settings := *in.DDNS
	forward, e := keaZone(settings.ForwardZone)
	if e != nil {
		return nil, nil, e
	}
	settings.ForwardZone = forward
	if settings.DNSPort < 1 || settings.DNSPort > 65535 || settings.NCRPort < 1024 || settings.NCRPort > 65535 {
		return nil, nil, fmt.Errorf("проверьте порты DNS и локального D2 (1024–65535)")
	}
	address, e := netip.ParseAddr(settings.DNSAddress)
	if e != nil || address.IsUnspecified() || address.IsMulticast() || address.Is4In6() {
		return nil, nil, fmt.Errorf("задайте IP-адрес DNS-сервера")
	}
	if len(settings.ReverseZones) == 0 || len(settings.ReverseZones) > 512 {
		return nil, nil, fmt.Errorf("задайте от 1 до 512 обратных зон")
	}
	settings.ReverseZones = append([]string{}, settings.ReverseZones...)
	seen := map[string]bool{}
	for i, value := range settings.ReverseZones {
		zone, e := keaZone(value)
		if e != nil || !(strings.HasSuffix(zone, ".in-addr.arpa.") || strings.HasSuffix(zone, ".ip6.arpa.")) {
			return nil, nil, fmt.Errorf("неверная обратная зона")
		}
		if seen[zone] {
			return nil, nil, fmt.Errorf("обратная зона повторяется")
		}
		seen[zone] = true
		settings.ReverseZones[i] = zone
	}
	d2 := newKeaDDNSHost(h.cfg)
	d2.run = h.run
	if !filepath.IsAbs(d2.path) || filepath.Clean(d2.path) != d2.path {
		return nil, nil, fmt.Errorf("проверьте helper.kea_ddns_config")
	}
	raw, mode, e := d2.read()
	if e != nil {
		return nil, nil, e
	}
	doc := map[string]any{"DhcpDdns": map[string]any{}}
	root := doc["DhcpDdns"].(map[string]any)
	if len(raw) > 0 {
		doc, root, e = keaRoot(raw, "Ddns")
		if e != nil {
			return nil, nil, e
		}
	}
	var instructions string
	var secretHost *keaHost
	var secretRaw []byte
	var secretMode os.FileMode
	var secretValue string
	var selectedTSIG map[string]any
	keyName := ""
	switch settings.Auth {
	case "tsig":
		keyName, e = keaZone(settings.KeyName)
		if e != nil {
			return nil, nil, fmt.Errorf("проверьте имя TSIG-ключа")
		}
		settings.KeyName = keyName
		keys, _ := root["tsig-keys"].([]any)
		var selected map[string]any
		for _, key := range keys {
			if entry, ok := key.(map[string]any); ok {
				normalized, _ := keaZone(fmt.Sprint(entry["name"]))
				if normalized == keyName {
					selected = entry
					break
				}
			}
		}
		secret := settings.Secret
		if secret == "" && selected != nil {
			secret, _ = selected["secret"].(string)
			if secret == "" {
				if path, ok := selected["secret-file"].(string); ok {
					host := &keaHost{path: path}
					value, _, e := host.read()
					if e != nil {
						return nil, nil, fmt.Errorf("не удалось прочитать существующий TSIG secret-file: %w", e)
					}
					secret = strings.TrimSpace(string(value))
				}
			}
		}
		decoded, e := base64.StdEncoding.DecodeString(secret)
		if e != nil || len(decoded) < 16 || len(decoded) > 128 {
			return nil, nil, fmt.Errorf("TSIG: требуется base64-ключ длиной 16–128 байт; для нового ключа используйте генератор")
		}
		if selected == nil {
			selected = map[string]any{}
			keys = append(keys, selected)
		}
		selected["name"] = keyName
		selected["algorithm"] = "HMAC-SHA256"
		secretHost = &keaHost{cfg: h.cfg, path: filepath.Join(filepath.Dir(d2.path), "sambaadm-ddns-tsig.secret"), family: "TSIG", run: h.run}
		secretRaw, secretMode, e = secretHost.read()
		if e != nil {
			return nil, nil, e
		}
		secretMode &= 0640
		secretValue = secret + "\n"
		selectedTSIG = selected
		selected["secret-file"] = secretHost.path
		delete(selected, "secret")
		root["tsig-keys"] = keys
		instructions = fmt.Sprintf("Создайте на DNS-сервере прямую зону %s и обратные зоны:\n%s\nРазрешите в этих зонах обновление A, AAAA, PTR и DHCID от ключа %s.\n\nBIND: определение ключа (содержит секрет):\nkey \"%s\" { algorithm hmac-sha256; secret \"%s\"; };\nВ каждой из выбранных зон: allow-update { key \"%s\"; };\nДля защищённых зон Samba AD требуется GSS-TSIG, keytab и права на зоны.", forward, strings.Join(settings.ReverseZones, "\n"), keyName, keyName, secret, keyName)
	case "gss-tsig":
		library := h.hooks()["libddns_gss_tsig.so"]
		if library == "" {
			return nil, nil, fmt.Errorf("libddns_gss_tsig.so отсутствует в установленной сборке Kea; для защищённого DNS AD нужны GSS-TSIG hook и keytab")
		}
		if !strings.Contains(settings.ServerPrincipal, "/") || !strings.Contains(settings.ServerPrincipal, "@") || !strings.Contains(settings.ClientPrincipal, "@") || strings.ContainsAny(settings.ClientPrincipal+settings.ServerPrincipal, "\r\n\x00") {
			return nil, nil, fmt.Errorf("укажите Kerberos principals DNS-сервера и DDNS-клиента")
		}
		keytab := h.cfg.Helper.KeaDDNSKeytab
		if keytab == "" {
			keytab = "/etc/kea/ddns.keytab"
		}
		st, e := os.Lstat(keytab)
		if e != nil || !st.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("подготовьте keytab %s с правом чтения для _kea", keytab)
		}
		hooks, _ := root["hooks-libraries"].([]any)
		var selected map[string]any
		for _, hook := range hooks {
			if entry, ok := hook.(map[string]any); ok && strings.HasSuffix(fmt.Sprint(entry["library"]), "/libddns_gss_tsig.so") {
				selected = entry
				break
			}
		}
		if selected == nil {
			selected = map[string]any{}
			hooks = append(hooks, selected)
		}
		selected["library"] = library
		selected["parameters"] = map[string]any{"client-keytab": "FILE:" + keytab, "client-principal": settings.ClientPrincipal, "retry-interval": 10, "servers": []any{map[string]any{"id": "sambaadm-dns", "exchange-timeout": 10000, "ip-address": address.String(), "port": settings.DNSPort, "server-principal": settings.ServerPrincipal, "fallback": false}}}
		if profile := h.gssProfile(); profile != nil {
			if profile["state"] == "needs-review" || profile["verified"] == nil || !h.gssKeytabMatches(keytab) {
				return nil, nil, fmt.Errorf("завершите проверку учётной записи AD и keytab перед настройкой D2")
			}
			if profile["principal"] != settings.ClientPrincipal || profile["serverPrincipal"] != settings.ServerPrincipal {
				return nil, nil, fmt.Errorf("principals не соответствуют подготовленному keytab AD")
			}
			parameters := selected["parameters"].(map[string]any)
			delete(parameters, "client-keytab")
			parameters["credentials-cache"] = "FILE:/run/kea/sambaadm-ddns/ccache"
		}
		root["hooks-libraries"] = hooks
		instructions = fmt.Sprintf("Создайте на DNS-сервере прямую зону %s и обратные зоны:\n%s\nПредоставьте %s право изменять собственные A, AAAA и PTR в этих зонах. Автонастройка Samba AD использует no-check-without-dhcid с обязательными GSS-TSIG и ACL AD. Keytab должен читаться пользователем _kea: %s.", forward, strings.Join(settings.ReverseZones, "\n"), settings.ClientPrincipal, keytab)
	default:
		return nil, nil, fmt.Errorf("выберите TSIG либо GSS-TSIG")
	}
	// Changing from GSS to TSIG must not leave an old GSS hook intercepting these updates.
	if settings.Auth == "tsig" {
		hooks, _ := root["hooks-libraries"].([]any)
		if hooks != nil {
			kept := []any{}
			for _, hook := range hooks {
				entry, _ := hook.(map[string]any)
				if !strings.HasSuffix(fmt.Sprint(entry["library"]), "/libddns_gss_tsig.so") {
					kept = append(kept, hook)
				}
			}
			root["hooks-libraries"] = kept
		}
	}
	root["ip-address"] = "127.0.0.1"
	root["port"] = settings.NCRPort
	root["ncr-protocol"] = "UDP"
	root["ncr-format"] = "JSON"
	server := map[string]any{"ip-address": address.String(), "port": settings.DNSPort}
	mergeDDNSDomains(root, "forward-ddns", []string{forward}, server, keyName)
	mergeDDNSDomains(root, "reverse-ddns", settings.ReverseZones, server, keyName)
	metadata, _ := root["user-context"].(map[string]any)
	if metadata == nil {
		metadata = map[string]any{}
		root["user-context"] = metadata
	}
	publicSettings := settings
	publicSettings.Secret = ""
	data, _ := json.Marshal(publicSettings)
	var saved map[string]any
	json.Unmarshal(data, &saved)
	metadata["sambaadm-ddns"] = saved
	// Kea 3.2 refuses inline TSIG secrets. Validate against a private temporary
	// secret file, then commit the final secret and configuration in one plan.
	var native []byte
	if secretHost != nil {
		path, e := secretHost.stage([]byte(secretValue), 0600)
		if e != nil {
			return nil, nil, e
		}
		defer os.Remove(path)
		selectedTSIG["secret-file"] = path
		native, _ = json.MarshalIndent(doc, "", "  ")
		selectedTSIG["secret-file"] = secretHost.path
	} else {
		native, _ = json.MarshalIndent(doc, "", "  ")
	}
	validation, e := d2.validate(ctx, string(native)+"\n")
	if e != nil {
		return nil, nil, fmt.Errorf("проверка D2: %w", redactDDNSError(e, settings.Secret))
	}
	proposed, _ := json.MarshalIndent(doc, "", "  ")
	d2Plan := &KeaPlan{Family: "Ddns", Before: string(raw), Proposed: string(proposed) + "\n", Revision: configRevision(raw), ProposedRevision: configRevision(append(proposed, '\n')), Validation: validation, Action: "apply"}
	candidates := []*keaDDNSCandidate{}
	if secretHost != nil {
		candidates = append(candidates, &keaDDNSCandidate{host: secretHost, raw: secretRaw, mode: secretMode, plan: &KeaPlan{Family: "TSIG", Before: string(secretRaw), Proposed: secretValue, Revision: configRevision(secretRaw), ProposedRevision: configRevision([]byte(secretValue)), Validation: "Секрет TSIG: base64, 16–128 байт", Action: "apply"}})
	}
	candidates = append(candidates, &keaDDNSCandidate{host: d2, plan: d2Plan, raw: raw, mode: mode})
	for _, family := range []string{"4", "6"} {
		host, e := configuredKeaHost(h.cfg, family)
		if e != nil {
			return nil, nil, e
		}
		host.run = h.run
		raw, mode, e := host.read()
		if e != nil {
			return nil, nil, e
		}
		if len(raw) == 0 {
			continue
		}
		doc, root, e := keaRoot(raw, family)
		if e != nil {
			return nil, nil, e
		}
		conn, _ := root["dhcp-ddns"].(map[string]any)
		if conn == nil {
			conn = map[string]any{}
			root["dhcp-ddns"] = conn
		}
		conn["enable-updates"] = true
		conn["server-ip"] = "127.0.0.1"
		conn["server-port"] = settings.NCRPort
		conn["ncr-protocol"] = "UDP"
		conn["ncr-format"] = "JSON"
		setDDNS := func(scope map[string]any) {
			scope["ddns-send-updates"] = true
			scope["ddns-qualifying-suffix"] = strings.TrimSuffix(forward, ".")
			scope["ddns-replace-client-name"] = "when-not-present"
			scope["ddns-generated-prefix"] = "dhcp"
			scope["ddns-override-client-update"] = settings.OverrideClient
			scope["ddns-override-no-update"] = settings.OverrideClient
			scope["ddns-update-on-renew"] = true
			if settings.Auth == "tsig" {
				scope["ddns-conflict-resolution-mode"] = "check-with-dhcid"
			}
			if settings.Auth == "gss-tsig" {
				if profile := h.gssProfile(); profile != nil && profile["conflictMode"] == "no-check-without-dhcid" {
					// Samba AD stores A/AAAA/PTR but does not implement DHCID.
					// GSS authentication and AD ownership ACLs still protect updates.
					scope["ddns-conflict-resolution-mode"] = "no-check-without-dhcid"
				}
			}
		}
		setDDNS(root)
		for _, subnet := range keaSubnets(root, family) {
			setDDNS(subnet)
		}
		proposed, _ := json.MarshalIndent(doc, "", "  ")
		plan, e := host.plan(ctx, KeaRequest{Config: string(proposed) + "\n"})
		if e != nil {
			return nil, nil, e
		}
		candidates = append(candidates, &keaDDNSCandidate{host: host, plan: plan, raw: raw, mode: mode})
	}
	dhcpCount := 0
	for _, c := range candidates {
		if c.host.family == "4" || c.host.family == "6" {
			dhcpCount++
		}
	}
	if dhcpCount == 0 {
		return nil, nil, fmt.Errorf("сначала настройте DHCPv4 или DHCPv6")
	}
	out := &KeaDDNSPlan{ZoneHints: append([]string{forward}, settings.ReverseZones...), DNSInstructions: instructions}
	var before, after []string
	for _, candidate := range candidates {
		c := candidate
		info, e := os.Lstat(c.host.path)
		c.originalInfo = info
		c.existed = e == nil
		before = append(before, c.host.path+":"+c.plan.Revision)
		after = append(after, c.host.path+":"+c.plan.ProposedRevision)
		old, new := c.plan.Before, c.plan.Proposed
		if c.host.family == "TSIG" {
			old = "[скрыто]"
			new = "[скрыто]"
		}
		if c.host.family == "Ddns" {
			old = redactKeaDDNS(old)
			new = redactKeaDDNS(new)
		}
		out.Files = append(out.Files, KeaDDNSFilePlan{Family: c.host.family, Path: c.host.path, Before: old, Proposed: new, Revision: c.plan.Revision, ProposedRevision: c.plan.ProposedRevision, Validation: c.plan.Validation})
	}
	out.Revision = configRevision([]byte(strings.Join(before, "\n")))
	out.ProposedRevision = configRevision([]byte(strings.Join(after, "\n")))
	return out, candidates, nil
}
func redactDDNSError(err error, secret string) error {
	if err == nil {
		return nil
	}
	if secret != "" {
		return errors.New(strings.ReplaceAll(err.Error(), secret, "[скрыто]"))
	}
	return err
}

func (h *keaHost) ddnsApply(ctx context.Context, in KeaRequest) (result *KeaDDNSResult, err error) {
	if !in.Confirm {
		return nil, fmt.Errorf("подтвердите настройку DDNS и перезапуск служб")
	}
	plan, files, e := h.ddnsPlan(ctx, in)
	if e != nil {
		return nil, e
	}
	if in.Revision == "" || in.Revision != plan.Revision || in.ProposedRevision != plan.ProposedRevision {
		return nil, ErrTopologyConflict
	}
	for _, c := range files {
		if c.host.unit == "" {
			continue
		}
		c.prior, e = h.run(ctx, "systemctl", "is-active", c.host.unit)
		if c.prior != "active" && c.prior != "inactive" && c.prior != "failed" {
			return nil, fmt.Errorf("не удалось определить состояние %s: %s (%v)", c.host.unit, c.prior, e)
		}
		if c.host.family == "Ddns" {
			c.enabled, _ = h.run(ctx, "systemctl", "is-enabled", c.host.unit)
			if c.enabled != "enabled" && c.enabled != "disabled" {
				return nil, fmt.Errorf("не удалось определить автозапуск D2: %s", c.enabled)
			}
		}
	}
	defer func() {
		for _, c := range files {
			if c.candidate != "" {
				os.Remove(c.candidate)
			}
		}
	}()
	for _, c := range files {
		mode := c.mode
		if c.host.family == "Ddns" {
			mode &= 0640
		}
		c.candidate, e = c.host.stage([]byte(c.plan.Proposed), mode)
		if e != nil {
			return nil, e
		}
		if c.host.family == "TSIG" {
			f, e := os.OpenFile(c.candidate, os.O_WRONLY, 0)
			if e != nil {
				return nil, e
			}
			info, e := os.Stat(filepath.Dir(c.host.path))
			if e == nil {
				e = preserveConfigOwner(f, info)
			}
			if e == nil {
				e = f.Chmod(0640)
			}
			f.Close()
			if e != nil {
				return nil, e
			}
		}
		c.backup, e = c.host.stage(c.raw, 0600)
		if e != nil {
			return nil, e
		}
	}
	for _, c := range files {
		current, _, e := c.host.read()
		if e != nil || configRevision(current) != c.plan.Revision {
			return nil, ErrTopologyConflict
		}
	}
	committed := false
	defer func() {
		if err == nil || !committed {
			return
		}
		rollback, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		var failures []string
		for i := len(files) - 1; i >= 0; i-- {
			c := files[i]
			if !c.committed {
				continue
			}
			current, _, e := c.host.read()
			if e != nil || configRevision(current) != c.plan.ProposedRevision {
				failures = append(failures, c.host.path+": файл изменён извне; копия "+c.backup)
				continue
			}
			if c.existed {
				staged, e := c.host.stage(c.raw, c.mode)
				if e == nil && c.originalInfo != nil {
					f, openErr := os.OpenFile(staged, os.O_WRONLY, 0)
					if openErr != nil {
						e = openErr
					} else {
						e = preserveConfigOwner(f, c.originalInfo)
						f.Close()
					}
				}
				if e == nil {
					e = os.Rename(staged, c.host.path)
					os.Remove(staged)
				}
				if e != nil {
					failures = append(failures, c.host.path+": "+e.Error())
					continue
				}
			} else {
				if e = os.Remove(c.host.path); e != nil {
					failures = append(failures, e.Error())
					continue
				}
			}
			c.committed = false
		}
		for _, c := range files {
			if c.committed || !c.wrote || c.host.unit == "" {
				continue
			}
			action := "stop"
			if c.prior == "active" {
				action = "restart"
			}
			if _, e := h.run(rollback, "systemctl", action, c.host.unit); e != nil {
				failures = append(failures, c.host.unit+": "+e.Error())
			}
			if c.host.family == "Ddns" && c.enabled == "disabled" {
				if _, e := h.run(rollback, "systemctl", "disable", c.host.unit); e != nil {
					failures = append(failures, e.Error())
				}
			}
		}
		copies := []string{}
		for _, c := range files {
			copies = append(copies, c.host.path+"="+c.backup)
		}
		err = fmt.Errorf("%w; резервные копии: %s", err, strings.Join(copies, ", "))
		if len(failures) == 0 {
			err = fmt.Errorf("%w; прежние файлы и состояния служб восстановлены", err)
		} else {
			err = fmt.Errorf("%w; ошибки отката: %s", err, strings.Join(failures, "; "))
		}
	}()
	for _, c := range files {
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		current, _, e := c.host.read()
		if e != nil || configRevision(current) != c.plan.Revision {
			return nil, ErrTopologyConflict
		}
		if e = os.Rename(c.candidate, c.host.path); e != nil {
			return nil, e
		}
		c.committed = true
		c.wrote = true
		committed = true
	}
	// Start D2 first, then restart only DHCP services which were already active.
	for _, c := range files {
		if c.host.unit == "" {
			continue
		}
		if c.host.family == "Ddns" {
			if _, e = h.run(ctx, "systemctl", "enable", c.host.unit); e != nil {
				return nil, e
			}
		} else if c.prior != "active" {
			continue
		}
		if _, e = h.run(ctx, "systemctl", "restart", c.host.unit); e != nil {
			return nil, e
		}
		if _, e = h.run(ctx, "systemctl", "is-active", c.host.unit); e != nil {
			return nil, e
		}
	}
	out := &KeaDDNSResult{Backups: map[string]string{}, Status: h.ddnsInspect(ctx), Detail: "D2 настроен и включён; работающие DHCP-службы перезапущены. Создайте зоны и разрешите подписанные обновления на DNS-сервере."}
	for _, c := range files {
		out.Backups[c.host.path] = c.backup
	}
	return out, nil
}
func (h *keaHost) ddnsService(ctx context.Context, in KeaRequest) (*KeaDDNSResult, error) {
	d2 := newKeaDDNSHost(h.cfg)
	d2.run = h.run
	result, e := d2.service(ctx, in)
	if e != nil {
		return nil, e
	}
	return &KeaDDNSResult{Detail: result.Detail, Status: h.ddnsInspect(ctx)}, nil
}
