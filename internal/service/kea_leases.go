package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

const keaLeasePageSize = 256
const keaControlLimit = 4 << 20

type KeaLeaseRef struct {
	Address  string `json:"address"`
	Type     string `json:"type,omitempty"`
	SubnetID uint32 `json:"subnetID"`
	Revision string `json:"revision"`
}

type KeaLease struct {
	Address       string     `json:"ip-address"`
	Type          string     `json:"type,omitempty"`
	SubnetID      uint32     `json:"subnet-id"`
	MAC           string     `json:"hw-address,omitempty"`
	ClientID      string     `json:"client-id,omitempty"`
	DUID          string     `json:"duid,omitempty"`
	IAID          uint32     `json:"iaid,omitempty"`
	PrefixLen     int        `json:"prefix-len,omitempty"`
	Hostname      string     `json:"hostname,omitempty"`
	State         int        `json:"state"`
	CLTT          int64      `json:"cltt"`
	ValidLifetime uint32     `json:"valid-lft"`
	Revision      string     `json:"revision"`
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	Infinite      bool       `json:"infinite"`
}

type KeaLeasePage struct {
	Leases   []KeaLease `json:"leases"`
	Next     string     `json:"next,omitempty"`
	Observed time.Time  `json:"observed"`
	Scanned  int        `json:"scanned"`
}

type keaCommandResponse struct {
	Result    int             `json:"result"`
	Text      string          `json:"text"`
	Arguments json.RawMessage `json:"arguments"`
}

func keaRoot(raw []byte, family string) (map[string]any, map[string]any, error) {
	normalized, e := keaDocument(string(raw), family)
	if e != nil {
		return nil, nil, e
	}
	var doc map[string]any
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.UseNumber()
	if e = decoder.Decode(&doc); e != nil {
		return nil, nil, e
	}
	return doc, doc["Dhcp"+family].(map[string]any), nil
}

func keaControlSocket(root map[string]any) (string, error) {
	candidates := []any{root["control-socket"]}
	if sockets, ok := root["control-sockets"].([]any); ok {
		candidates = append(candidates, sockets...)
	}
	for _, candidate := range candidates {
		socket, ok := candidate.(map[string]any)
		if !ok || socket["socket-type"] != "unix" {
			continue
		}
		path, _ := socket["socket-name"].(string)
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 107 {
			return "", fmt.Errorf("некорректный путь UNIX control-socket Kea")
		}
		return path, nil
	}
	return "", fmt.Errorf("для аренд настройте UNIX control-socket и загрузите libdhcp_lease_cmds.so; используйте «Включить управление арендами»")
}

// Only these commands are reachable; callers cannot submit arbitrary Kea commands.
func (h *keaHost) leaseCommand(ctx context.Context, command string, arguments any) (*keaCommandResponse, error) {
	switch command {
	case "lease4-get-page", "lease6-get-page", "lease4-get", "lease6-get", "lease4-del", "lease6-del":
	default:
		return nil, fmt.Errorf("недопустимая команда аренд")
	}
	raw, _, e := h.read()
	if e != nil {
		return nil, e
	}
	_, root, e := keaRoot(raw, h.family)
	if e != nil {
		return nil, e
	}
	return keaSocketCommand(ctx, root, command, arguments)
}

func keaSocketCommand(ctx context.Context, root map[string]any, command string, arguments any) (*keaCommandResponse, error) {
	path, e := keaControlSocket(root)
	if e != nil {
		return nil, e
	}
	st, e := os.Lstat(path)
	if e != nil {
		return nil, fmt.Errorf("control-socket Kea недоступен: %w; проверьте службу и путь /run/kea вместо /tmp", e)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("control-socket Kea не является UNIX-сокетом")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if e != nil {
		return nil, fmt.Errorf("подключение к Kea: %w", e)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if e = conn.SetDeadline(deadline); e != nil {
		return nil, e
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	request := map[string]any{"command": command}
	if arguments != nil {
		request["arguments"] = arguments
	}
	if e = json.NewEncoder(conn).Encode(request); e != nil {
		return nil, fmt.Errorf("отправка команды Kea: %w", e)
	}
	var response json.RawMessage
	if e = json.NewDecoder(io.LimitReader(conn, keaControlLimit+1)).Decode(&response); e != nil {
		return nil, fmt.Errorf("чтение ответа Kea: %w", e)
	}
	if len(response) > keaControlLimit {
		return nil, fmt.Errorf("ответ Kea превышает 4 МиБ")
	}
	if len(response) > 0 && response[0] == '[' {
		var values []json.RawMessage
		if json.Unmarshal(response, &values) != nil || len(values) != 1 {
			return nil, fmt.Errorf("неверный ответ Kea")
		}
		response = values[0]
	}
	var result struct {
		Result    *int            `json:"result"`
		Text      string          `json:"text"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal(response, &result) != nil || result.Result == nil {
		return nil, fmt.Errorf("неверный ответ Kea")
	}
	if *result.Result != 0 && *result.Result != 3 {
		return nil, fmt.Errorf("Kea %s: %s (код %d); проверьте libdhcp_lease_cmds.so", command, result.Text, *result.Result)
	}
	return &keaCommandResponse{Result: *result.Result, Text: result.Text, Arguments: result.Arguments}, nil
}

func decodeKeaLease(raw json.RawMessage) (KeaLease, error) {
	var lease KeaLease
	if e := json.Unmarshal(raw, &lease); e != nil {
		return lease, e
	}
	address, e := netip.ParseAddr(lease.Address)
	if e != nil || address.Is4In6() || lease.SubnetID == 0 || lease.CLTT < 0 || lease.CLTT > 253402300799-int64(lease.ValidLifetime) {
		return lease, fmt.Errorf("неверная запись аренды Kea")
	}
	// Hash the complete server record, including fields unknown to the UI.
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(raw, &fields); e != nil {
		return lease, e
	}
	canonical, _ := json.Marshal(fields)
	lease.Revision = configRevision(canonical)
	lease.Infinite = lease.ValidLifetime == ^uint32(0)
	if !lease.Infinite {
		expiry := time.Unix(lease.CLTT+int64(lease.ValidLifetime), 0).UTC()
		lease.ExpiresAt = &expiry
	}
	return lease, nil
}
func (l KeaLease) active(now time.Time) bool {
	return l.State == 0 && l.ValidLifetime > 0 && (l.Infinite || l.ExpiresAt != nil && l.ExpiresAt.After(now))
}
func (h *keaHost) checkLeaseAddress(address string) error {
	ip, e := netip.ParseAddr(address)
	if e != nil || ip.Is4In6() || ip.Is4() != (h.family == "4") {
		return fmt.Errorf("адрес аренды не соответствует IPv%s", h.family)
	}
	return nil
}
func (h *keaHost) leases(ctx context.Context, in KeaRequest) (*KeaLeasePage, error) {
	if utf8.RuneCountInString(in.Search) > 256 {
		return nil, fmt.Errorf("поисковая строка длиннее 256 символов")
	}
	needle := strings.ToLower(strings.TrimSpace(in.Search))
	from := in.From
	if from == "" {
		from = "start"
	}
	if from != "start" {
		if e := h.checkLeaseAddress(from); e != nil {
			return nil, e
		}
	}
	result, e := h.leaseCommand(ctx, "lease"+h.family+"-get-page", map[string]any{"from": from, "limit": keaLeasePageSize})
	if e != nil {
		return nil, e
	}
	page := &KeaLeasePage{Leases: []KeaLease{}, Observed: time.Now().UTC()}
	if result.Result == 3 {
		return page, nil
	}
	var data struct {
		Leases []json.RawMessage `json:"leases"`
	}
	if json.Unmarshal(result.Arguments, &data) != nil || data.Leases == nil || len(data.Leases) > keaLeasePageSize {
		return nil, fmt.Errorf("неверная страница аренд Kea")
	}
	for _, raw := range data.Leases {
		lease, e := decodeKeaLease(raw)
		if e != nil {
			return nil, e
		}
		if e = h.checkLeaseAddress(lease.Address); e != nil {
			return nil, e
		}
		searchAddress := lease.Address
		if lease.Type == "IA_PD" {
			searchAddress = fmt.Sprintf("%s/%d", lease.Address, lease.PrefixLen)
		}
		text := strings.ToLower(strings.Join([]string{searchAddress, lease.Hostname, lease.MAC, lease.ClientID, lease.DUID, lease.Type, fmt.Sprint(lease.IAID), fmt.Sprint(lease.SubnetID)}, " "))
		if lease.active(page.Observed) && (in.SubnetID == 0 || lease.SubnetID == in.SubnetID) && (needle == "" || strings.Contains(text, needle)) {
			page.Leases = append(page.Leases, lease)
		}
	}
	page.Scanned = len(data.Leases)
	if len(data.Leases) == keaLeasePageSize {
		last, e := decodeKeaLease(data.Leases[len(data.Leases)-1])
		if e != nil {
			return nil, e
		}
		if from != "start" && netip.MustParseAddr(last.Address).Compare(netip.MustParseAddr(from)) <= 0 {
			return nil, fmt.Errorf("Kea не продвинул курсор аренд")
		}
		page.Next = last.Address
	}
	return page, nil
}
func (h *keaHost) currentLease(ctx context.Context, ref *KeaLeaseRef) (*KeaLease, error) {
	if ref == nil || ref.Revision == "" || ref.SubnetID == 0 {
		return nil, fmt.Errorf("выберите аренду и обновите список")
	}
	if e := h.checkLeaseAddress(ref.Address); e != nil {
		return nil, e
	}
	args := map[string]any{"ip-address": ref.Address}
	if h.family == "6" {
		if ref.Type != "IA_NA" && ref.Type != "IA_PD" {
			return nil, fmt.Errorf("поддерживаются аренды IA_NA и IA_PD")
		}
		args["type"] = ref.Type
	}
	result, e := h.leaseCommand(ctx, "lease"+h.family+"-get", args)
	if e != nil {
		return nil, e
	}
	if result.Result == 3 {
		return nil, fmt.Errorf("аренда уже отсутствует; обновите список")
	}
	raw := result.Arguments
	// Older and newer command responses may wrap a single record in leases.
	var wrapper struct {
		Leases []json.RawMessage `json:"leases"`
	}
	if json.Unmarshal(raw, &wrapper) != nil {
		return nil, fmt.Errorf("неверный ответ Kea")
	}
	if wrapper.Leases != nil {
		if len(wrapper.Leases) != 1 {
			return nil, fmt.Errorf("неоднозначный ответ Kea")
		}
		raw = wrapper.Leases[0]
	}
	lease, e := decodeKeaLease(raw)
	if e != nil {
		return nil, e
	}
	if lease.Address != ref.Address || lease.SubnetID != ref.SubnetID || lease.Revision != ref.Revision || (h.family == "6" && lease.Type != ref.Type) {
		return nil, fmt.Errorf("аренда изменилась; обновите список: %w", ErrTopologyConflict)
	}
	return &lease, nil
}
func (h *keaHost) deleteLease(ctx context.Context, in KeaRequest) (*KeaResult, error) {
	if !in.Confirm {
		return nil, fmt.Errorf("подтвердите удаление аренды")
	}
	lease, e := h.currentLease(ctx, in.Lease)
	if e != nil {
		return nil, e
	}
	args := map[string]any{"ip-address": lease.Address, "subnet-id": lease.SubnetID, "update-ddns": in.UpdateDDNS}
	if h.family == "6" {
		args["type"] = lease.Type
	}
	result, e := h.leaseCommand(ctx, "lease"+h.family+"-del", args)
	if e != nil {
		return nil, e
	}
	if result.Result != 0 {
		return nil, fmt.Errorf("аренда уже отсутствует; обновите список")
	}
	return &KeaResult{Detail: "Аренда " + lease.Address + " удалена на выбранном сервере. " + result.Text}, nil
}
func findKeaSubnet(root map[string]any, family string, id uint32) map[string]any {
	find := func(value any) map[string]any {
		entries, _ := value.([]any)
		for _, entry := range entries {
			if subnet, ok := entry.(map[string]any); ok {
				if number, ok := subnet["id"].(json.Number); ok {
					if value, e := number.Int64(); e == nil && value == int64(id) {
						return subnet
					}
				}
			}
		}
		return nil
	}
	if subnet := find(root["subnet"+family]); subnet != nil {
		return subnet
	}
	networks, _ := root["shared-networks"].([]any)
	for _, entry := range networks {
		if network, ok := entry.(map[string]any); ok {
			if subnet := find(network["subnet"+family]); subnet != nil {
				return subnet
			}
		}
	}
	return nil
}
func keaIdentifier(value any) string {
	text, _ := value.(string)
	return strings.ToLower(strings.NewReplacer(":", "", "-", "", " ", "").Replace(text))
}
func keaReservationConflict(existing, new map[string]any) bool {
	for _, key := range []string{"hw-address", "client-id", "duid"} {
		if value := keaIdentifier(new[key]); value != "" && value == keaIdentifier(existing[key]) {
			return true
		}
	}
	if address, ok := new["ip-address"].(string); ok && address == existing["ip-address"] {
		return true
	}
	for _, key := range []string{"ip-addresses", "prefixes"} {
		wanted, _ := new[key].([]any)
		old, _ := existing[key].([]any)
		for _, a := range wanted {
			for _, b := range old {
				if key == "prefixes" {
					pa, ea := netip.ParsePrefix(fmt.Sprint(a))
					pb, eb := netip.ParsePrefix(fmt.Sprint(b))
					if ea == nil && eb == nil && pa.Overlaps(pb) {
						return true
					}
				} else {
					pa, ea := netip.ParseAddr(fmt.Sprint(a))
					pb, eb := netip.ParseAddr(fmt.Sprint(b))
					if ea == nil && eb == nil && pa == pb {
						return true
					}
				}
			}
		}
	}
	return false
}
func (h *keaHost) reserveLeasePlan(ctx context.Context, in KeaRequest) (*KeaPlan, error) {
	lease, e := h.currentLease(ctx, in.Lease)
	if e != nil {
		return nil, e
	}
	if !lease.active(time.Now()) {
		return nil, fmt.Errorf("аренда больше не активна; обновите список")
	}
	raw, _, e := h.read()
	if e != nil {
		return nil, e
	}
	if in.Revision == "" || configRevision(raw) != in.Revision {
		return nil, ErrTopologyConflict
	}
	doc, root, e := keaRoot(raw, h.family)
	if e != nil {
		return nil, e
	}
	subnet := findKeaSubnet(root, h.family, lease.SubnetID)
	if subnet == nil {
		return nil, fmt.Errorf("область аренды отсутствует в файле конфигурации; проверьте внешний config backend")
	}
	reservation := map[string]any{}
	if h.family == "4" {
		if lease.MAC != "" {
			reservation["hw-address"] = lease.MAC
		} else if lease.ClientID != "" {
			reservation["client-id"] = lease.ClientID
		} else {
			return nil, fmt.Errorf("у аренды нет MAC или client-id для резервирования")
		}
		reservation["ip-address"] = lease.Address
	} else {
		if lease.DUID == "" {
			return nil, fmt.Errorf("у аренды нет DUID")
		}
		reservation["duid"] = lease.DUID
		if lease.Type == "IA_PD" {
			if lease.PrefixLen < 1 || lease.PrefixLen > 128 {
				return nil, fmt.Errorf("неверная длина делегированного префикса")
			}
			reservation["prefixes"] = []any{fmt.Sprintf("%s/%d", lease.Address, lease.PrefixLen)}
		} else {
			reservation["ip-addresses"] = []any{lease.Address}
		}
	}
	hostname := lease.Hostname
	if in.ReservationHostname != nil {
		hostname = *in.ReservationHostname
	}
	if hostname != "" {
		reservation["hostname"] = hostname
	}
	for _, scope := range []map[string]any{root, subnet} {
		entries, _ := scope["reservations"].([]any)
		for _, entry := range entries {
			if existing, ok := entry.(map[string]any); ok && (keaReservationConflict(existing, reservation) || keaReservationConflict(existing, map[string]any{"hw-address": lease.MAC, "client-id": lease.ClientID, "duid": lease.DUID})) {
				return nil, fmt.Errorf("для адреса или клиента уже существует резервирование; откройте его свойства")
			}
		}
	}
	reservations, _ := subnet["reservations"].([]any)
	subnet["reservations"] = append(reservations, reservation)
	proposed, e := json.MarshalIndent(doc, "", "  ")
	if e != nil {
		return nil, e
	}
	in.Config = string(proposed) + "\n"
	return h.plan(ctx, in)
}
