package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"sambaadm/internal/audit"
	ldapproto "sambaadm/internal/ldap"
)

var ErrEmployeeInput = errors.New("проверьте параметры мастера")
var ErrEmployeeConflict = errors.New("данные изменились; обновите план перед выполнением")
var ErrEmployeeBusy = errors.New("другой мастер выполняет операцию; повторите запрос позже")
var ErrEmployeeNotFound = errors.New("операция не найдена")

type EmployeeRef struct {
	ID      string `json:"id"`
	DN      string `json:"dn"`
	Name    string `json:"name"`
	Primary bool   `json:"primary,omitempty"`
}
type EmployeeInput struct {
	Scenario     string        `json:"scenario"`
	Login        string        `json:"login"`
	UserID       string        `json:"userId,omitempty"`
	DisplayName  string        `json:"displayName,omitempty"`
	Mail         *string       `json:"mail,omitempty"`
	Department   *string       `json:"department,omitempty"`
	Title        *string       `json:"title,omitempty"`
	Parent       *EmployeeRef  `json:"parent,omitempty"`
	AddGroups    []EmployeeRef `json:"addGroups"`
	RemoveGroups []EmployeeRef `json:"removeGroups"`
	Activate     bool          `json:"activate"`
	ForceChange  bool          `json:"forceChange"`
}
type EmployeePerson struct {
	EmployeeRef
	Login   string        `json:"login"`
	Enabled bool          `json:"enabled"`
	Groups  []EmployeeRef `json:"groups"`
}
type EmployeeStep struct {
	Key      string       `json:"key"`
	Kind     string       `json:"kind"`
	Label    string       `json:"label"`
	Group    *EmployeeRef `json:"group,omitempty"`
	State    string       `json:"state"`
	Attempts int          `json:"attempts"`
	Error    string       `json:"error,omitempty"`
	Detail   string       `json:"detail,omitempty"`
}
type EmployeeChange struct {
	Label  string `json:"label"`
	Before string `json:"before"`
	After  string `json:"after"`
}
type EmployeePlan struct {
	Changes       []EmployeeChange `json:"changes"`
	ID            string           `json:"id"`
	Revision      string           `json:"revision"`
	Scenario      string           `json:"scenario"`
	State         string           `json:"state"`
	Created       time.Time        `json:"created"`
	Updated       time.Time        `json:"updated"`
	Expires       time.Time        `json:"expires"`
	Actor         string           `json:"actor"`
	Input         EmployeeInput    `json:"input"`
	Person        *EmployeePerson  `json:"person,omitempty"`
	Steps         []EmployeeStep   `json:"steps"`
	NeedsPassword bool             `json:"needsPassword"`
	Notices       []string         `json:"notices"`
	Error         string           `json:"error,omitempty"`
}
type EmployeeActor struct{ Name, DN, ID, IP string }
type employeeSnapshot struct {
	Person EmployeePerson
	USN    string
	Values map[string]string
}
type employeeRecord struct {
	Version      int
	BaseDN       string
	Plan         EmployeePlan
	Expected     *employeeSnapshot
	OwnedID      string
	PasswordDone bool
	RevokeDone   bool
}
type EmployeeService struct {
	ldap       *ldapproto.Client
	audit      *audit.Logger
	root       string
	bindUser   string
	revoke     func(string) error
	beforeStep func(string) error
}

func NewEmployeeService(client *ldapproto.Client, logger *audit.Logger, root, bindUser string, revoke func(string) error) *EmployeeService {
	return &EmployeeService{ldap: client, audit: logger, root: root, bindUser: bindUser, revoke: revoke}
}

var employeeAttrs = []string{"objectGUID", "objectSid", "uSNChanged", "sAMAccountName", "cn", "displayName", "userPrincipalName", "userAccountControl", "adminCount", "servicePrincipalName", "pwdLastSet", "primaryGroupID", "mail", "department", "title", "adminDescription"}

func employeeGUID(entry *ldap.Entry) string {
	return hex.EncodeToString(entry.GetRawAttributeValue("objectGUID"))
}
func employeeSameDN(a, b string) bool {
	x, e := ldap.ParseDN(a)
	y, e2 := ldap.ParseDN(b)
	return e == nil && e2 == nil && x.EqualFold(y)
}
func employeeHash(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func employeeKey(kind string, group *EmployeeRef) string {
	if group != nil {
		return kind + ":" + group.ID
	}
	return kind
}
func employeeExtendedDN(ref EmployeeRef) string {
	raw, _ := hex.DecodeString(ref.ID)
	return fmt.Sprintf("<GUID=%08x-%04x-%04x-%x-%x>", binary.LittleEndian.Uint32(raw[:4]), binary.LittleEndian.Uint16(raw[4:6]), binary.LittleEndian.Uint16(raw[6:8]), raw[8:10], raw[10:])
}
func employeeAssertion(ref EmployeeRef, usn string) ([]ldap.Control, error) {
	raw, e := psoGUID(ref.ID)
	if e != nil {
		return nil, e
	}
	if _, e = strconv.ParseUint(usn, 10, 64); e != nil {
		return nil, ErrEmployeeConflict
	}
	filter, e := ldap.CompileFilter("(&(objectGUID=" + ldap.EscapeFilter(string(raw)) + ")(uSNChanged=" + usn + "))")
	if e != nil {
		return nil, e
	}
	return []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(filter.Bytes()))}, nil
}
func (s *EmployeeService) findUser(ctx context.Context, login, id string) (*ldap.Entry, error) {
	filter := "(sAMAccountName=" + ldap.EscapeFilter(login) + ")"
	if id != "" {
		raw, e := psoGUID(id)
		if e != nil {
			return nil, e
		}
		filter = "(objectGUID=" + ldap.EscapeFilter(string(raw)) + ")"
	}
	entries, e := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(&(objectCategory=person)(objectClass=user)" + filter + ")", Attributes: employeeAttrs, MaxEntries: 2})
	if e != nil {
		return nil, e
	}
	if len(entries) == 0 {
		return nil, ErrEmployeeNotFound
	}
	if len(entries) != 1 {
		return nil, ErrEmployeeConflict
	}
	return entries[0], nil
}
func (s *EmployeeService) refByID(ctx context.Context, ref EmployeeRef, kind string, strict bool) (EmployeeRef, string, error) {
	raw, e := psoGUID(ref.ID)
	if e != nil {
		return EmployeeRef{}, "", fmt.Errorf("%w: выберите объект из списка", ErrEmployeeInput)
	}
	filter := "(objectClass=group)"
	if kind == "parent" {
		filter = "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS))"
	}
	entries, e := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(&" + filter + "(objectGUID=" + ldap.EscapeFilter(string(raw)) + "))", Attributes: []string{"objectGUID", "uSNChanged", "cn", "ou", "sAMAccountName", "adminCount", "objectSid"}, MaxEntries: 2})
	if e != nil {
		return EmployeeRef{}, "", e
	}
	if len(entries) != 1 {
		return EmployeeRef{}, "", fmt.Errorf("%w: объект назначения не найден или недоступен", ErrEmployeeConflict)
	}
	entry := entries[0]
	name := entry.GetAttributeValue("sAMAccountName")
	if name == "" {
		name = entry.GetAttributeValue("ou")
	}
	if name == "" {
		name = entry.GetAttributeValue("cn")
	}
	if name == "" {
		name = entry.DN
	}
	if strict && !employeeSameDN(ref.DN, entry.DN) {
		return EmployeeRef{}, "", ErrEmployeeConflict
	}
	if kind == "group" && entry.GetAttributeValue("adminCount") == "1" {
		return EmployeeRef{}, "", fmt.Errorf("%w: защищённые административные группы изменяются отдельными операциями, не кадровым мастером", ErrEmployeeInput)
	}
	return EmployeeRef{ID: employeeGUID(entry), DN: entry.DN, Name: name}, entry.GetAttributeValue("uSNChanged"), nil
}
func (s *EmployeeService) Parent(ctx context.Context, dn string) (EmployeeRef, error) {
	base, e := ldap.ParseDN(s.ldap.BaseDN())
	target, e2 := ldap.ParseDN(dn)
	if e != nil || e2 != nil || (!base.EqualFold(target) && !base.AncestorOfFold(target)) {
		return EmployeeRef{}, fmt.Errorf("%w: выберите подразделение текущего домена", ErrEmployeeInput)
	}
	entry, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=domainDNS))", Attributes: []string{"objectGUID", "cn", "ou"}})
	if e != nil {
		return EmployeeRef{}, e
	}
	if len(entry.GetRawAttributeValue("objectGUID")) != 16 {
		return EmployeeRef{}, ErrEmployeeConflict
	}
	name := entry.GetAttributeValue("ou")
	if name == "" {
		name = entry.GetAttributeValue("cn")
	}
	if name == "" {
		name = entry.DN
	}
	return EmployeeRef{ID: employeeGUID(entry), DN: entry.DN, Name: name}, nil
}
func (s *EmployeeService) Choices(ctx context.Context, kind, q string) ([]EmployeeRef, error) {
	q = strings.TrimSpace(q)
	if len([]rune(q)) < 2 || len(q) > 128 || (kind != "user" && kind != "group") {
		return nil, fmt.Errorf("%w: введите не менее двух символов", ErrEmployeeInput)
	}
	filter := "(&(objectCategory=person)(objectClass=user)(!(adminCount=1))(!(servicePrincipalName=*)))"
	if kind == "group" {
		filter = "(&(objectClass=group)(!(adminCount=1)))"
	}
	entries, e := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(&" + filter + "(|(sAMAccountName=*" + ldap.EscapeFilter(q) + "*)(displayName=*" + ldap.EscapeFilter(q) + "*)(cn=*" + ldap.EscapeFilter(q) + "*)))", Attributes: []string{"objectGUID", "sAMAccountName", "cn"}, MaxEntries: 50})
	if e != nil {
		return nil, fmt.Errorf("поиск не завершён; уточните запрос: %w", e)
	}
	out := []EmployeeRef{}
	for _, entry := range entries {
		if len(entry.GetRawAttributeValue("objectGUID")) != 16 {
			return nil, ErrEmployeeConflict
		}
		name := entry.GetAttributeValue("sAMAccountName")
		if name == "" {
			name = entry.GetAttributeValue("cn")
		}
		out = append(out, EmployeeRef{ID: employeeGUID(entry), Name: name, DN: entry.DN})
	}
	return out, nil
}
func (s *EmployeeService) capture(ctx context.Context, login, id string) (*employeeSnapshot, error) {
	entry, e := s.findUser(ctx, login, id)
	if e != nil {
		return nil, e
	}
	raw := entry.GetRawAttributeValue("objectGUID")
	uac, e := strconv.ParseUint(entry.GetAttributeValue("userAccountControl"), 10, 32)
	if len(raw) != 16 || e != nil || entry.GetAttributeValue("uSNChanged") == "" {
		return nil, fmt.Errorf("не удалось полностью прочитать учётную запись")
	}
	values := map[string]string{}
	for _, attr := range employeeAttrs {
		if attr != "objectGUID" && attr != "objectSid" && attr != "uSNChanged" {
			values[attr] = entry.GetAttributeValue(attr)
		}
	}
	out := &employeeSnapshot{Person: EmployeePerson{EmployeeRef: EmployeeRef{ID: hex.EncodeToString(raw), Name: entry.GetAttributeValue("displayName"), DN: entry.DN}, Login: entry.GetAttributeValue("sAMAccountName"), Enabled: uac&2 == 0, Groups: []EmployeeRef{}}, USN: entry.GetAttributeValue("uSNChanged"), Values: values}
	groups, e := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: "(&(objectClass=group)(member=" + ldap.EscapeFilter(entry.DN) + "))", Attributes: []string{"objectGUID", "sAMAccountName", "cn"}, MaxEntries: 64})
	if e != nil {
		return nil, fmt.Errorf("не удалось прочитать прямые группы пользователя (не более 64): %w", e)
	}
	for _, g := range groups {
		if len(g.GetRawAttributeValue("objectGUID")) != 16 {
			return nil, ErrEmployeeConflict
		}
		out.Person.Groups = append(out.Person.Groups, EmployeeRef{ID: employeeGUID(g), DN: g.DN, Name: g.GetAttributeValue("sAMAccountName")})
	}
	sid := append([]byte{}, entry.GetRawAttributeValue("objectSid")...)
	rid, e := strconv.ParseUint(entry.GetAttributeValue("primaryGroupID"), 10, 32)
	if e != nil || len(sid) < 12 || len(sid) != 8+4*int(sid[1]) {
		return nil, fmt.Errorf("не удалось проверить основную группу пользователя")
	}
	binary.LittleEndian.PutUint32(sid[len(sid)-4:], uint32(rid))
	primary, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{Filter: "(&(objectClass=group)(objectSid=" + ldap.EscapeFilter(string(sid)) + "))", Attributes: []string{"objectGUID", "sAMAccountName"}})
	if e != nil {
		return nil, e
	}
	primaryID := employeeGUID(primary)
	found := false
	for i, g := range out.Person.Groups {
		if g.ID == primaryID {
			out.Person.Groups[i].Primary = true
			found = true
		}
	}
	if !found {
		out.Person.Groups = append(out.Person.Groups, EmployeeRef{ID: primaryID, DN: primary.DN, Name: primary.GetAttributeValue("sAMAccountName"), Primary: true})
	}
	sort.Slice(out.Person.Groups, func(i, j int) bool { return out.Person.Groups[i].ID < out.Person.Groups[j].ID })
	return out, nil
}
func (s *EmployeeService) protect(snap *employeeSnapshot, actor EmployeeActor) error {
	if snap == nil {
		return nil
	}
	v := snap.Values
	bindName := s.bindUser
	if at := strings.LastIndex(bindName, "\\"); at >= 0 {
		bindName = bindName[at+1:]
	}
	if snap.Person.ID == actor.ID || employeeSameDN(snap.Person.DN, actor.DN) || strings.EqualFold(v["sAMAccountName"], bindName) || strings.EqualFold(v["userPrincipalName"], s.bindUser) || employeeSameDN(snap.Person.DN, s.bindUser) || v["adminCount"] == "1" || v["servicePrincipalName"] != "" || strings.EqualFold(v["sAMAccountName"], "krbtgt") {
		return fmt.Errorf("%w: мастер не изменяет текущего оператора, служебные и защищённые учётные записи", ErrEmployeeInput)
	}
	return nil
}
func validateEmployee(in EmployeeInput) error {
	if in.Scenario != "join" && in.Scenario != "transfer" && in.Scenario != "offboard" {
		return fmt.Errorf("%w: неизвестный сценарий", ErrEmployeeInput)
	}
	if in.Login == "" || len([]rune(in.Login)) > 20 || strings.HasSuffix(in.Login, ".") || strings.ContainsAny(in.Login, "/\\[]:;|=,+*?<>\"@") || strings.IndexFunc(in.Login, unicode.IsControl) >= 0 {
		return fmt.Errorf("%w: логин должен содержать 1–20 символов без служебных знаков", ErrEmployeeInput)
	}
	if len(in.AddGroups) > 32 || len(in.RemoveGroups) > 32 {
		return fmt.Errorf("%w: допускается до 32 назначений и 32 снятий групп", ErrEmployeeInput)
	}
	for _, v := range []struct {
		value *string
		max   int
	}{{&in.DisplayName, 64}, {in.Mail, 256}, {in.Department, 64}, {in.Title, 64}} {
		if v.value != nil && (!utf8.ValidString(*v.value) || len([]rune(*v.value)) > v.max || strings.ContainsAny(*v.value, "\x00\r\n")) {
			return fmt.Errorf("%w: некорректная длина или символы в свойствах сотрудника", ErrEmployeeInput)
		}
	}
	if in.Mail != nil && *in.Mail != "" {
		a, e := mail.ParseAddress(*in.Mail)
		if e != nil || a.Address != *in.Mail {
			return fmt.Errorf("%w: некорректный адрес почты", ErrEmployeeInput)
		}
	}
	if in.Scenario != "join" && (in.Activate || in.ForceChange) {
		return fmt.Errorf("%w: включение записи и начальный пароль относятся только к приёму", ErrEmployeeInput)
	}
	if in.Scenario == "offboard" && (len(in.AddGroups) > 0 || in.Mail != nil || in.Department != nil || in.Title != nil) {
		return fmt.Errorf("%w: увольнение не назначает группы и не меняет профиль", ErrEmployeeInput)
	}
	if in.Scenario == "join" && len(in.RemoveGroups) > 0 {
		return fmt.Errorf("%w: приём не снимает группы", ErrEmployeeInput)
	}
	return nil
}
func (s *EmployeeService) normalize(ctx context.Context, in *EmployeeInput, strict bool) error {
	in.Login = strings.TrimSpace(in.Login)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if in.DisplayName == "" && in.Scenario == "join" {
		in.DisplayName = in.Login
	}
	if e := validateEmployee(*in); e != nil {
		return e
	}
	if in.Parent != nil {
		ref, _, e := s.refByID(ctx, *in.Parent, "parent", strict)
		if e != nil {
			return e
		}
		in.Parent = &ref
	}
	if in.Scenario == "join" && in.Parent == nil {
		ref, e := s.Parent(ctx, DefaultUsersOU("", s.ldap.BaseDN()))
		if e != nil {
			return e
		}
		in.Parent = &ref
	}
	seen := map[string]bool{}
	for _, list := range []*[]EmployeeRef{&in.AddGroups, &in.RemoveGroups} {
		for i, ref := range *list {
			actual, _, e := s.refByID(ctx, ref, "group", strict)
			if e != nil {
				return e
			}
			if seen[actual.ID] {
				return fmt.Errorf("%w: группа указана повторно или одновременно добавляется и снимается", ErrEmployeeInput)
			}
			seen[actual.ID] = true
			(*list)[i] = actual
		}
	}
	return nil
}
func employeeGroupSet(snap *employeeSnapshot) map[string]EmployeeRef {
	out := map[string]EmployeeRef{}
	if snap != nil {
		for _, g := range snap.Person.Groups {
			out[g.ID] = g
		}
	}
	return out
}
func (s *EmployeeService) pending(r *employeeRecord, snap *employeeSnapshot) ([]EmployeeStep, error) {
	in := r.Plan.Input
	steps := []EmployeeStep{}
	add := func(kind, label string, g *EmployeeRef) {
		steps = append(steps, EmployeeStep{Key: employeeKey(kind, g), Kind: kind, Label: label, Group: g, State: "pending"})
	}
	if in.Scenario == "join" && snap == nil {
		add("create", "Создать отключённую учётную запись", nil)
	}
	if snap != nil {
		if in.Scenario == "offboard" && snap.Person.Enabled || in.Scenario == "join" && !r.PasswordDone && snap.Person.Enabled {
			add("disable", "Отключить учётную запись", nil)
		}
	}
	if in.Scenario == "offboard" && !r.RevokeDone {
		add("revoke", "Завершить сессии sambaadm на этом сервере", nil)
	}
	groups := employeeGroupSet(snap)
	for _, g := range in.RemoveGroups {
		if existing, ok := groups[g.ID]; ok {
			if existing.Primary {
				return nil, fmt.Errorf("%w: основная группа не снимается мастером", ErrEmployeeInput)
			}
			group := g
			add("remove_group", "Снять группу «"+g.Name+"»", &group)
		}
	}
	if snap != nil && in.Parent != nil {
		dn, e := ldap.ParseDN(snap.Person.DN)
		if e != nil {
			return nil, e
		}
		parent := &ldap.DN{RDNs: dn.RDNs[1:]}
		target, e := ldap.ParseDN(in.Parent.DN)
		if e != nil {
			return nil, e
		}
		if !parent.EqualFold(target) {
			add("move", "Переместить в «"+in.Parent.Name+"»", nil)
		}
	}
	if in.Scenario != "offboard" && snap != nil {
		changed := false
		for _, f := range []struct {
			key   string
			value *string
		}{{"mail", in.Mail}, {"department", in.Department}, {"title", in.Title}} {
			changed = changed || f.value != nil && snap.Values[f.key] != *f.value
		}
		if changed {
			add("profile", "Обновить должность, отдел и почту", nil)
		}
	}
	for _, g := range in.AddGroups {
		if _, ok := groups[g.ID]; !ok {
			group := g
			add("add_group", "Назначить группу «"+g.Name+"»", &group)
		}
	}
	if in.Scenario == "join" && !r.PasswordDone {
		add("password", "Задать начальный пароль"+map[bool]string{true: " со сменой при первом входе", false: ""}[in.ForceChange], nil)
	}
	if in.Scenario == "join" && in.Activate && (snap == nil || !snap.Person.Enabled || !r.PasswordDone) {
		add("enable", "Включить учётную запись после успешных шагов", nil)
	}
	if in.Scenario == "join" && !in.Activate && snap != nil && snap.Person.Enabled && r.PasswordDone {
		add("disable", "Оставить учётную запись отключённой", nil)
	}
	return steps, nil
}
func (s *EmployeeService) recordSnapshot(ctx context.Context, r *employeeRecord) (*employeeSnapshot, error) {
	id := r.Plan.Input.UserID
	if r.OwnedID != "" {
		id = r.OwnedID
	}
	snap, e := s.capture(ctx, r.Plan.Input.Login, id)
	if errors.Is(e, ErrEmployeeNotFound) && r.Plan.Scenario == "join" && r.OwnedID == "" {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if r.Plan.Scenario == "join" && r.OwnedID == "" {
		if snap.Values["adminDescription"] != "sambaadm.employee:"+r.Plan.ID {
			return nil, fmt.Errorf("%w: логин уже занят другой учётной записью", ErrEmployeeConflict)
		}
		r.OwnedID = snap.Person.ID
	}
	return snap, nil
}
func (s *EmployeeService) Preview(ctx context.Context, in EmployeeInput, actor EmployeeActor) (out *EmployeePlan, err error) {
	unlock, e := s.lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	if e = s.normalize(ctx, &in, true); e != nil {
		return nil, e
	}
	r := &employeeRecord{Version: 1, BaseDN: s.ldap.BaseDN(), Plan: EmployeePlan{ID: strings.ReplaceAll(uuid.NewString(), "-", ""), Scenario: in.Scenario, Input: in, State: "ready", Created: time.Now().UTC(), Actor: actor.Name, Notices: []string{"Изменения выполняются по шагам, а не одной транзакцией. После ошибки успешные шаги сохраняются; продолжение требует нового просмотра плана."}}}
	var snap *employeeSnapshot
	if in.Scenario == "join" {
		_, e = s.findUser(ctx, in.Login, "")
		if e == nil {
			return nil, fmt.Errorf("%w: такой логин уже существует", ErrEmployeeInput)
		}
		if !errors.Is(e, ErrEmployeeNotFound) {
			return nil, e
		}
		r.Plan.Notices = append(r.Plan.Notices, "Запись создаётся отключённой. Пароль задаётся после групп с учётом PSO; при ошибке запись не включается. Пароль не сохраняется в плане или журнале.")
	} else {
		snap, e = s.capture(ctx, in.Login, in.UserID)
		if e != nil {
			return nil, e
		}
		if e = s.protect(snap, actor); e != nil {
			return nil, e
		}
		r.Plan.Input.UserID = snap.Person.ID
		r.Plan.Input.Login = snap.Person.Login
	}
	if in.Scenario == "offboard" {
		r.Plan.Notices = append(r.Plan.Notices, "Отзываются сессии на этом сервере sambaadm. Уже выданные билеты Kerberos и открытые сеансы на рабочих станциях могут продолжать действовать; их завершение здесь не подтверждается.")
	}
	steps, e := s.pending(r, snap)
	if e != nil {
		return nil, e
	}
	r.Expected = snap
	r.Plan.Steps = steps
	s.refreshPlan(r, snap)
	if e = s.save(r); e != nil {
		return nil, e
	}
	s.event(actor, "employee.preview", r.Plan.ID, nil)
	return &r.Plan, nil
}
func (s *EmployeeService) refreshPlan(r *employeeRecord, snap *employeeSnapshot) {
	r.Plan.Changes = []EmployeeChange{}
	in := r.Plan.Input
	if snap == nil && in.Scenario == "join" {
		r.Plan.Changes = append(r.Plan.Changes, EmployeeChange{Label: "ФИО", After: in.DisplayName})
	}
	for _, f := range []struct {
		key, label string
		value      *string
	}{{"mail", "Почта", in.Mail}, {"department", "Отдел", in.Department}, {"title", "Должность", in.Title}} {
		if f.value != nil {
			old := ""
			if snap != nil {
				old = snap.Values[f.key]
			}
			if old != *f.value {
				r.Plan.Changes = append(r.Plan.Changes, EmployeeChange{Label: f.label, Before: old, After: *f.value})
			}
		}
	}
	if in.Parent != nil {
		old := ""
		if snap != nil {
			dn, e := ldap.ParseDN(snap.Person.DN)
			if e == nil && len(dn.RDNs) > 1 {
				parent := (&ldap.DN{RDNs: dn.RDNs[1:]}).String()
				if !employeeSameDN(parent, in.Parent.DN) {
					old = cnFromDN(parent)
				} else {
					old = in.Parent.Name
				}
			}
		}
		if old != in.Parent.Name {
			r.Plan.Changes = append(r.Plan.Changes, EmployeeChange{Label: "Подразделение", Before: old, After: in.Parent.Name})
		}
	}

	r.Plan.Person = nil
	if snap != nil {
		person := snap.Person
		r.Plan.Person = &person
	}
	r.Plan.NeedsPassword = false
	for _, step := range r.Plan.Steps {
		if step.Kind == "password" && step.State != "done" && step.State != "skipped" {
			r.Plan.NeedsPassword = true
		}
	}
	r.Plan.Expires = time.Now().UTC().Add(15 * time.Minute)
}
func (s *EmployeeService) Review(ctx context.Context, id, revision string, actor EmployeeActor) (*EmployeePlan, error) {
	unlock, e := s.lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	r, e := s.load(id)
	if e != nil {
		return nil, e
	}
	if r.Plan.Revision != revision {
		return nil, ErrEmployeeConflict
	}
	if r.Plan.State == "completed" {
		return &r.Plan, nil
	}
	snap, e := s.recordSnapshot(ctx, r)
	if e != nil {
		return nil, e
	}
	if e = s.protect(snap, actor); e != nil {
		return nil, e
	}
	if e = s.normalize(ctx, &r.Plan.Input, false); e != nil {
		return nil, e
	}
	needed, e := s.pending(r, snap)
	if e != nil {
		return nil, e
	}
	old := map[string]EmployeeStep{}
	for _, step := range r.Plan.Steps {
		old[step.Key] = step
	}
	keys := map[string]bool{}
	for i, step := range needed {
		keys[step.Key] = true
		if previous, ok := old[step.Key]; ok {
			needed[i].Attempts = previous.Attempts
			if previous.Error != "" {
				needed[i].Detail = "Предыдущая попытка: " + previous.Error
			} else if previous.State == "running" {
				needed[i].Detail = "Ранее выполнение прервано; результат будет проверен или операция повторена после подтверждения."
			}
		}
	}
	history := []EmployeeStep{}
	for _, step := range r.Plan.Steps {
		if !keys[step.Key] {
			if step.State != "done" {
				step.State = "skipped"
				step.Error = ""
				step.Detail = "Нужное состояние подтверждено; повтор не требуется."
			}
			history = append(history, step)
		}
	}
	r.Plan.Steps = append(history, needed...)
	r.Expected = snap
	r.Plan.State = "ready"
	r.Plan.Error = ""
	s.refreshPlan(r, snap)
	if e = s.save(r); e != nil {
		return nil, e
	}
	s.event(actor, "employee.review", id, nil)
	return &r.Plan, nil
}
func (s *EmployeeService) event(actor EmployeeActor, action, target string, err error) {
	if s.audit == nil {
		return
	}
	if err != nil {
		s.audit.Failure(actor.Name, action, target, actor.IP, err)
	} else {
		s.audit.Success(actor.Name, action, target, actor.IP)
	}
}
