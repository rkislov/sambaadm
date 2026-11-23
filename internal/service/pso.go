package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

var ErrPSOInput = errors.New("некорректные параметры PSO")
var ErrPSOConflict = errors.New("PSO изменена другим администратором; обновите данные")
var ErrPSONotFound = errors.New("PSO не найдена или недоступна")

type PSOSubject struct {
	ID   string `json:"id"`
	DN   string `json:"dn"`
	Name string `json:"name"`
	Kind string `json:"kind"`
}
type PSOValues struct {
	PasswordPolicyValues
	Precedence           int  `json:"precedence"`
	ReversibleEncryption bool `json:"reversibleEncryption"`
}
type PSO struct {
	PSOValues
	ID          string       `json:"id"`
	DN          string       `json:"dn"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Revision    string       `json:"revision"`
	Subjects    []PSOSubject `json:"subjects"`
}
type PSOChange struct {
	PSOValues
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Revision    string       `json:"revision"`
	Subjects    []PSOSubject `json:"subjects"`
}
type EffectivePasswordPolicy struct {
	Login       string                `json:"login"`
	DN          string                `json:"dn"`
	Controller  string                `json:"controller"`
	ObservedAt  time.Time             `json:"observedAt"`
	Source      string                `json:"source"`
	Policy      *PSO                  `json:"pso,omitempty"`
	Domain      *DomainPasswordPolicy `json:"domain,omitempty"`
	Explanation string                `json:"explanation"`
	Limitations []string              `json:"limitations"`
}

var psoAttrs = []string{"cn", "description", "objectGUID", "uSNChanged", "msDS-PasswordSettingsPrecedence", "msDS-PasswordReversibleEncryptionEnabled", "msDS-PasswordHistoryLength", "msDS-PasswordComplexityEnabled", "msDS-MinimumPasswordLength", "msDS-MinimumPasswordAge", "msDS-MaximumPasswordAge", "msDS-LockoutThreshold", "msDS-LockoutObservationWindow", "msDS-LockoutDuration", "msDS-PSOAppliesTo"}

func (s *DomainService) psoBase() string {
	return "CN=Password Settings Container,CN=System," + s.ldap.BaseDN()
}
func psoGUID(id string) ([]byte, error) {
	raw, e := hex.DecodeString(id)
	if e != nil || len(raw) != 16 {
		return nil, fmt.Errorf("%w: неверный идентификатор объекта", ErrPSOInput)
	}
	return raw, nil
}
func psoRevision(e *ldap.Entry) string {
	values := []string{e.DN}
	for _, attr := range psoAttrs {
		v := append([]string{}, e.GetAttributeValues(attr)...)
		if attr == "objectGUID" {
			v = []string{hex.EncodeToString(e.GetRawAttributeValue(attr))}
		}
		sort.Strings(v)
		values = append(values, attr)
		values = append(values, v...)
	}
	raw, _ := json.Marshal(values)
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func parsePSO(e *ldap.Entry) (*PSO, error) {
	p := &PSO{ID: hex.EncodeToString(e.GetRawAttributeValue("objectGUID")), DN: e.DN, Name: e.GetAttributeValue("cn"), Description: e.GetAttributeValue("description"), Revision: psoRevision(e), Subjects: []PSOSubject{}}
	if len(e.GetRawAttributeValue("objectGUID")) != 16 || e.GetAttributeValue("uSNChanged") == "" || p.Name == "" {
		return nil, fmt.Errorf("PSO прочитана не полностью: нужны имя, GUID и версия объекта")
	}
	for _, a := range e.Attributes {
		if strings.HasPrefix(strings.ToLower(a.Name), "msds-psoappliesto;range=") {
			return nil, fmt.Errorf("список назначений PSO возвращён частично; редактирование остановлено")
		}
	}
	for _, f := range []struct {
		attr  string
		value *int
	}{{"msDS-PasswordSettingsPrecedence", &p.Precedence}, {"msDS-PasswordHistoryLength", &p.HistoryLength}, {"msDS-MinimumPasswordLength", &p.MinLength}, {"msDS-LockoutThreshold", &p.LockoutThreshold}} {
		n, err := strconv.Atoi(e.GetAttributeValue(f.attr))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("не удалось прочитать параметр PSO %s", f.attr)
		}
		*f.value = n
	}
	for _, f := range []struct {
		attr  string
		value *bool
	}{{"msDS-PasswordReversibleEncryptionEnabled", &p.ReversibleEncryption}, {"msDS-PasswordComplexityEnabled", &p.Complexity}} {
		v := e.GetAttributeValue(f.attr)
		if !strings.EqualFold(v, "TRUE") && !strings.EqualFold(v, "FALSE") {
			return nil, fmt.Errorf("не удалось прочитать параметр PSO %s", f.attr)
		}
		*f.value = strings.EqualFold(v, "TRUE")
	}
	for _, f := range []struct {
		attr  string
		value *float64
		unit  float64
		never bool
	}{{"msDS-MinimumPasswordAge", &p.MinAgeDays, 864000000000, false}, {"msDS-MaximumPasswordAge", &p.MaxAgeDays, 864000000000, true}, {"msDS-LockoutObservationWindow", &p.LockoutWindowMinutes, 600000000, false}, {"msDS-LockoutDuration", &p.LockoutDurationMinutes, 600000000, false}} {
		v, err := passwordInterval(e.GetAttributeValue(f.attr), f.unit, f.never)
		if err != nil {
			return nil, fmt.Errorf("не удалось прочитать интервал PSO %s", f.attr)
		}
		*f.value = v
	}
	targets := e.GetAttributeValues("msDS-PSOAppliesTo")
	if len(targets) > 256 {
		return nil, fmt.Errorf("PSO содержит более 256 назначений; список слишком велик для редактора")
	}
	for _, dn := range targets {
		p.Subjects = append(p.Subjects, PSOSubject{DN: dn})
	}
	return p, nil
}
func (s *DomainService) psoEntry(ctx context.Context, id string) (*ldap.Entry, error) {
	raw, err := psoGUID(id)
	if err != nil {
		return nil, err
	}
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: s.psoBase(), Filter: "(&(objectClass=msDS-PasswordSettings)(objectGUID=" + ldap.EscapeFilter(string(raw)) + "))", Attributes: psoAttrs, MaxEntries: 2})
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать PSO: %w", err)
	}
	if len(entries) != 1 {
		return nil, ErrPSONotFound
	}
	return entries[0], nil
}
func (s *DomainService) ListPSOs(ctx context.Context) ([]PSO, error) {
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{BaseDN: s.psoBase(), Filter: "(objectClass=msDS-PasswordSettings)", Attributes: psoAttrs, MaxEntries: 2000})
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать PSO; проверьте уровень домена и права служебной записи: %w", err)
	}
	out := []PSO{}
	for _, e := range entries {
		p, err := parsePSO(e)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Precedence != out[j].Precedence {
			return out[i].Precedence < out[j].Precedence
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}
func psoSubject(e *ldap.Entry) (PSOSubject, error) {
	out := PSOSubject{ID: hex.EncodeToString(e.GetRawAttributeValue("objectGUID")), DN: e.DN, Name: e.GetAttributeValue("sAMAccountName")}
	if len(e.GetRawAttributeValue("objectGUID")) != 16 || out.Name == "" {
		return out, fmt.Errorf("не удалось подтвердить получателя PSO")
	}
	for _, c := range e.GetAttributeValues("objectClass") {
		if strings.EqualFold(c, "computer") {
			return out, fmt.Errorf("PSO нельзя назначить компьютеру")
		}
		if strings.EqualFold(c, "group") {
			flags, err := strconv.ParseInt(e.GetAttributeValue("groupType"), 10, 64)
			if err != nil || uint32(flags)&0x8000000f != 0x80000002 {
				return out, fmt.Errorf("PSO можно назначить только глобальной группе безопасности")
			}
			out.Kind = "group"
		}
	}
	if out.Kind == "" {
		hasUser := false
		hasPerson := false
		for _, c := range e.GetAttributeValues("objectClass") {
			hasUser = hasUser || strings.EqualFold(c, "user")
			hasPerson = hasPerson || strings.EqualFold(c, "person")
		}
		if !hasUser || !hasPerson {
			return out, fmt.Errorf("PSO можно назначить пользователю или глобальной группе безопасности")
		}
		out.Kind = "user"
	}
	return out, nil
}
func (s *DomainService) subjectByDN(ctx context.Context, dn string) (PSOSubject, error) {
	return s.lookupPSOSubject(ctx, dn, true)
}
func (s *DomainService) lookupPSOSubject(ctx context.Context, dn string, eligible bool) (PSOSubject, error) {
	base, err := ldap.ParseDN(s.ldap.BaseDN())
	if err != nil {
		return PSOSubject{}, err
	}
	target, err := ldap.ParseDN(dn)
	if err != nil || !base.AncestorOfFold(target) {
		return PSOSubject{}, fmt.Errorf("%w: получатель должен находиться в этом домене", ErrPSOInput)
	}
	e, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"objectGUID", "sAMAccountName", "cn", "objectClass", "groupType"}})
	if err != nil {
		return PSOSubject{}, fmt.Errorf("не удалось проверить получателя %s: %w", dn, err)
	}
	sub, err := psoSubject(e)
	if err != nil && !eligible && len(e.GetRawAttributeValue("objectGUID")) == 16 {
		name := e.GetAttributeValue("sAMAccountName")
		if name == "" {
			name = e.GetAttributeValue("cn")
		}
		return PSOSubject{ID: hex.EncodeToString(e.GetRawAttributeValue("objectGUID")), DN: e.DN, Name: name, Kind: "unsupported"}, nil
	}
	return sub, err
}
func (s *DomainService) GetPSO(ctx context.Context, id string) (*PSO, error) {
	entry, err := s.psoEntry(ctx, id)
	if err != nil {
		return nil, err
	}
	p, err := parsePSO(entry)
	if err != nil {
		return nil, err
	}
	for i, sub := range p.Subjects {
		p.Subjects[i], err = s.lookupPSOSubject(ctx, sub.DN, false)
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}
func (s *DomainService) PSOSubjects(ctx context.Context, q, kind string) ([]PSOSubject, error) {
	q = strings.TrimSpace(q)
	if len([]rune(q)) < 2 || len(q) > 128 || (kind != "user" && kind != "group") {
		return nil, fmt.Errorf("%w: задайте тип получателя и не менее двух символов поиска", ErrPSOInput)
	}
	filter := "(&(objectCategory=person)(objectClass=user))"
	if kind == "group" {
		filter = "(&(objectClass=group)(groupType=-2147483646))"
	}
	filter = "(&" + filter + "(|(sAMAccountName=*" + ldap.EscapeFilter(q) + "*)(cn=*" + ldap.EscapeFilter(q) + "*)))"
	entries, err := s.ldap.Search(ctx, ldapproto.SearchOptions{Filter: filter, Attributes: []string{"objectGUID", "sAMAccountName", "objectClass", "groupType"}, MaxEntries: 100})
	if err != nil {
		return nil, fmt.Errorf("поиск получателей не завершён; уточните запрос: %w", err)
	}
	out := []PSOSubject{}
	for _, e := range entries {
		sub, err := psoSubject(e)
		if err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, nil
}
func validatePSO(in PSOChange) error {
	if in.Precedence < 1 || int64(in.Precedence) > 2147483647 || len(in.Subjects) > 256 || len([]rune(in.Description)) > 1024 || strings.ContainsAny(in.Description, "\x00\r\n") {
		return fmt.Errorf("%w: приоритет 1–2147483647, до 256 получателей и описание до 1024 символов", ErrPSOInput)
	}
	for _, f := range []struct{ value, unit float64 }{{in.MinAgeDays, 864000000000}, {in.MaxAgeDays, 864000000000}, {in.LockoutDurationMinutes, 600000000}, {in.LockoutWindowMinutes, 600000000}} {
		if f.value > 0 && math.Round(f.value*f.unit) == 0 {
			return fmt.Errorf("%w: слишком малый интервал, задайте большее значение", ErrPSOInput)
		}
	}
	if err := validatePasswordPolicy(in.PasswordPolicyValues); err != nil {
		return fmt.Errorf("%w: проверьте длину, историю и сроки; максимальный срок должен превышать минимальный, а длительность блокировки — покрывать окно ошибок (0 означает отсутствие срока)", ErrPSOInput)
	}
	return nil
}
func (s *DomainService) requirePSOLevel(ctx context.Context) error {
	entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: s.ldap.BaseDN(), Scope: ldapproto.ScopeBase(), Filter: "(objectClass=domainDNS)", Attributes: []string{"msDS-Behavior-Version"}})
	if err != nil {
		return fmt.Errorf("не удалось проверить функциональный уровень домена: %w", err)
	}
	n, err := strconv.Atoi(entry.GetAttributeValue("msDS-Behavior-Version"))
	if err != nil || n < 3 {
		return fmt.Errorf("%w: для PSO нужен функциональный уровень домена Windows Server 2008 или выше", ErrPSOInput)
	}
	return nil
}
func verifyPSOResult(p *PSO, in PSOChange) error {
	expected := in.PSOValues
	for _, f := range []struct {
		v    *float64
		unit float64
	}{{&expected.MinAgeDays, 864000000000}, {&expected.MaxAgeDays, 864000000000}, {&expected.LockoutDurationMinutes, 600000000}, {&expected.LockoutWindowMinutes, 600000000}} {
		*f.v = math.Round(*f.v*f.unit) / f.unit
	}
	ids := func(subjects []PSOSubject) string {
		values := []string{}
		for _, s := range subjects {
			values = append(values, s.ID)
		}
		sort.Strings(values)
		return strings.Join(values, ",")
	}
	if p.PSOValues != expected || p.Description != in.Description || ids(p.Subjects) != ids(in.Subjects) {
		return fmt.Errorf("результат изменения PSO отличается от отправленных параметров; перечитайте данные перед повторной операцией")
	}
	return nil
}
func psoUpdates(in PSOChange) map[string][]string {
	b := func(v bool) string {
		if v {
			return "TRUE"
		}
		return "FALSE"
	}
	out := map[string][]string{"description": {}, "msDS-PasswordSettingsPrecedence": {strconv.Itoa(in.Precedence)}, "msDS-PasswordHistoryLength": {strconv.Itoa(in.HistoryLength)}, "msDS-MinimumPasswordLength": {strconv.Itoa(in.MinLength)}, "msDS-LockoutThreshold": {strconv.Itoa(in.LockoutThreshold)}, "msDS-PasswordComplexityEnabled": {b(in.Complexity)}, "msDS-PasswordReversibleEncryptionEnabled": {b(in.ReversibleEncryption)}, "msDS-PSOAppliesTo": {}}
	if in.Description != "" {
		out["description"] = []string{in.Description}
	}
	for _, sub := range in.Subjects {
		out["msDS-PSOAppliesTo"] = append(out["msDS-PSOAppliesTo"], sub.DN)
	}
	for _, f := range []struct {
		attr    string
		v, unit float64
	}{{"msDS-MinimumPasswordAge", in.MinAgeDays, 864000000000}, {"msDS-MaximumPasswordAge", in.MaxAgeDays, 864000000000}, {"msDS-LockoutDuration", in.LockoutDurationMinutes, 600000000}, {"msDS-LockoutObservationWindow", in.LockoutWindowMinutes, 600000000}} {
		n := int64(-math.Round(f.v * f.unit))
		if f.attr == "msDS-MaximumPasswordAge" && f.v == 0 {
			n = math.MinInt64
		}
		out[f.attr] = []string{strconv.FormatInt(n, 10)}
	}
	return out
}
func (s *DomainService) validatePSOSubjects(ctx context.Context, in *PSOChange) error {
	seen := map[string]bool{}
	for i, sub := range in.Subjects {
		actual, err := s.subjectByDN(ctx, sub.DN)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrPSOInput, err)
		}
		if actual.ID != sub.ID {
			return fmt.Errorf("%w: получатель изменился, выберите его заново", ErrPSOConflict)
		}
		if seen[actual.ID] {
			return fmt.Errorf("%w: получатель указан повторно", ErrPSOInput)
		}
		seen[actual.ID] = true
		in.Subjects[i] = actual
	}
	return nil
}
func (s *DomainService) psoAudit(actor, op, dn, ip string, err error) {
	if s.audit == nil {
		return
	}
	if err != nil {
		s.audit.Failure(actor, op, dn, ip, err)
	} else {
		s.audit.Success(actor, op, dn, ip)
	}
}
func psoAssertion(entry *ldap.Entry) ([]ldap.Control, error) {
	usn := entry.GetAttributeValue("uSNChanged")
	if _, err := strconv.ParseUint(usn, 10, 64); err != nil {
		return nil, fmt.Errorf("не удалось подтвердить версию PSO")
	}
	guid := entry.GetRawAttributeValue("objectGUID")
	if len(guid) != 16 {
		return nil, fmt.Errorf("не удалось подтвердить GUID PSO")
	}
	filter, err := ldap.CompileFilter("(&(objectGUID=" + ldap.EscapeFilter(string(guid)) + ")(uSNChanged=" + ldap.EscapeFilter(usn) + "))")
	if err != nil {
		return nil, err
	}
	return []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(filter.Bytes()))}, nil
}
func (s *DomainService) CreatePSO(ctx context.Context, in PSOChange, actor, ip string) (out *PSO, err error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len([]rune(in.Name)) > 64 || strings.ContainsAny(in.Name, "\x00\r\n") {
		return nil, fmt.Errorf("%w: имя PSO должно содержать 1–64 символа", ErrPSOInput)
	}
	if err = validatePSO(in); err != nil {
		return nil, err
	}
	if err = s.validatePSOSubjects(ctx, &in); err != nil {
		return nil, err
	}
	if err = s.requirePSOLevel(ctx); err != nil {
		return nil, err
	}
	dn := BuildDN("CN", in.Name, s.psoBase())
	defer func() { s.psoAudit(actor, "pso.create", dn, ip, err) }()
	attrs := []ldap.Attribute{{Type: "objectClass", Vals: []string{"top", "msDS-PasswordSettings"}}, {Type: "cn", Vals: []string{in.Name}}}
	for k, v := range psoUpdates(in) {
		if len(v) > 0 {
			attrs = append(attrs, ldap.Attribute{Type: k, Vals: v})
		}
	}
	if err = s.ldap.Add(ctx, dn, attrs); err != nil {
		return nil, fmt.Errorf("не удалось создать PSO: %w", err)
	}
	e, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=msDS-PasswordSettings)", Attributes: psoAttrs})
	if err != nil {
		return nil, fmt.Errorf("PSO создана, но проверка результата не удалась; перечитайте список: %w", err)
	}
	p, err := parsePSO(e)
	if err != nil {
		return nil, fmt.Errorf("PSO создана, но параметры прочитаны не полностью; перечитайте список: %w", err)
	}
	out, err = s.GetPSO(ctx, p.ID)
	if err == nil {
		err = verifyPSOResult(out, in)
	}
	if err != nil {
		return nil, fmt.Errorf("PSO создана, но результат не подтверждён; перечитайте список: %w", err)
	}
	return out, nil
}
func (s *DomainService) UpdatePSO(ctx context.Context, id string, in PSOChange, actor, ip string) (out *PSO, err error) {
	if in.Revision == "" {
		return nil, fmt.Errorf("%w: нужна версия PSO", ErrPSOInput)
	}
	if err = validatePSO(in); err != nil {
		return nil, err
	}
	entry, err := s.psoEntry(ctx, id)
	if err != nil {
		return nil, err
	}
	defer func() { s.psoAudit(actor, "pso.update", entry.DN, ip, err) }()
	if psoRevision(entry) != in.Revision {
		return nil, ErrPSOConflict
	}
	if in.Name != "" && in.Name != entry.GetAttributeValue("cn") {
		return nil, fmt.Errorf("%w: имя существующей PSO не изменяется этим редактором", ErrPSOInput)
	}
	if err = s.validatePSOSubjects(ctx, &in); err != nil {
		return nil, err
	}
	controls, err := psoAssertion(entry)
	if err != nil {
		return nil, err
	}
	req := ldap.NewModifyRequest(entry.DN, controls)
	updates := psoUpdates(in)
	if len(entry.GetAttributeValues("description")) > 1 {
		if in.Description != entry.GetAttributeValue("description") {
			return nil, fmt.Errorf("%w: многозначное описание PSO нельзя заменить одной строкой; остальные параметры можно изменить с сохранением описания", ErrPSOInput)
		}
		delete(updates, "description")
	}
	for k, v := range updates {
		old := append([]string{}, entry.GetAttributeValues(k)...)
		next := append([]string{}, v...)
		sort.Strings(old)
		sort.Strings(next)
		if strings.Join(old, "\x00") != strings.Join(next, "\x00") {
			req.Replace(k, v)
		}
	}
	if len(req.Changes) > 0 {
		if err = s.ldap.Modify(ctx, req); err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultAssertionFailed) {
				return nil, ErrPSOConflict
			}
			return nil, fmt.Errorf("не удалось сохранить PSO: %w", err)
		}
	}
	out, err = s.GetPSO(ctx, id)
	if err == nil {
		err = verifyPSOResult(out, in)
	}
	if err != nil {
		return nil, fmt.Errorf("результат сохранения PSO не подтверждён; перечитайте данные: %w", err)
	}
	return out, nil
}
func (s *DomainService) DeletePSO(ctx context.Context, id, revision, actor, ip string) (err error) {
	if revision == "" {
		return fmt.Errorf("%w: нужна версия PSO", ErrPSOInput)
	}
	entry, err := s.psoEntry(ctx, id)
	if err != nil {
		return err
	}
	defer func() { s.psoAudit(actor, "pso.delete", entry.DN, ip, err) }()
	if psoRevision(entry) != revision {
		return ErrPSOConflict
	}
	controls, err := psoAssertion(entry)
	if err != nil {
		return err
	}
	conn, err := s.ldap.Conn(ctx)
	if err != nil {
		return err
	}
	if err = conn.Del(ldap.NewDelRequest(entry.DN, controls)); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultAssertionFailed) {
			return ErrPSOConflict
		}
		return fmt.Errorf("не удалось удалить PSO: %w", err)
	}
	_, err = s.psoEntry(ctx, id)
	if errors.Is(err, ErrPSONotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("PSO удалена, но проверка результата не удалась: %w", err)
	}
	return fmt.Errorf("удаление PSO не подтверждено; перечитайте список")
}
func (s *DomainService) EffectivePasswordPolicy(ctx context.Context, login, controller string) (*EffectivePasswordPolicy, error) {
	user, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{Filter: "(&(objectCategory=person)(objectClass=user)(sAMAccountName=" + ldap.EscapeFilter(login) + "))", Attributes: []string{"sAMAccountName", "msDS-ResultantPSO", "objectGUID"}})
	if err != nil {
		return nil, fmt.Errorf("не удалось получить результирующую политику пользователя: %w", err)
	}
	out := &EffectivePasswordPolicy{Login: user.GetAttributeValue("sAMAccountName"), DN: user.DN, Controller: controller, ObservedAt: time.Now().UTC(), Limitations: []string{"Результат прочитан с указанного DC; после изменения назначений и членства учитывайте время репликации.", "Используется msDS-ResultantPSO контроллера, а не локальная модель приоритетов. Неполные права служебной записи могут скрыть PSO или её параметры."}}
	dn := user.GetAttributeValue("msDS-ResultantPSO")
	if dn == "" {
		out.Domain, err = s.PasswordPolicy(ctx)
		if err != nil {
			return nil, err
		}
		out.Source = "domain"
		out.Explanation = "DC не вернул результирующую PSO. Показана общая доменная политика; при неполных правах чтения PSO может быть скрыта."
		return out, nil
	}
	base, e := ldap.ParseDN(s.psoBase())
	target, e2 := ldap.ParseDN(dn)
	if e != nil || e2 != nil || !base.AncestorOfFold(target) {
		return nil, fmt.Errorf("DC вернул PSO вне контейнера парольных политик домена")
	}
	entry, err := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=msDS-PasswordSettings)", Attributes: psoAttrs})
	if err != nil {
		return nil, fmt.Errorf("DC выбрал PSO, но прочитать её параметры не удалось; общая политика не подставляется: %w", err)
	}
	out.Policy, err = parsePSO(entry)
	if err != nil {
		return nil, err
	}
	out.Source = "pso"
	out.Explanation = "Эту PSO выбрал контроллер домена. Прямые назначения пользователю имеют преимущество над групповыми; затем учитывается меньший номер приоритета, а при равенстве — GUID. Вложенное членство оценивает сам DC."
	return out, nil
}
