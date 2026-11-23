package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
)

var ErrLoginConflict = errors.New("состояние учётной записи изменилось; обновите диагностику")
var ErrUnlockInput = errors.New("для разблокировки нужны подтверждение и актуальная версия диагностики")

type LoginCheck struct {
	Code   string `json:"code"`
	Title  string `json:"title"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}
type UserLoginStatus struct {
	Login        string       `json:"login"`
	DN           string       `json:"dn"`
	Controller   string       `json:"controller"`
	ObservedAt   time.Time    `json:"observedAt"`
	Revision     string       `json:"revision"`
	CanUnlock    bool         `json:"canUnlock"`
	Checks       []LoginCheck `json:"checks"`
	ResultantPSO string       `json:"resultantPSO,omitempty"`
	Limitations  []string     `json:"limitations"`
}

var loginAttrs = []string{"sAMAccountName", "objectGUID", "uSNChanged", "userAccountControl", "msDS-User-Account-Control-Computed", "lockoutTime", "badPwdCount", "badPasswordTime", "pwdLastSet", "accountExpires", "msDS-UserPasswordExpiryTimeComputed", "msDS-ResultantPSO", "userWorkstations", "logonHours", "lastLogonTimestamp"}

func (s *UserService) loginEntry(ctx context.Context, login string) (*ldap.Entry, error) {
	return s.ldap.SearchOne(ctx, ldapproto.SearchOptions{Filter: "(&(objectCategory=person)(objectClass=user)(sAMAccountName=" + ldap.EscapeFilter(login) + "))", Attributes: loginAttrs})
}
func loginRevision(e *ldap.Entry) string {
	raw, _ := json.Marshal([]string{e.DN, hex.EncodeToString(e.GetRawAttributeValue("objectGUID")), e.GetAttributeValue("uSNChanged"), e.GetAttributeValue("lockoutTime"), e.GetAttributeValue("userAccountControl")})
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}
func filetimeDate(raw string) (time.Time, bool) {
	ticks, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ticks <= 0 || ticks == 9223372036854775807 {
		return time.Time{}, false
	}
	return time.Unix(ticks/10000000-11644473600, (ticks%10000000)*100).UTC(), true
}
func loginStatus(e *ldap.Entry, now time.Time, controller string) *UserLoginStatus {
	out := &UserLoginStatus{Login: e.GetAttributeValue("sAMAccountName"), DN: e.DN, Controller: controller, ObservedAt: now.UTC(), Revision: loginRevision(e), Checks: []LoginCheck{}, ResultantPSO: e.GetAttributeValue("msDS-ResultantPSO"), Limitations: []string{
		"Состояние прочитано с указанного контроллера. Счётчик ошибочных паролей и последнее обращение могут отличаться на других DC; репликация требует времени.",
		"Диагностика не проверяет пароль и не выполняет пробный вход. Отсутствие найденных ограничений не гарантирует вход: проверьте время, DNS, Kerberos/SSSD и доступность DC на рабочей станции.",
	}}
	add := func(code, title, state, detail string) {
		out.Checks = append(out.Checks, LoginCheck{code, title, state, detail})
	}
	uac, ue := strconv.ParseUint(e.GetAttributeValue("userAccountControl"), 10, 32)
	computed, ce := strconv.ParseUint(e.GetAttributeValue("msDS-User-Account-Control-Computed"), 10, 32)
	lock, le := strconv.ParseInt(e.GetAttributeValue("lockoutTime"), 10, 64)
	if ue != nil {
		add("enabled", "Учётная запись", "unknown", "Не удалось прочитать состояние учётной записи.")
	} else if uac&2 != 0 {
		add("enabled", "Учётная запись", "issue", "Учётная запись отключена. Разблокировка её не включает; включите запись отдельным действием после проверки причины.")
	} else {
		add("enabled", "Учётная запись", "ok", "Учётная запись включена.")
	}
	if ce == nil {
		if computed&16 != 0 {
			add("lockout", "Блокировка входа", "issue", "Контроллер подтверждает блокировку. Проверьте источник неверных паролей, затем разблокируйте пользователя.")
		} else {
			add("lockout", "Блокировка входа", "ok", "Контроллер не сообщает об активной блокировке. Ненулевой lockoutTime сам по себе не означает, что блокировка ещё действует.")
		}
	} else {
		add("lockout", "Блокировка входа", "unknown", "Контроллер не вернул вычисляемое состояние блокировки. По одному lockoutTime нельзя подтвердить активную блокировку.")
	}
	out.CanUnlock = (le == nil && lock > 0) || (ce == nil && computed&16 != 0)
	if raw := e.GetAttributeValue("lockoutTime"); le == nil && lock > 0 {
		date, ok := filetimeDate(raw)
		if ok {
			add("lockout-time", "Последняя отметка блокировки", "info", date.Format(time.RFC3339))
		}
	}
	expiry := e.GetAttributeValue("accountExpires")
	if expiry == "0" || expiry == "9223372036854775807" {
		add("account-expiry", "Срок учётной записи", "ok", "Срок действия учётной записи не ограничен.")
	} else if date, ok := filetimeDate(expiry); ok {
		state := "ok"
		detail := "Действует до " + date.Format(time.RFC3339)
		if !date.After(now) {
			state = "issue"
			detail = "Срок учётной записи истёк " + date.Format(time.RFC3339) + ". Разблокировка не продлевает срок."
		}
		add("account-expiry", "Срок учётной записи", state, detail)
	} else {
		add("account-expiry", "Срок учётной записи", "unknown", "Срок действия не возвращён или некорректен.")
	}
	pwd := e.GetAttributeValue("pwdLastSet")
	pwdExpiry := e.GetAttributeValue("msDS-UserPasswordExpiryTimeComputed")
	if pwd == "0" {
		add("password", "Пароль", "issue", "Требуется смена пароля при следующем входе. Клиент должен поддерживать смену пароля; при необходимости используйте сброс пароля.")
	} else if ce == nil && computed&0x800000 != 0 {
		add("password", "Пароль", "issue", "Контроллер сообщает об истёкшем пароле. Разблокировка не меняет пароль.")
	} else if pwdExpiry == "9223372036854775807" {
		add("password", "Пароль", "ok", "Контроллер сообщает, что срок пароля не ограничен.")
	} else if date, ok := filetimeDate(pwdExpiry); ok {
		state := "ok"
		detail := "Пароль действует до " + date.Format(time.RFC3339)
		if !date.After(now) {
			state = "issue"
			detail = "Срок пароля истёк " + date.Format(time.RFC3339)
		}
		add("password", "Пароль", state, detail)
	} else {
		add("password", "Пароль", "unknown", "Контроллер не вернул вычисляемый срок пароля; общая доменная политика может быть переопределена PSO.")
	}
	if date, ok := filetimeDate(pwd); ok {
		add("password-set", "Последняя смена пароля", "info", date.Format(time.RFC3339))
	}
	if ue == nil && uac&0x40000 != 0 {
		add("smartcard", "Способ входа", "issue", "Для учётной записи требуется смарт-карта. Обычный вход по паролю может быть запрещён.")
	}
	if raw := e.GetAttributeValue("userWorkstations"); raw != "" {
		add("workstations", "Разрешённые компьютеры", "info", raw+". Убедитесь, что нужная станция разрешена.")
	}
	if hours := e.GetRawAttributeValue("logonHours"); len(hours) > 0 {
		restricted := len(hours) != 21
		for _, b := range hours {
			if b != 255 {
				restricted = true
			}
		}
		if restricted {
			add("hours", "Часы входа", "info", "Заданы ограничения часов входа. Их применение зависит от времени и контроллера; проверьте расписание учётной записи.")
		}
	}
	for _, f := range []struct{ attr, title string }{{"badPwdCount", "Ошибочных паролей на этом DC"}, {"badPasswordTime", "Последний неверный пароль на этом DC"}, {"lastLogonTimestamp", "Реплицируемая отметка последнего входа"}} {
		raw := e.GetAttributeValue(f.attr)
		if raw == "" {
			continue
		}
		if f.attr != "badPwdCount" {
			if date, ok := filetimeDate(raw); ok {
				raw = date.Format(time.RFC3339)
			} else if raw == "0" {
				raw = "Нет отметки"
			} else {
				raw = "Некорректная отметка времени"
			}
		}
		add(f.attr, f.title, "info", raw)
	}
	return out
}
func (s *UserService) LoginStatus(ctx context.Context, login, controller string) (*UserLoginStatus, error) {
	e, err := s.loginEntry(ctx, login)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать диагностику входа: %w", err)
	}
	return loginStatus(e, time.Now(), controller), nil
}
func (s *UserService) Unlock(ctx context.Context, login, revision, controller, actor, ip string) (out *UserLoginStatus, err error) {
	if revision == "" {
		return nil, ErrUnlockInput
	}
	var dn string
	defer func() {
		if s.audit != nil {
			if err != nil {
				s.audit.Failure(actor, "user.unlock", dn, ip, err)
			} else {
				s.audit.Success(actor, "user.unlock", dn, ip)
			}
		}
	}()
	entry, err := s.loginEntry(ctx, login)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать состояние пользователя: %w", err)
	}
	dn = entry.DN
	if loginRevision(entry) != revision {
		return nil, ErrLoginConflict
	}
	before := loginStatus(entry, time.Now(), controller)
	if !before.CanUnlock {
		computed, e := strconv.ParseUint(entry.GetAttributeValue("msDS-User-Account-Control-Computed"), 10, 32)
		if e != nil || computed&16 != 0 {
			return nil, fmt.Errorf("контроллер не подтвердил состояние блокировки; обновите диагностику")
		}
		return before, nil
	}
	usn := entry.GetAttributeValue("uSNChanged")
	guid := entry.GetRawAttributeValue("objectGUID")
	if _, e := strconv.ParseUint(usn, 10, 64); e != nil || len(guid) != 16 {
		return nil, fmt.Errorf("не удалось подтвердить идентификатор и версию объекта; разблокировка остановлена")
	}
	filter, err := ldap.CompileFilter("(&(objectGUID=" + ldap.EscapeFilter(string(guid)) + ")(uSNChanged=" + ldap.EscapeFilter(usn) + "))")
	if err != nil {
		return nil, err
	}
	req := ldap.NewModifyRequest(dn, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(filter.Bytes()))})
	req.Replace("lockoutTime", []string{"0"})
	if err = s.ldap.Modify(ctx, req); err != nil {
		if ldap.IsErrorWithCode(err, 122) {
			return nil, ErrLoginConflict
		}
		return nil, fmt.Errorf("не удалось снять блокировку: %w", err)
	}
	after, err := s.loginEntry(ctx, login)
	if err != nil {
		return nil, fmt.Errorf("сброс блокировки отправлен, но проверка результата не удалась; обновите диагностику: %w", err)
	}
	out = loginStatus(after, time.Now(), controller)
	if string(after.GetRawAttributeValue("objectGUID")) != string(guid) || after.GetAttributeValue("lockoutTime") != "0" || out.CanUnlock {
		return out, fmt.Errorf("разблокировка не подтверждена; возможна повторная блокировка, обновите диагностику и проверьте источник неверных паролей")
	}
	return out, nil
}
