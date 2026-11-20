package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/policy"
)

type PasswordPolicyValues struct {
	MinLength              int     `json:"minLength"`
	HistoryLength          int     `json:"historyLength"`
	Complexity             bool    `json:"complexity"`
	MinAgeDays             float64 `json:"minAgeDays"`
	MaxAgeDays             float64 `json:"maxAgeDays"`
	LockoutThreshold       int     `json:"lockoutThreshold"`
	LockoutDurationMinutes float64 `json:"lockoutDurationMinutes"`
	LockoutWindowMinutes   float64 `json:"lockoutWindowMinutes"`
}
type DomainPasswordPolicy struct {
	PasswordPolicyValues
	DN                   string `json:"dn"`
	Revision             string `json:"revision"`
	ReversibleEncryption bool   `json:"reversibleEncryption"`
}
type PasswordPolicyChange struct {
	Revision string               `json:"revision"`
	Policy   PasswordPolicyValues `json:"policy"`
}

var passwordPolicyAttrs = []string{"minPwdLength", "pwdHistoryLength", "pwdProperties", "minPwdAge", "maxPwdAge", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow", "uSNChanged"}

func passwordInterval(raw string, unit float64, never bool) (float64, error) {
	n, e := strconv.ParseInt(raw, 10, 64)
	if e != nil {
		return 0, fmt.Errorf("invalid password policy interval")
	}
	if never && n == math.MinInt64 {
		return 0, nil
	}
	if n > 0 || n == math.MinInt64 {
		return 0, fmt.Errorf("invalid password policy interval")
	}
	return float64(-n) / unit, nil
}
func passwordPolicyFromEntry(entry *ldap.Entry) (*DomainPasswordPolicy, error) {
	out := &DomainPasswordPolicy{DN: entry.DN}
	raw := map[string]string{}
	for _, a := range passwordPolicyAttrs {
		raw[a] = entry.GetAttributeValue(a)
	}
	h, _ := json.Marshal(raw)
	out.Revision = fmt.Sprintf("%x", sha256.Sum256(h))
	for _, field := range []struct {
		name  string
		value *int
	}{{"minPwdLength", &out.MinLength}, {"pwdHistoryLength", &out.HistoryLength}, {"lockoutThreshold", &out.LockoutThreshold}} {
		n, e := strconv.Atoi(raw[field.name])
		if e != nil || n < 0 {
			return nil, fmt.Errorf("invalid domain attribute %s", field.name)
		}
		*field.value = n
	}
	flags, e := strconv.ParseUint(raw["pwdProperties"], 10, 32)
	if e != nil {
		return nil, e
	}
	out.Complexity = flags&1 != 0
	out.ReversibleEncryption = flags&16 != 0
	for _, f := range []struct {
		name  string
		unit  float64
		value *float64
		never bool
	}{{"minPwdAge", 864000000000, &out.MinAgeDays, false}, {"maxPwdAge", 864000000000, &out.MaxAgeDays, true}, {"lockoutDuration", 600000000, &out.LockoutDurationMinutes, false}, {"lockOutObservationWindow", 600000000, &out.LockoutWindowMinutes, false}} {
		n, e := passwordInterval(raw[f.name], f.unit, f.never)
		if e != nil {
			return nil, e
		}
		*f.value = n
	}
	return out, nil
}
func validatePasswordPolicy(v PasswordPolicyValues) error {
	invalid := func(message string) error { return fmt.Errorf("%w: %s", policy.ErrInvalidValue, message) }
	if v.MinLength < 0 || v.MinLength > 255 || v.HistoryLength < 0 || v.HistoryLength > 1024 || v.LockoutThreshold < 0 || v.LockoutThreshold > 999 {
		return invalid("password length, history or lockout threshold is outside the supported range")
	}
	for _, f := range []struct{ n, max float64 }{{v.MinAgeDays, 998}, {v.MaxAgeDays, 999}, {v.LockoutDurationMinutes, 99999}, {v.LockoutWindowMinutes, 99999}} {
		if math.IsNaN(f.n) || math.IsInf(f.n, 0) || f.n < 0 || f.n > f.max {
			return invalid("invalid password policy duration")
		}
	}
	if v.MaxAgeDays != 0 && v.MinAgeDays >= v.MaxAgeDays {
		return invalid("maximum password age must exceed minimum age, or be zero for no expiry")
	}
	if v.LockoutThreshold > 0 && (v.LockoutWindowMinutes <= 0 || (v.LockoutDurationMinutes != 0 && v.LockoutDurationMinutes < v.LockoutWindowMinutes)) {
		return invalid("lockout duration must cover the observation window, or be zero for administrator unlock")
	}
	return nil
}
func (s *DomainService) passwordPolicySnapshot(ctx context.Context) (*ldap.Entry, *DomainPasswordPolicy, error) {
	entry, e := s.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: s.ldap.BaseDN(), Scope: ldapproto.ScopeBase(), Filter: "(objectClass=domainDNS)", Attributes: passwordPolicyAttrs})
	if e != nil {
		return nil, nil, e
	}
	p, e := passwordPolicyFromEntry(entry)
	return entry, p, e
}
func (s *DomainService) PasswordPolicy(ctx context.Context) (*DomainPasswordPolicy, error) {
	_, p, e := s.passwordPolicySnapshot(ctx)
	return p, e
}
func (s *DomainService) SetPasswordPolicy(ctx context.Context, in PasswordPolicyChange, actor, ip string) (out *DomainPasswordPolicy, err error) {
	if in.Revision == "" {
		return nil, fmt.Errorf("%w: revision is required", policy.ErrInvalidValue)
	}
	if err = validatePasswordPolicy(in.Policy); err != nil {
		return nil, err
	}
	defer func() {
		if s.audit != nil {
			if err != nil {
				s.audit.Failure(actor, "domain.password-policy.set", s.ldap.BaseDN(), ip, err)
			} else {
				s.audit.Success(actor, "domain.password-policy.set", s.ldap.BaseDN(), ip)
			}
		}
	}()
	entry, before, e := s.passwordPolicySnapshot(ctx)
	if e != nil {
		return nil, e
	}
	if in.Revision != before.Revision {
		return nil, ErrPolicyConflict
	}
	flags, e := strconv.ParseUint(entry.GetAttributeValue("pwdProperties"), 10, 32)
	if e != nil {
		return nil, e
	}
	if in.Policy.Complexity {
		flags |= 1
	} else {
		flags &^= 1
	}
	updates := map[string]string{"minPwdLength": strconv.Itoa(in.Policy.MinLength), "pwdHistoryLength": strconv.Itoa(in.Policy.HistoryLength), "lockoutThreshold": strconv.Itoa(in.Policy.LockoutThreshold), "pwdProperties": strconv.FormatUint(flags, 10)}
	for _, f := range []struct {
		name                string
		value, before, unit float64
	}{{"minPwdAge", in.Policy.MinAgeDays, before.MinAgeDays, 864000000000}, {"maxPwdAge", in.Policy.MaxAgeDays, before.MaxAgeDays, 864000000000}, {"lockoutDuration", in.Policy.LockoutDurationMinutes, before.LockoutDurationMinutes, 600000000}, {"lockOutObservationWindow", in.Policy.LockoutWindowMinutes, before.LockoutWindowMinutes, 600000000}} {
		if f.value == f.before {
			continue
		}
		n := int64(-math.Round(f.value * f.unit))
		if f.name == "maxPwdAge" && f.value == 0 {
			n = math.MinInt64
		}
		updates[f.name] = strconv.FormatInt(n, 10)
	}
	filter, e := ldap.CompileFilter("(uSNChanged=" + ldap.EscapeFilter(entry.GetAttributeValue("uSNChanged")) + ")")
	if e != nil {
		return nil, e
	}
	req := ldap.NewModifyRequest(entry.DN, []ldap.Control{ldap.NewControlString("1.3.6.1.1.12", true, string(filter.Bytes()))})
	for _, name := range passwordPolicyAttrs {
		if value, ok := updates[name]; ok && value != entry.GetAttributeValue(name) {
			req.Replace(name, []string{value})
		}
	}
	if len(req.Changes) == 0 {
		return before, nil
	}
	if e = s.ldap.Modify(ctx, req); e != nil {
		var le *ldap.Error
		if errors.As(e, &le) && le.ResultCode == ldap.LDAPResultAssertionFailed {
			return nil, ErrPolicyConflict
		}
		return nil, e
	}
	return s.PasswordPolicy(ctx)
}
