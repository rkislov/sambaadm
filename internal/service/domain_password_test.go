package service

import (
	"errors"
	"math"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/policy"
)

func passwordPolicyTestEntry() *ldap.Entry {
	return ldap.NewEntry("DC=example,DC=com", map[string][]string{"minPwdLength": {"12"}, "pwdHistoryLength": {"24"}, "pwdProperties": {"17"}, "minPwdAge": {"-864000000000"}, "maxPwdAge": {"-37152000000000"}, "lockoutThreshold": {"5"}, "lockoutDuration": {"-18000000000"}, "lockOutObservationWindow": {"-18000000000"}, "uSNChanged": {"123"}})
}
func TestDomainPasswordPolicyIntervalsAndFlags(t *testing.T) {
	entry := passwordPolicyTestEntry()
	out, e := passwordPolicyFromEntry(entry)
	if e != nil {
		t.Fatal(e)
	}
	if out.MinLength != 12 || out.MinAgeDays != 1 || out.MaxAgeDays != 43 || out.LockoutDurationMinutes != 30 || !out.Complexity || !out.ReversibleEncryption || out.Revision == "" {
		t.Fatalf("wrong domain values: %+v", out)
	}
	if e = validatePasswordPolicy(out.PasswordPolicyValues); e != nil {
		t.Fatal(e)
	}
	if got, e := passwordInterval("-9223372036854775808", 864000000000, true); e != nil || got != 0 {
		t.Fatalf("infinite lifetime: %v %v", got, e)
	}
	if got, e := passwordInterval("-432000000000", 864000000000, false); e != nil || got != 0.5 {
		t.Fatalf("fractional lifetime: %v %v", got, e)
	}
	for _, raw := range []string{"10", "bad", "-9223372036854775808"} {
		if _, e = passwordInterval(raw, 600000000, false); e == nil {
			t.Fatalf("accepted bad interval %s", raw)
		}
	}
	changed := passwordPolicyTestEntry()
	for _, attr := range changed.Attributes {
		if attr.Name == "uSNChanged" {
			attr.Values = []string{"456"}
		}
	}
	next, _ := passwordPolicyFromEntry(changed)
	if out.Revision == next.Revision {
		t.Fatal("revision must account for concurrent LDAP changes")
	}
}
func TestDomainPasswordPolicyRejectsInconsistentSettings(t *testing.T) {
	base, _ := passwordPolicyFromEntry(passwordPolicyTestEntry())
	for _, change := range []func(*PasswordPolicyValues){func(v *PasswordPolicyValues) { v.MinLength = -1 }, func(v *PasswordPolicyValues) { v.MinLength = 256 }, func(v *PasswordPolicyValues) { v.HistoryLength = 1025 }, func(v *PasswordPolicyValues) { v.MinAgeDays = 44 }, func(v *PasswordPolicyValues) { v.MaxAgeDays = math.NaN() }, func(v *PasswordPolicyValues) { v.LockoutDurationMinutes = 29 }, func(v *PasswordPolicyValues) { v.LockoutWindowMinutes = 0 }} {
		v := base.PasswordPolicyValues
		change(&v)
		if e := validatePasswordPolicy(v); !errors.Is(e, policy.ErrInvalidValue) {
			t.Fatalf("invalid policy accepted: %+v %v", v, e)
		}
	}
	v := base.PasswordPolicyValues
	v.MaxAgeDays = 0
	v.LockoutDurationMinutes = 0
	if e := validatePasswordPolicy(v); e != nil {
		t.Fatal("no expiry and administrator unlock must be supported", e)
	}
}
