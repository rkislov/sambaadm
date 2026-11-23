package service

import (
	"context"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"strconv"
	"testing"
	"time"
)

func TestLoginDiagnosticsAuthoritativeLockAndExpiry(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	ticks := func(t time.Time) string { return strconv.FormatInt((t.Unix()+11644473600)*10000000, 10) }
	attrs := map[string][]string{"sAMAccountName": {"alice"}, "userAccountControl": {"514"}, "msDS-User-Account-Control-Computed": {"16"}, "lockoutTime": {ticks(now.Add(-time.Hour))}, "accountExpires": {ticks(now.Add(-time.Hour))}, "pwdLastSet": {"0"}, "msDS-UserPasswordExpiryTimeComputed": {"0"}}
	status := loginStatus(ldap.NewEntry("CN=alice", attrs), now, "dc.test")
	checks := map[string]LoginCheck{}
	for _, c := range status.Checks {
		checks[c.Code] = c
	}
	for _, code := range []string{"enabled", "lockout", "account-expiry", "password"} {
		if checks[code].State != "issue" {
			t.Fatalf("missing issue %s: %+v", code, status)
		}
	}
	if !status.CanUnlock {
		t.Fatal("unlock unavailable")
	}
	attrs["msDS-User-Account-Control-Computed"] = []string{"0"}
	status = loginStatus(ldap.NewEntry("CN=alice", attrs), now, "dc.test")
	if status.CanUnlock {
		t.Fatal("historical lockout timestamp exposes unlock despite DC confirming unlocked state")
	}
	for _, c := range status.Checks {
		if c.Code == "lockout" && c.State != "ok" {
			t.Fatal("historical lockoutTime treated as active block")
		}
	}
	delete(attrs, "msDS-User-Account-Control-Computed")
	status = loginStatus(ldap.NewEntry("CN=alice", attrs), now, "dc.test")
	for _, c := range status.Checks {
		if c.Code == "lockout" && c.State != "unknown" {
			t.Fatal("missing computed state treated as confirmed")
		}
	}
}
func TestLoginUnknownFieldsAndFiletimeBoundaries(t *testing.T) {
	for _, raw := range []string{"", "bad", "-1", "0", "9223372036854775807", "9223372036854775808"} {
		if _, ok := filetimeDate(raw); ok {
			t.Fatalf("invalid/sentinel time accepted: %s", raw)
		}
	}
	status := loginStatus(ldap.NewEntry("CN=alice", nil), time.Now(), "dc.test")
	if status.CanUnlock {
		t.Fatal("missing attributes allow unlock")
	}
	for _, c := range status.Checks {
		if c.State != "unknown" {
			t.Fatalf("missing value reported as %s", c.State)
		}
	}
	if _, err := (&UserService{}).Unlock(context.Background(), "alice", "", "dc", "actor", ""); !errors.Is(err, ErrUnlockInput) {
		t.Fatal("missing revision reached LDAP")
	}
}
