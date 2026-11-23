package service

import (
	"context"
	"errors"
	"github.com/go-ldap/ldap/v3"
	"math"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/testldap"
	"strings"
	"testing"
)

func psoTestAttributes() map[string][]string {
	return map[string][]string{"cn": {"Test PSO"}, "objectGUID": {"1234567890abcdef"}, "uSNChanged": {"100"}, "msDS-PasswordSettingsPrecedence": {"5"}, "msDS-PasswordHistoryLength": {"24"}, "msDS-MinimumPasswordLength": {"18"}, "msDS-LockoutThreshold": {"5"}, "msDS-MinimumPasswordAge": {"0"}, "msDS-MaximumPasswordAge": {"-9223372036854775808"}, "msDS-LockoutDuration": {"-18000000000"}, "msDS-LockoutObservationWindow": {"-18000000000"}, "msDS-PasswordReversibleEncryptionEnabled": {"FALSE"}, "msDS-PasswordComplexityEnabled": {"TRUE"}}
}
func TestPSOParsingRequiresCompleteValuesAndRejectsPartialAssignments(t *testing.T) {
	attrs := psoTestAttributes()
	p, err := parsePSO(ldap.NewEntry("CN=Test", attrs))
	if err != nil || p.MaxAgeDays != 0 || p.MinLength != 18 || p.LockoutDurationMinutes != 30 {
		t.Fatal(p, err)
	}
	for _, key := range []string{"objectGUID", "uSNChanged", "msDS-MinimumPasswordLength", "msDS-PasswordComplexityEnabled", "msDS-MaximumPasswordAge"} {
		copy := psoTestAttributes()
		delete(copy, key)
		if _, e := parsePSO(ldap.NewEntry("CN=Test", copy)); e == nil {
			t.Fatal("incomplete policy accepted", key)
		}
	}
	attrs["msDS-PSOAppliesTo;range=0-1499"] = []string{"CN=User"}
	if _, err = parsePSO(ldap.NewEntry("CN=Test", attrs)); err == nil {
		t.Fatal("partial target list accepted")
	}
}
func TestPSOValidationAndGlobalSecurityGroupEligibility(t *testing.T) {
	p, _ := parsePSO(ldap.NewEntry("CN=Test", psoTestAttributes()))
	base := PSOChange{PSOValues: p.PSOValues}
	for _, change := range []func(*PSOChange){func(v *PSOChange) { v.Precedence = 0 }, func(v *PSOChange) { v.MinAgeDays = math.NaN() }, func(v *PSOChange) { v.MaxAgeDays = 1e-20 }, func(v *PSOChange) { v.MaxAgeDays = 1; v.MinAgeDays = 2 }, func(v *PSOChange) { v.Subjects = make([]PSOSubject, 257) }} {
		in := base
		change(&in)
		if err := validatePSO(in); !errors.Is(err, ErrPSOInput) {
			t.Fatal("invalid PSO accepted", err)
		}
	}
	for _, kind := range []struct {
		classes []string
		flags   string
		ok      bool
	}{{[]string{"top", "group"}, "-2147483646", true}, {[]string{"top", "group"}, "2", false}, {[]string{"top", "group"}, "-2147483640", false}, {[]string{"top", "group"}, "-2147483644", false}, {[]string{"top", "person", "user"}, "", true}, {[]string{"top", "person", "user", "computer"}, "", false}} {
		_, err := psoSubject(ldap.NewEntry("CN=target", map[string][]string{"objectClass": kind.classes, "groupType": {kind.flags}, "objectGUID": {"1234567890abcdef"}, "sAMAccountName": {"target"}}))
		if (err == nil) != kind.ok {
			t.Fatal("bad PSO subject eligibility", kind, err)
		}
	}
	for _, id := range []string{"", strings.Repeat("z", 32), "1234"} {
		if _, err := psoGUID(id); !errors.Is(err, ErrPSOInput) {
			t.Fatal("bad identifier accepted")
		}
	}
}
func TestEffectivePSOReadFailureNeverFallsBackToDomainPolicy(t *testing.T) {
	const base = "DC=example,DC=test"
	for _, mode := range []string{"denied", "foreign", "missing", "pso"} {
		t.Run(mode, func(t *testing.T) {
			domainReads := 0
			fake := testldap.New(t, nil, func(q testldap.Search) ([]testldap.Entry, int64) {
				if q.Scope == 0 && q.BaseDN == base {
					domainReads++
					entry := passwordPolicyTestEntry()
					attrs := map[string][]string{}
					for _, a := range entry.Attributes {
						attrs[a.Name] = a.Values
					}
					return []testldap.Entry{{DN: base, Attributes: attrs}}, 0
				}
				if q.Scope == 0 {
					if mode == "denied" {
						return nil, 50
					}
					return []testldap.Entry{{DN: q.BaseDN, Attributes: psoTestAttributes()}}, 0
				}
				attrs := map[string][]string{"sAMAccountName": {"alice"}, "objectGUID": {"user123456789012"}}
				if mode != "missing" {
					dn := "CN=PSO,CN=Password Settings Container,CN=System," + base
					if mode == "foreign" {
						dn = "CN=PSO,DC=foreign,DC=test"
					}
					attrs["msDS-ResultantPSO"] = []string{dn}
				}
				return []testldap.Entry{{DN: "CN=alice," + base, Attributes: attrs}}, 0
			})
			client := ldapproto.NewClient(config.LDAPConfig{URI: fake.URI(), BaseDN: base})
			defer client.Close()
			service := &DomainService{ldap: client}
			result, err := service.EffectivePasswordPolicy(context.Background(), "alice", "dc0")
			if mode == "denied" || mode == "foreign" {
				if err == nil || domainReads != 0 {
					t.Fatal("PSO error hidden by domain fallback", err, domainReads)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing" && (result.Source != "domain" || result.Domain == nil || domainReads != 1) {
				t.Fatal("missing domain result", result)
			}
			if mode == "pso" && (result.Source != "pso" || result.Policy == nil || domainReads != 0) {
				t.Fatal("missing PSO result", result)
			}
		})
	}
}
