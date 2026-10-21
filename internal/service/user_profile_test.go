package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/testldap"
	"strings"
	"testing"
)

func TestInvalidProfileNeverReachesLDAP(t *testing.T) {
	str := func(v string) *string { return &v }
	for _, input := range []UpdateUserInput{
		{Revision: ""}, {Revision: "1"}, {Revision: "1", Mail: str("not an address")}, {Revision: "1", Mail: str("Name <a@example.test>")}, {Revision: "1", GivenName: str(strings.Repeat("x", 65))}, {Revision: "1", Description: str("a\x00b")}, {Revision: "1", Telephone: str("123\n456")},
	} {
		if _, e := (&UserService{}).Update(context.Background(), "alice", input, "actor", ""); !errors.Is(e, ErrUserInput) {
			t.Fatalf("expected input refusal, got %v", e)
		}
	}
}

func TestGroupSelectionPrefersUniqueAccountName(t *testing.T) {
	for _, ambiguous := range []bool{false, true} {
		t.Run(fmt.Sprint(ambiguous), func(t *testing.T) {
			fake := testldap.New(t, map[string]string{}, func(q testldap.Search) ([]testldap.Entry, int64) {
				if bytes.Contains(q.Filter.Bytes(), []byte("sAMAccountName")) {
					if !ambiguous {
						return []testldap.Entry{{DN: "CN=Chosen,DC=example,DC=com"}}, 0
					}
					return nil, 0
				}
				return []testldap.Entry{{DN: "CN=Finance,OU=One,DC=example,DC=com"}, {DN: "CN=Finance,OU=Two,DC=example,DC=com"}}, 0
			})
			client := ldapproto.NewClient(config.LDAPConfig{URI: fake.URI(), BaseDN: "DC=example,DC=com"})
			defer client.Close()
			entry, err := (&GroupService{ldap: client}).find(context.Background(), "Finance")
			if ambiguous && err == nil {
				t.Fatal("ambiguous CN selected")
			}
			if !ambiguous && (err != nil || entry.DN != "CN=Chosen,DC=example,DC=com") {
				t.Fatalf("wrong group: %+v %v", entry, err)
			}
		})
	}
}

func TestExtendedProfileRejectsSecurityAndInvalidValues(t *testing.T) {
	for _, attrs := range []map[string]string{
		{"unicodePwd": "secret"}, {"userAccountControl": "512"}, {"manager": "CN=Other"},
		{"company": "bad\nvalue"}, {"initials": "1234567"},
	} {
		_, err := (&UserService{}).Update(context.Background(), "alice", UpdateUserInput{Revision: "1", Attributes: attrs}, "actor", "")
		if !errors.Is(err, ErrUserInput) {
			t.Fatalf("expected validation failure for %v: %v", attrs, err)
		}
	}
}
