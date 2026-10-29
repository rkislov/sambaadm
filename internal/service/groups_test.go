package service

import (
	"context"
	"errors"
	"testing"

	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/testldap"
)

func TestGroupMembersRejectContainersAndSelf(t *testing.T) {
	group := "CN=Finance,CN=Users,DC=example,DC=com"
	for _, member := range []string{"", "invalid", "cn=finance,cn=users,dc=EXAMPLE,dc=COM"} {
		if err := (&GroupService{}).validateMember(context.Background(), group, member); !errors.Is(err, ErrGroupMemberInput) {
			t.Fatalf("expected input error for %q: %v", member, err)
		}
	}
	for _, found := range []bool{false, true} {
		fake := testldap.New(t, nil, func(q testldap.Search) ([]testldap.Entry, int64) {
			if !found {
				return nil, 0
			}
			return []testldap.Entry{{DN: "CN=Nested,CN=Users,DC=example,DC=com"}}, 0
		})
		client := ldapproto.NewClient(config.LDAPConfig{URI: fake.URI(), BaseDN: "DC=example,DC=com"})
		err := (&GroupService{ldap: client}).validateMember(context.Background(), group, "CN=Nested,CN=Users,DC=example,DC=com")
		client.Close()
		if found && err != nil {
			t.Fatal(err)
		}
		if !found && !errors.Is(err, ErrGroupMemberInput) {
			t.Fatalf("non-member object accepted: %v", err)
		}
	}
}
