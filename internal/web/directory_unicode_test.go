package web

import (
	"github.com/go-ldap/ldap/v3"
	"strings"
	"testing"
)

func TestDirectoryUnicodeRoundTrip(t *testing.T) {
	raw := `CN=Приёмная\, 1+UID=42,OU=Аппарат ЦИК РФ,OU=ЦИК РФ,DC=example,DC=com`
	parsed, err := ldap.ParseDN(raw)
	if err != nil {
		t.Fatal(err)
	}
	root, err := directoryTree("DC=example,DC=com", []directoryEntry{{parsed.String(), "Приёмная", "user"}, {raw, "Приёмная", "user"}})
	if err != nil {
		t.Fatal(err)
	}
	ou := root.Children[0]
	if !strings.Contains(ou.DN, "ЦИК РФ") || strings.Contains(ou.DN, `\d0`) {
		t.Fatalf("unreadable OU: %s", ou.DN)
	}
	node := ou.Children[0].Children[0]
	if len(ou.Children[0].Children) != 1 {
		t.Fatal("equivalent DNs duplicated")
	}
	roundtrip, err := ldap.ParseDN(node.DN)
	if err != nil || !roundtrip.EqualFold(parsed) {
		t.Fatalf("DN changed: %s (%v)", node.DN, err)
	}
	if node.ParentDN != ou.Children[0].DN {
		t.Fatal("broken parent link")
	}
}
