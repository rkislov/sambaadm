package service

import (
	"os"
	"path/filepath"
	"testing"

	"sambaadm/internal/config"
)

func TestCatalogCategoryHierarchyUsesNamespaceAliases(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"Root.admx":       `<policyDefinitions><policyNamespaces><target prefix="root" namespace="Vendor.Root"/></policyNamespaces><categories><category name="System" displayName="$(string.system)"/></categories></policyDefinitions>`,
		"ru-RU/Root.adml": `<policyDefinitionResources><resources><stringTable><string id="system">Система</string></stringTable></resources></policyDefinitionResources>`,
		"Child.admx":      `<policyDefinitions><policyNamespaces><target prefix="child" namespace="Vendor.Child"/><using prefix="other" namespace="Vendor.Root"/></policyNamespaces><categories><category name="Logon" displayName="Вход"><parentCategory ref="other:System"/></category></categories><policies><policy name="Example" displayName="Пример" class="Both" key="Software\Policies\Example" valueName="Enabled"><parentCategory ref="Logon"/></policy></policies></policyDefinitions>`,
		"Another.admx":    `<policyDefinitions><policyNamespaces><target prefix="another" namespace="Vendor.Another"/><using prefix="different" namespace="Vendor.Child"/></policyNamespaces><policies><policy name="Example" class="Machine" key="Software\Policies\Another" valueName="Enabled"><parentCategory ref="different:Logon"/></policy></policies></policyDefinitions>`,
	}
	for name, data := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := &GPOService{gpoCfg: config.GPOConfig{ADMXPath: dir}}
	defs, _, err := s.loadEditorDefinitions(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) != 3 {
		t.Fatalf("definitions: %d", len(defs))
	}
	for _, d := range defs {
		if len(d.CategoryPath) != 2 || d.CategoryPath[0].ID != "Vendor.Root/System" || d.CategoryPath[0].Label != "Система" || d.CategoryPath[1].ID != "Vendor.Child/Logon" || d.CategoryPath[1].Label != "Вход" {
			t.Fatalf("hierarchy lost: %+v", d)
		}
	}
}
