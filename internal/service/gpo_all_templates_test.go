package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	"testing"
)

const windowsTemplateFixture = `<policyDefinitions><policies><policy name="Example" class="Both" key="Software\Policies\Microsoft\Example" valueName="Enabled" displayName="Windows example"><parentCategory ref="windows:System"/><enabledValue><decimal value="1"/></enabledValue><disabledValue><decimal value="0"/></disabledValue></policy></policies></policyDefinitions>`

func TestCatalogImportsAllVendorsAndCategoryOnlyTemplates(t *testing.T) {
	dir := t.TempDir()
	if e := os.Mkdir(filepath.Join(dir, "ru-RU"), 0700); e != nil {
		t.Fatal(e)
	}
	files := map[string]string{"Windows.admx": `<policyDefinitions><policyNamespaces><target prefix="windows" namespace="Microsoft.Policies.Windows"/></policyNamespaces><categories><category name="System" displayName="$(string.system)"/></categories></policyDefinitions>`, "ru-RU/Windows.adml": `<policyDefinitionResources><resources><stringTable><string id="system">Система Windows</string></stringTable></resources></policyDefinitionResources>`, "BaseALTTest.admx": typedEditorADMX, "VendorBrowser.admx": windowsTemplateFixture}
	for i := 0; i < 70; i++ {
		files[fmt.Sprintf("Windows%02d.admx", i)] = windowsTemplateFixture
	}
	for name, data := range files {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); e != nil {
			t.Fatal(e)
		}
	}
	s := &GPOService{gpoCfg: config.GPOConfig{ADMXPath: dir}}
	defs, _, e := s.loadEditorDefinitions(nil, "")
	if e != nil {
		t.Fatal(e)
	}
	if len(defs) != 144 {
		t.Fatalf("some templates were excluded or old 64-file limit remained: %d", len(defs))
	}
	seen := map[string]bool{}
	for _, d := range defs {
		seen[d.Template] = true
		if d.Template != "BaseALTTest.admx" && (d.Category != "Система Windows" || d.Unsupported != "") {
			t.Fatalf("cross-template resource or supported mapping lost: %+v", d)
		}
	}
	if !seen["VendorBrowser.admx"] || !seen["Windows69.admx"] || !seen["BaseALTTest.admx"] {
		t.Fatal("vendor filtering remained")
	}
	// Local and helper sources must agree about the complete catalogue.
	cfg := &config.Config{GPO: config.GPOConfig{ADMXPath: dir}, Helper: config.HelperServerConfig{Node: "host.example.com", ADMXRoot: dir}}
	logger, e := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { logger.Close() })
	backend := &Services{Audit: logger}
	client := testHelperClient(t, backend, cfg)
	s.helpers = client
	remote, _, e := s.loadEditorDefinitions(&sysvolShare{ctx: context.Background()}, "")
	if e != nil || len(remote) != len(defs) {
		t.Fatalf("helper did not import all vendors: %d %v", len(remote), e)
	}
}
