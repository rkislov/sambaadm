package service

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"sambaadm/internal/audit"
	"sambaadm/internal/config"
)

func TestPartialTemplateImportReportsFilesAndKeepsGoodDefinitions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "ru-RU"), 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"00Broken.admx":         "<policyDefinitions><policies>",
		"01Language.admx":       windowsTemplateFixture,
		"ru-RU/01Language.adml": "<policyDefinitionResources><resources>",
		"99Good.admx":           windowsTemplateFixture,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "99Good.admx"), filepath.Join(dir, "02Unreadable.admx")); err != nil {
		t.Fatal(err)
	}
	cfg := config.GPOConfig{ADMXPath: dir, ManagedEditorFile: filepath.Join(t.TempDir(), "settings", "gpo-editor.json")}
	s := &GPOService{gpoCfg: cfg}
	var issues []TemplateImportIssue
	defs, source, err := s.loadEditorDefinitionsReport(nil, "", &issues)
	if err != nil || len(defs) != 2 || len(issues) != 3 {
		t.Fatalf("partial import lost valid policies or diagnostics: %d %+v %v", len(defs), issues, err)
	}
	if issues[0].File != "00Broken.admx" || issues[1].File != "ru-RU/01Language.adml" || issues[1].Template != "01Language.admx" || issues[2].File != "02Unreadable.admx" {
		t.Fatalf("wrong file attribution: %+v", issues)
	}
	for _, d := range defs {
		if d.Template != "99Good.admx" {
			t.Fatalf("broken template imported: %+v", d)
		}
	}
	// The helper must return the same report through its binary catalogue.
	logger, err := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Close() })
	client := testHelperClient(t, &Services{Audit: logger}, &config.Config{GPO: cfg, Helper: config.HelperServerConfig{Node: "host.example.com", ADMXRoot: dir}})
	remote := &GPOService{helpers: client, gpoCfg: cfg}
	var remoteIssues []TemplateImportIssue
	got, _, err := remote.loadEditorDefinitionsReport(&sysvolShare{ctx: context.Background()}, "", &remoteIssues)
	if err != nil || !reflect.DeepEqual(got, defs) || !reflect.DeepEqual(remoteIssues, issues) {
		t.Fatalf("helper report lost: %+v %v", remoteIssues, err)
	}
	if err = s.storeTemplateCache(templateCatalog{Schema: 1, Key: "test", Loaded: time.Now(), Source: source, Definitions: defs, Issues: issues}); err != nil {
		t.Fatal(err)
	}
	restarted := &GPOService{gpoCfg: cfg}
	cached := restarted.loadTemplateCache("test")
	if cached == nil || !reflect.DeepEqual(cached.Issues, issues) {
		t.Fatal("cached diagnostics were lost")
	}
	// A fully broken source still returns its file report, never an empty usable editor.
	if err = os.Remove(filepath.Join(dir, "99Good.admx")); err != nil {
		t.Fatal(err)
	}
	remoteIssues = nil
	got, _, err = remote.loadEditorDefinitionsReport(&sysvolShare{ctx: context.Background()}, "", &remoteIssues)
	if err != nil || len(got) != 0 || len(remoteIssues) != 3 {
		t.Fatalf("all-failed report lost: %d %+v %v", len(got), remoteIssues, err)
	}
	if _, _, err = remote.loadEditorDefinitions(&sysvolShare{ctx: context.Background()}, ""); err == nil {
		t.Fatal("empty failed catalog exposed as usable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err = s.loadEditorDefinitionsReport(&sysvolShare{ctx: ctx}, "", nil); err == nil {
		t.Fatal("cancellation swallowed as a file warning")
	}
}
