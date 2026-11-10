package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"sambaadm/internal/agent"
	"sambaadm/internal/config"
	"sambaadm/internal/policy"
)

func TestTemplateCatalogPreservesPrivateRegistryEncodings(t *testing.T) {
	defs, e := policy.ParseADMX("BaseALTTest.admx", []byte(typedEditorADMX), nil)
	if e != nil {
		t.Fatal(e)
	}
	defs[0].Enabled = &policy.Literal{Type: 4, Data: []byte{3, 0, 0, 0}}
	defs[0].Disabled = &policy.Literal{Type: 1, Data: []byte{0, 0}}
	out, e := catalogResponse(defs, "fixture")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(out)
	if e != nil {
		t.Fatal(e)
	}
	var wire helperADMXCatalog
	if e = json.Unmarshal(raw, &wire); e != nil {
		t.Fatal(e)
	}
	got, source, e := decodedCatalog(wire)
	if e != nil || source != "fixture" || !reflect.DeepEqual(got, defs) {
		t.Fatalf("registry encodings lost in helper/cache roundtrip: %v", e)
	}
}
func TestTemplateCacheRestartIsolationFreshnessAndPermissions(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "BaseALTTest.admx")
	if e := os.WriteFile(file, []byte(typedEditorADMX), 0600); e != nil {
		t.Fatal(e)
	}
	cfg := config.GPOConfig{ADMXPath: file, ManagedEditorFile: filepath.Join(dir, "settings", "gpo-editor.json")}
	s := &GPOService{gpoCfg: cfg}
	share := &sysvolShare{ctx: context.Background()}
	defs, _, e := s.editorDefinitions(share, "example.com")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(file); e != nil {
		t.Fatal(e)
	}
	restarted := &GPOService{gpoCfg: cfg}
	got, _, e := restarted.editorDefinitions(share, "example.com")
	if e != nil || !reflect.DeepEqual(got, defs) {
		t.Fatalf("restart did not use disk cache: %v", e)
	}
	// Saving must re-read the configured source, never silently reuse cached templates.
	fresh := &sysvolShare{ctx: context.WithValue(context.Background(), freshTemplatesKey{}, true)}
	if _, _, e = restarted.editorDefinitions(fresh, "example.com"); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("fresh read used stale data: %v", e)
	}
	credentials := agent.WithCredentials(context.Background(), func() (agent.Credentials, error) {
		return agent.Credentials{Username: "other@example.com", Password: "test-password-never-store"}, nil
	})
	if _, _, e = restarted.editorDefinitions(&sysvolShare{ctx: credentials}, "example.com"); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("identity reused another cache: %v", e)
	}
	if _, _, e = restarted.editorDefinitions(share, "another.example"); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("domain reused another cache: %v", e)
	}
	entries, e := os.ReadDir(s.templateCacheDir())
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		info, _ := entry.Info()
		if info.Mode().Perm() != 0600 {
			t.Fatal("cache file is not private")
		}
		raw, _ := os.ReadFile(filepath.Join(s.templateCacheDir(), entry.Name()))
		if bytes.Contains(raw, []byte("test-password-never-store")) {
			t.Fatal("credential persisted")
		}
	}
	key, _ := s.templateCacheKey(share, "example.com")
	c := *s.loadTemplateCache(key)
	c.Loaded = time.Now().AddDate(-10, 0, 0)
	if e = s.storeTemplateCache(c); e != nil {
		t.Fatal(e)
	}
	if got, _, err := (&GPOService{gpoCfg: cfg}).editorDefinitions(share, "example.com"); err != nil || !reflect.DeepEqual(got, defs) {
		t.Fatalf("old import was unexpectedly expired: %v", err)
	}
}
func TestEditorLockHonorsCancellation(t *testing.T) {
	s := &GPOService{}
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if e := s.lockEditor(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatalf("waiting reader ignored deadline: %v", e)
	}
}

func TestTemplateBulkReadDoesNotFallBackOnPermissionFailure(t *testing.T) {
	cfg := &config.Config{Helper: config.HelperServerConfig{Node: "dc.example.com"}}
	var calls atomic.Int32
	client := testHelperClient(t, nil, cfg, func(ctx context.Context, method string, _ json.RawMessage) error {
		calls.Add(1)
		if method != "sysvol.admx-catalog" {
			t.Errorf("unexpected fallback %s", method)
		}
		cred, present, e := agent.OperationCredentials(ctx)
		if e != nil || !present || cred.Username != "alice@example.com" {
			t.Error("browser identity was not forwarded")
		}
		return os.ErrPermission
	})
	ctx := agent.WithCredentials(context.Background(), func() (agent.Credentials, error) {
		return agent.Credentials{Username: "alice@example.com", Password: "test-password-never-store"}, nil
	})
	s := &GPOService{helpers: client}
	_, _, e := s.loadEditorDefinitions(&sysvolShare{helpers: client, node: cfg.Helper.Node, ctx: ctx}, "example.com")
	if !errors.Is(e, os.ErrPermission) || calls.Load() != 1 {
		t.Fatalf("permission failure was masked or read was not batched: calls=%d err=%v", calls.Load(), e)
	}
}

func TestTemplateValidationDoesNotReplacePermanentImport(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "BaseALTTest.admx")
	if err := os.WriteFile(file, []byte(typedEditorADMX), 0600); err != nil {
		t.Fatal(err)
	}
	s := &GPOService{gpoCfg: config.GPOConfig{ADMXPath: file, ManagedEditorFile: filepath.Join(dir, "settings", "gpo-editor.json")}}
	share := &sysvolShare{ctx: context.Background()}
	imported, _, err := s.editorDefinitions(share, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, []byte(typedEditorADMX+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	live, _, err := s.editorDefinitions(&sysvolShare{ctx: context.WithValue(context.Background(), freshTemplatesKey{}, true)}, "example.com")
	if err != nil || live[0].Digest == imported[0].Digest {
		t.Fatal("save-time validation did not read current templates", err)
	}
	stillImported, _, err := s.editorDefinitions(share, "example.com")
	if err != nil || !reflect.DeepEqual(imported, stillImported) {
		t.Fatal("validation replaced the permanent import", err)
	}
	// Memory pressure may evict entries from RAM, never from persistent storage.
	for i := 0; i < 12; i++ {
		if err = s.storeTemplateCache(templateCatalog{Schema: 1, Key: fmt.Sprint(i), Loaded: time.Now(), Source: "fixture", Definitions: imported}); err != nil {
			t.Fatal(err)
		}
	}
	restarted := &GPOService{gpoCfg: s.gpoCfg}
	cached, _, err := restarted.editorDefinitions(share, "example.com")
	if err != nil || !reflect.DeepEqual(cached, imported) {
		t.Fatal("another import evicted persistent templates", err)
	}
}
