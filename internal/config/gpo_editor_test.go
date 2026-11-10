package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEditorOverrideDefaultsAndRejectsInvalidState(t *testing.T) {
	file := filepath.Join(t.TempDir(), "gpo-editor.json")
	cfg := GPOConfig{EditorEnabled: true, ManagedEditorFile: file}
	if enabled, err := cfg.EffectiveEditorEnabled(); err != nil || !enabled {
		t.Fatal("YAML default lost", enabled, err)
	}
	for _, raw := range []string{"null", " null\n", "{}", "\"true\"", "true false", ""} {
		os.WriteFile(file, []byte(raw), 0600)
		if enabled, err := cfg.EffectiveEditorEnabled(); err == nil || enabled {
			t.Fatalf("invalid override enabled writes: %q %v %v", raw, enabled, err)
		}
	}
	os.WriteFile(file, []byte("false"), 0600)
	if enabled, err := cfg.EffectiveEditorEnabled(); err != nil || enabled {
		t.Fatal("disabled override ignored", enabled, err)
	}
}
