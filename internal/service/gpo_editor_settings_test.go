package service

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"sambaadm/internal/audit"
	"sambaadm/internal/config"
)

func TestEditorToggleIsAtomicAndKeepsWritesDisabled(t *testing.T) {
	log, err := audit.New(filepath.Join(t.TempDir(), "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	s := &GPOService{audit: log, gpoCfg: config.GPOConfig{EditorEnabled: true, ManagedEditorFile: filepath.Join(t.TempDir(), "settings", "gpo-editor.json")}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if _, err := s.EditorEnabled(); err != nil {
				t.Error("observed partial state file", err)
			}
		}
	}()
	for i := 0; i < 10; i++ {
		if err := s.SetEditorEnabled(i%2 == 0); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if err := s.SetEditorEnabled(false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetALTSetting(t.Context(), "test", ALTChange{}, "test", ""); !errors.Is(err, ErrEditorUnavailable) {
		t.Fatal("editor writes not blocked", err)
	}
	if _, err := s.ALTSettings(t.Context(), "test"); !errors.Is(err, ErrEditorUnavailable) {
		t.Fatal("editor entry still available", err)
	}
	stat, err := os.Stat(filepath.Dir(s.gpoCfg.ManagedEditorFile))
	if err != nil || stat.Mode().Perm() != 0700 {
		t.Fatal("unsafe directory permissions", err)
	}
}
