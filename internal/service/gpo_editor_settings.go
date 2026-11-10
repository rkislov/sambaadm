package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func (s *GPOService) EditorEnabled() (bool, error) { return s.gpoCfg.EffectiveEditorEnabled() }

// Wait for current editor/model reads to complete before changing availability.
// The override is durable and shared with new server/CLI processes.
func (s *GPOService) SetEditorEnabled(enabled bool) error {
	s.editorMu.Lock()
	defer s.editorMu.Unlock()
	file := s.gpoCfg.ManagedEditorFile
	if !filepath.IsAbs(file) {
		return fmt.Errorf("GPO editor settings file is not configured")
	}
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("GPO settings directory must not be a symlink")
	}
	f, err := os.CreateTemp(dir, ".gpo-editor-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	raw, _ := json.Marshal(enabled)
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	if err = os.Rename(f.Name(), file); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
