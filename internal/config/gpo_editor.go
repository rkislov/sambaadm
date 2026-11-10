package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// EffectiveEditorEnabled reads an atomic UI override without mutating shared config.
// A malformed/unreadable override must not silently enable writes.
func (c GPOConfig) EffectiveEditorEnabled() (bool, error) {
	if c.ManagedEditorFile == "" {
		return c.EditorEnabled, nil
	}
	raw, err := os.ReadFile(c.ManagedEditorFile)
	if os.IsNotExist(err) {
		return c.EditorEnabled, nil
	}
	if err != nil {
		return false, err
	}
	var enabled *bool
	if err := json.Unmarshal(raw, &enabled); err != nil || enabled == nil {
		return false, fmt.Errorf("invalid GPO editor setting")
	}
	return *enabled, nil
}
