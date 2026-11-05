package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sambaadm/internal/agent"
)

// ManagedHelpers reads the last complete registration transaction.
func ManagedHelpers(dir string) (agent.Config, error) {
	var c agent.Config
	if !filepath.IsAbs(dir) {
		return c, fmt.Errorf("enrollment_dir must be absolute")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "nodes.json"))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}
