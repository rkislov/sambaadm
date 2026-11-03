package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type pinnedHostPath struct {
	Path string
	File *os.File
}

func (p *pinnedHostPath) Close() {
	if p.File != nil {
		p.File.Close()
	}
}
func (s *ShareService) shareRoot(path string, createRoot bool) (*os.Root, string, error) {
	if e := s.validatePath(path); e != nil {
		return nil, "", e
	}
	base := s.cfg.SharesRoot
	if s.cfg.AllowAnyPath {
		base = filepath.VolumeName(path) + string(filepath.Separator)
	}
	if createRoot {
		if e := os.MkdirAll(base, 0755); e != nil {
			return nil, "", e
		}
	}
	rel, e := filepath.Rel(base, path)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("path outside share root")
	}
	root, e := os.OpenRoot(base)
	return root, rel, e
}
func (s *ShareService) prepareDir(path, mode, owner string) (*pinnedHostPath, error) {
	perm := os.FileMode(0755)
	if mode != "" {
		v, e := strconv.ParseUint(strings.TrimPrefix(mode, "0"), 8, 32)
		if e != nil {
			return nil, e
		}
		perm = os.FileMode(v)
	}
	root, rel, e := s.shareRoot(path, true)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	if e = root.MkdirAll(rel, perm); e != nil {
		return nil, e
	}
	pin, e := pinHostPath(root, rel, path)
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(pin.Path, perm); e != nil {
		pin.Close()
		return nil, e
	}
	if owner != "" {
		if e = chownPath(pin.Path, owner); e != nil {
			pin.Close()
			return nil, e
		}
	}
	return pin, nil
}
func (s *ShareService) pinPath(path string) (*pinnedHostPath, error) {
	root, rel, e := s.shareRoot(path, false)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	return pinHostPath(root, rel, path)
}
func (s *ShareService) removeSharePath(path string) error {
	root, rel, e := s.shareRoot(path, false)
	if e != nil {
		return e
	}
	defer root.Close()
	if rel == "." {
		return fmt.Errorf("cannot remove the configured share root")
	}
	return root.RemoveAll(rel)
}
