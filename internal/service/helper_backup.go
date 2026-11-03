package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sambaadm/internal/config"
	"strings"
)

func helperBackup(cfg *config.Config, method string, in HostOperation) (any, error) {
	base := cfg.Helper.BackupRoot
	if base == "" {
		return nil, fmt.Errorf("helper.backup_root is required")
	}
	if !filepath.IsAbs(base) || !filepath.IsAbs(in.Path) {
		return nil, fmt.Errorf("absolute helper backup paths required")
	}
	rel, e := filepath.Rel(base, in.Path)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("backup path outside helper backup root")
	}
	root, e := os.OpenRoot(base)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	if method == "backup.store" {
		if !looksLikeGUID(in.Name) {
			return nil, fmt.Errorf("backup GPO GUID required")
		}
		var backup policyBackup
		if e = decodeHost(in.Input, &backup); e != nil {
			return nil, e
		}
		if backup.Format != 1 {
			return nil, fmt.Errorf("unsupported backup format")
		}
		dir := filepath.Join(rel, "policy", in.Name)
		if e = root.MkdirAll(dir, 0700); e != nil {
			return nil, e
		}
		data, e := json.MarshalIndent(backup, "", "  ")
		if e != nil {
			return nil, e
		}
		if len(data) > 100<<20 {
			return nil, fmt.Errorf("backup exceeds limit")
		}
		f, e := root.OpenFile(filepath.Join(dir, "sambaadm-backup.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		_, e = f.Write(data)
		if e == nil {
			e = f.Sync()
		}
		return nil, errors.Join(e, f.Close())
	}
	name := filepath.Join(rel, "sambaadm-backup.json")
	st, e := root.Lstat(name)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() > 100<<20 {
		return nil, fmt.Errorf("invalid backup file")
	}
	data, e := root.ReadFile(name)
	if e != nil {
		return nil, e
	}
	var backup policyBackup
	e = json.Unmarshal(data, &backup)
	return backup, e
}
