package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"sambaadm/internal/config"
)

const cleanupSnapshotLimit = 2 << 20

type CleanupReceipt struct {
	ID       string    `json:"id"`
	SHA256   string    `json:"sha256"`
	Created  time.Time `json:"created"`
	Verified bool      `json:"verified"`
}

func helperTopologySnapshot(cfg *config.Config, method string, in HostOperation) (any, error) {
	if !filepath.IsAbs(cfg.Helper.BackupRoot) {
		return nil, fmt.Errorf("absolute helper.backup_root required")
	}
	root, err := os.OpenRoot(cfg.Helper.BackupRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	const dir = "topology-snapshots"
	if method == "topology.snapshot.store" {
		if err = root.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}
	st, err := root.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("snapshot directory must be private and not a symlink")
	}
	sub, err := root.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer sub.Close()
	if method == "topology.snapshot.store" {
		if len(in.Input) > cleanupSnapshotLimit {
			return nil, fmt.Errorf("snapshot exceeds limit")
		}
		var plan CleanupPlan
		if err = decodeHost(in.Input, &plan); err != nil {
			return nil, err
		}
		if plan.Format != 1 || plan.CanApply || len(plan.Objects) == 0 || len(plan.Objects) > 150 || plan.Revision != cleanupRevision(&plan) {
			return nil, fmt.Errorf("invalid read-only cleanup snapshot")
		}
		data, err := json.Marshal(plan)
		if err != nil {
			return nil, err
		}
		id := uuid.NewString()
		name := id + ".json"
		f, err := sub.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		if _, err = f.Write(data); err != nil {
			f.Close()
			return nil, err
		}
		err = f.Sync()
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		// Persist the directory entry before reporting success.
		d, err := sub.Open(".")
		if err != nil {
			return nil, err
		}
		err = d.Sync()
		d.Close()
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(data)
		return &CleanupReceipt{ID: id, SHA256: hex.EncodeToString(h[:]), Created: time.Now().UTC()}, nil
	}
	id, err := uuid.Parse(in.Name)
	if err != nil || id.String() != in.Name || len(in.Revision) != 64 {
		return nil, fmt.Errorf("invalid snapshot identity or checksum")
	}
	name := in.Name + ".json"
	st, err = sub.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > cleanupSnapshotLimit {
		return nil, fmt.Errorf("invalid snapshot file")
	}
	f, err := sub.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, cleanupSnapshotLimit+1))
	if err != nil {
		return nil, err
	}
	if len(data) > cleanupSnapshotLimit {
		return nil, fmt.Errorf("snapshot exceeds limit")
	}
	h := sha256.Sum256(data)
	if hex.EncodeToString(h[:]) != in.Revision {
		return nil, fmt.Errorf("snapshot checksum mismatch")
	}
	var plan CleanupPlan
	if err = decodeHost(data, &plan); err != nil {
		return nil, err
	}
	if plan.Format != 1 || plan.CanApply || plan.Revision != cleanupRevision(&plan) {
		return nil, fmt.Errorf("snapshot plan mismatch")
	}
	return &plan, nil
}
