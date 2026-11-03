package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"sambaadm/internal/config"
)

// A persisted deletion manifest makes partial cleanup and lost SMB replies
// retryable. Only individually listed objects are removed; never RemoveAll.
type repairCleanupTree struct {
	Name  string
	Files []ConsistencyFile
}
type RepairCleanupInfo struct {
	Path    string `json:"path"`
	Objects int    `json:"objects"`
	Bytes   int64  `json:"bytes"`
}

func validRepairStage(id, name string) bool {
	prefix := ".sambaadm-repair-" + id + "-"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	u, e := uuid.Parse(strings.TrimPrefix(name, prefix))
	return e == nil && u.String() == strings.TrimPrefix(name, prefix)
}

func validateRepairCleanup(r *RepairRecord) error {
	if len(r.Stages) > 8 || len(r.Cleanup) > 10 {
		return fmt.Errorf("invalid repair cleanup limits")
	}
	for _, n := range r.Stages {
		if !validRepairStage(r.ID, n) {
			return fmt.Errorf("invalid repair stage")
		}
	}
	seen := map[string]bool{}
	for _, tree := range r.Cleanup {
		if seen[tree.Name] || (tree.Name != repairBackup(r) && tree.Name != repairArchive(r) && !validRepairStage(r.ID, tree.Name)) || len(tree.Files) == 0 || len(tree.Files) > consistencyObjects {
			return fmt.Errorf("invalid repair cleanup tree")
		}
		seen[tree.Name] = true
		paths := map[string]bool{}
		for _, f := range tree.Files {
			if paths[strings.ToLower(f.Path)] || (f.Path != "." && (f.Path == ".." || path.Clean(f.Path) != f.Path || strings.HasPrefix(f.Path, "../") || path.IsAbs(f.Path) || strings.ContainsAny(f.Path, `\:`))) || (f.Kind != "file" && f.Kind != "directory") || f.Size < 0 || f.Size > consistencyBytes {
				return fmt.Errorf("invalid repair cleanup object")
			}
			paths[strings.ToLower(f.Path)] = true
		}
	}
	if r.State != "pruning" && len(r.Cleanup) != 0 {
		return fmt.Errorf("unexpected cleanup manifest")
	}
	return nil
}

func repairRetention(records []RepairSummary, cfg config.GPOConfig) []RepairSummary {
	keep, mib := cfg.RepairBackupKeep, cfg.RepairBackupMaxMiB
	if keep <= 0 {
		keep = 10
	}
	if mib <= 0 {
		mib = 512
	}
	blocked := false
	for _, r := range records {
		if r.State == "pending" || r.State == "pruning" {
			blocked = true
		}
	}
	latest := map[string]bool{}
	var bytes int64
	count := 0
	for i := range records {
		r := &records[i]
		if r.State == "pruned" {
			continue
		}
		key := strings.ToLower(r.Target)
		r.Protected = blocked || !latest[key]
		latest[key] = true
		count++
		bytes += r.Bytes
		r.Prunable = !r.Protected && (count > keep || bytes > int64(mib)<<20)
	}
	return records
}

func repairPruneAllowed(local *os.Root, r *RepairRecord, cfg config.GPOConfig) error {
	records, e := repairRecords(local, r.GPO)
	if e != nil {
		return e
	}
	if r.State == "pruning" {
		for _, other := range records {
			if other.ID != r.ID && (other.State == "pending" || other.State == "pruning") {
				return ErrTopologyConflict
			}
		}
		return nil
	}
	for _, item := range repairRetention(records, cfg) {
		if item.ID == r.ID && item.Prunable {
			return nil
		}
	}
	return topologyBad("archive is protected or within retention limits")
}

func scanRepairCleanup(ctx context.Context, v repairVolume, r *RepairRecord) ([]repairCleanupTree, error) {
	names := []string{repairBackup(r), repairArchive(r)}
	names = append(names, r.Stages...)
	if r.Stage != "" {
		names = append(names, r.Stage)
	}
	seen := map[string]bool{}
	out := []repairCleanupTree{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		root := v.Tree(name)
		if _, e := root.Lstat("."); os.IsNotExist(e) {
			continue
		} else if e != nil {
			return nil, e
		}
		first, e := scanPolicyTreeMetadata(ctx, root, true, true)
		if e != nil {
			return nil, e
		}
		second, e := scanPolicyTreeMetadata(ctx, root, true, true)
		if e != nil {
			return nil, e
		}
		if first.Signature != second.Signature {
			return nil, ErrTopologyConflict
		}
		out = append(out, repairCleanupTree{Name: name, Files: first.Files})
	}
	return out, nil
}

func checkRepairCleanup(ctx context.Context, v repairVolume, trees []repairCleanupTree) error {
	for _, tree := range trees {
		root := v.Tree(tree.Name)
		if _, e := root.Lstat("."); os.IsNotExist(e) {
			continue
		} else if e != nil {
			return e
		}
		snap, e := scanPolicyTreeMetadata(ctx, root, true, true)
		if e != nil {
			return e
		}
		allowed := map[string]ConsistencyFile{}
		for _, f := range tree.Files {
			allowed[f.Path] = f
		}
		for _, f := range snap.Files {
			if old, ok := allowed[f.Path]; !ok || old != f {
				return ErrTopologyConflict
			}
		}
	}
	return nil
}

func repairCleanupInfo(trees []repairCleanupTree) []RepairCleanupInfo {
	out := []RepairCleanupInfo{}
	for _, tree := range trees {
		item := RepairCleanupInfo{Path: tree.Name, Objects: len(tree.Files)}
		for _, f := range tree.Files {
			item.Bytes += f.Size
		}
		out = append(out, item)
	}
	return out
}

func (s *GPOService) buildRepairPrune(ctx context.Context, local *os.Root, gpo string, in RepairInput) (*RepairPlan, error) {
	r, e := readRepair(local, in.Record)
	if e != nil {
		return nil, e
	}
	if r.GPO != braceGUID(gpo) {
		return nil, topologyBad("record belongs to another GPO")
	}
	if e = repairPruneAllowed(local, r, s.gpoCfg); e != nil {
		return nil, e
	}
	e = s.withRepairDC(ctx, gpo, r.Target, func(_ *GPOService, _ *ldap.Entry, v repairVolume, base string) error {
		if base != r.Base {
			return ErrTopologyConflict
		}
		if r.State == "pruning" {
			return checkRepairCleanup(ctx, v, r.Cleanup)
		}
		r.Cleanup, e = scanRepairCleanup(ctx, v, r)
		return e
	})
	if e != nil {
		return nil, e
	}
	return &RepairPlan{Operation: "prune", Source: r.Source, Target: r.Target, Record: r.ID, Preview: consistencyHash([]any{r, s.gpoCfg.RepairBackupKeep, s.gpoCfg.RepairBackupMaxMiB}), Changes: []ConsistencyDifference{}, ACLChanges: []RepairACLChange{}, Cleanup: repairCleanupInfo(r.Cleanup), Warnings: []string{"Permanently deletes these remote archive trees, including service backups and all file metadata, and discards local rollback snapshots. Live SYSVOL is not changed. Stop external editors and synchronizers during cleanup."}, record: r}, nil
}

func runRepairPrune(ctx context.Context, v repairVolume, local *os.Root, r *RepairRecord) error {
	if r.State != "pruning" {
		return fmt.Errorf("durable cleanup journal required")
	}
	if e := validateRepairCleanup(r); e != nil {
		return e
	}
	if e := checkRepairCleanup(ctx, v, r.Cleanup); e != nil {
		return e
	}
	for _, tree := range r.Cleanup {
		root := v.Tree(tree.Name)
		files := append([]ConsistencyFile(nil), tree.Files...)
		// Descendants before parents. Remove refuses nonempty directories.
		sort.Slice(files, func(i, j int) bool { return len(files[i].Path) > len(files[j].Path) })
		for _, f := range files {
			if e := ctx.Err(); e != nil {
				return e
			}
			info, e := root.Lstat(f.Path)
			if os.IsNotExist(e) {
				continue
			}
			if e != nil {
				return e
			}
			if info.Mode()&os.ModeSymlink != 0 || (f.Kind == "directory") != info.IsDir() || (!info.IsDir() && !info.Mode().IsRegular()) {
				return ErrTopologyConflict
			}
			acl, e := root.(policySecurityStore).GetACL(f.Path)
			if e != nil {
				return e
			}
			a, e := consistencyACL(acl)
			if e != nil {
				return e
			}
			if a != f.ACL {
				return ErrTopologyConflict
			}
			if f.Kind == "file" {
				file, e := root.Open(f.Path)
				if e != nil {
					return e
				}
				h := sha256.New()
				n, e := io.Copy(h, io.LimitReader(file, consistencyBytes+1))
				e = errors.Join(e, file.Close())
				if e != nil {
					return e
				}
				if n != f.Size || fmt.Sprintf("%x", h.Sum(nil)) != f.SHA256 {
					return ErrTopologyConflict
				}
			}
			if e = root.Remove(f.Path); e != nil {
				return e
			}
		}
	}
	// Keep a compact history entry so older repairs cannot bypass ordering.
	r.State = "pruned"
	r.Before, r.After, r.Cleanup, r.Stages = nil, nil, nil, nil
	r.Stage = ""
	return saveRepair(local, r)
}
