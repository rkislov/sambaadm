package service

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type sharePermissionJournal struct {
	ID      string                      `json:"id"`
	Share   string                      `json:"share"`
	Root    string                      `json:"root"`
	Actor   string                      `json:"actor"`
	Created time.Time                   `json:"created"`
	Plan    *SharePermissionPlan        `json:"plan"`
	Result  *SharePermissionApplyResult `json:"result"`
}

func openSharePermissionJournal(stateDir string) (*os.Root, error) {
	if !filepath.IsAbs(stateDir) {
		return nil, fmt.Errorf("для журнала прав требуется абсолютный helper.state_dir")
	}
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	const sub = "permission-maps"
	if err = root.Mkdir(sub, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	info, err := root.Lstat(sub)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("каталог журнала прав должен быть приватным и не являться символьной ссылкой")
	}
	return root.OpenRoot(sub)
}
func saveSharePermissionJournal(root *os.Root, journal *sharePermissionJournal) error {
	data, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	temp := journal.ID + "-" + uuid.NewString() + ".tmp"
	file, err := root.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temp)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return root.Rename(temp, journal.ID+".json")
}
func replaceSharePermissionACL(ctx context.Context, path, access, defaults string) error {
	run := func(args ...string) error {
		args = append(args, "--", path)
		cmd := exec.CommandContext(ctx, "setfacl", args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("setfacl: %w (%s)", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run("--no-mask", "--set="+strings.ReplaceAll(access, "\n", ",")); err != nil {
		return err
	}
	// Replace a nonempty default ACL directly, without a transient removal of
	// inheritance. Empty defaults require an explicit removal.
	if defaults == "" {
		return run("-k")
	}
	return run("-d", "--no-mask", "--set="+strings.ReplaceAll(strings.ReplaceAll(defaults, "default:", ""), "\n", ","))
}
func (s *ShareService) ApplyPermissionMap(ctx context.Context, name string, in SharePermissionMapRequest, actor, ip, stateDir string) (*SharePermissionApplyResult, error) {
	if !in.Confirm || in.PlanRevision == "" {
		return nil, fmt.Errorf("требуются подтверждение и версия предпросмотра")
	}
	if s.helpers != nil {
		var out SharePermissionApplyResult
		err := s.hostCall(ctx, "shares.permission-map.apply", HostOperation{Name: name, Input: hostInput(in), Actor: actor, IP: ip}, &out)
		return &out, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	scoped, _, err := s.scopedACL(ctx, name, in.Root)
	if err != nil {
		return nil, err
	}
	defer scoped.root.Close()
	snapshot, err := scoped.capturePermissionMap(ctx, name, in.Root)
	if err != nil {
		return nil, err
	}
	plan, err := planSharePermissionMap(snapshot, in)
	if err != nil {
		return nil, err
	}
	if plan.Revision != in.PlanRevision {
		return nil, ErrShareMapConflict
	}
	journalRoot, err := openSharePermissionJournal(stateDir)
	if err != nil {
		return nil, err
	}
	defer journalRoot.Close()
	result := &SharePermissionApplyResult{ID: uuid.NewString(), Status: "pending", Items: []SharePermissionApplyItem{}}
	result.Journal = filepath.Join(stateDir, "permission-maps", result.ID+".json")
	for _, change := range plan.Changes {
		result.Items = append(result.Items, SharePermissionApplyItem{Path: change.Path, Status: "pending"})
	}
	journal := &sharePermissionJournal{ID: result.ID, Share: name, Root: in.Root, Actor: actor, Created: time.Now().UTC(), Plan: plan, Result: result}
	if err = saveSharePermissionJournal(journalRoot, journal); err != nil {
		return nil, err
	}
	for i, change := range plan.Changes {
		item := &result.Items[i]
		apply := func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			current, err := scoped.readMapNode(ctx, change.Path)
			if err != nil {
				return err
			}
			if current.Revision != change.Before.Revision {
				return ErrShareMapConflict
			}
			pin, err := scoped.pinPath(filepath.Join(scoped.shares.cfg.SharesRoot, filepath.FromSlash(change.Path)))
			if err != nil {
				return err
			}
			defer pin.Close()
			info, err := pin.File.Stat()
			if err != nil {
				return err
			}
			if shareMapFileIdentity(info) != current.Identity {
				return ErrShareMapConflict
			}
			a, d, err := readACL(ctx, pin.Path)
			if err != nil {
				return err
			}
			a, d, err = canonicalShareACL(a, d)
			if err != nil {
				return err
			}
			if a != change.Before.Access || d != change.Before.Default {
				return ErrShareMapConflict
			}
			item.Status = "applying"
			if err = saveSharePermissionJournal(journalRoot, journal); err != nil {
				return err
			}
			if err = replaceSharePermissionACL(ctx, pin.Path, change.Access, change.Default); err != nil {
				return err
			}
			a, d, err = readACL(ctx, pin.Path)
			if err != nil {
				return err
			}
			a, d, err = canonicalShareACL(a, d)
			if err != nil {
				return err
			}
			if a != change.Access || d != change.Default {
				return fmt.Errorf("сервер не подтвердил записанный ACL")
			}
			return nil
		}
		if err = apply(); err != nil {
			item.Status = "failed"
			item.Error = err.Error()
			result.Status = "partial"
			if s.audit != nil {
				s.audit.Failure(actor, "shares.permission-map.apply", name+"/"+change.Path, ip, err)
			}
			if saveErr := saveSharePermissionJournal(journalRoot, journal); saveErr != nil {
				item.Error += "; журнал: " + saveErr.Error()
			}
			return result, nil
		}
		item.Status = "applied"
		if s.audit != nil {
			s.audit.Success(actor, "shares.permission-map.apply", name+"/"+change.Path, ip)
		}
		if err = saveSharePermissionJournal(journalRoot, journal); err != nil {
			result.Status = "partial"
			item.Error = "права записаны, обновление журнала не удалось: " + err.Error()
			return result, nil
		}
	}
	result.Status = "complete"
	if err = saveSharePermissionJournal(journalRoot, journal); err != nil {
		result.Status = "partial"
		result.Error = "Права записаны; итоговое обновление журнала не удалось: " + err.Error()
		return result, nil
	}
	return result, nil
}
