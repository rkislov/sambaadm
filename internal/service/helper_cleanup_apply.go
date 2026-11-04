package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sambaadm/internal/config"
	"strconv"
	"time"
)

func helperCleanupApply(ctx context.Context, cfg *config.Config, method string, in HostOperation) (any, error) {
	root, e := backupRoot(cfg)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	if !validBackupID(in.Name) {
		return nil, topologyBad("valid backup ID required")
	}
	if method == "topology.cleanup.reserve" {
		job, err := localBackupStatus(ctx, root, in.Name)
		if err != nil {
			return nil, err
		}
		if job.Plan == nil || job.PlanRevision != in.Revision {
			return nil, ErrTopologyConflict
		}
		if err = validateCleanupBackup(job.Plan, job); err != nil {
			return nil, err
		}
		if _, err = cleanupOrder(job.Plan); err != nil {
			return nil, err
		}
		f, err := root.Open(in.Name + "/domain.tar.gz")
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return nil, err
		}
		if hex.EncodeToString(h.Sum(nil)) != job.SHA256 {
			return nil, fmt.Errorf("backup checksum changed")
		}
		for _, o := range job.Plan.Objects {
			if cleanupDCRemnant(o) && in.Value != "permanently-decommissioned" {
				return nil, topologyBad("permanent retirement confirmation required")
			}
		}
		record := map[string]any{"revision": in.Revision, "sha256": job.SHA256, "actor": in.Actor, "decommissionConfirmed": in.Value == "permanently-decommissioned", "ip": in.IP, "time": time.Now().UTC()}
		if err = createBackupJSON(root, in.Name+"/apply.json", record); err != nil {
			if os.IsExist(err) {
				return nil, topologyBad("backup application already reserved; inspect journal before preparing a new plan")
			}
			return nil, err
		}
		return record, nil
	}
	var reservation map[string]any
	if e = readBackupJSON(root, in.Name+"/apply.json", &reservation); e != nil {
		return nil, e
	}
	var event CleanupApplyEvent
	if e = decodeHost(in.Input, &event); e != nil {
		return nil, e
	}
	if event.Step < 0 || event.Step > 302 || len(event.DN) > 4096 || len(event.Detail) > 8192 {
		return nil, topologyBad("invalid cleanup journal event")
	}
	switch event.Status {
	case "deleting", "deleted", "updating", "updated", "stopped", "completed":
	default:
		return nil, topologyBad("invalid cleanup journal state")
	}
	event.Time = time.Now().UTC()
	name := in.Name + "/apply-event-" + strconv.Itoa(event.Step) + ".json"
	if e = createBackupJSON(root, name, event); e != nil {
		return nil, e
	}
	return &event, nil
}
