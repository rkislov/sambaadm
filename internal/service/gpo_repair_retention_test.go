package service

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"sambaadm/internal/config"
)

func TestRepairRetentionProtectsLatestPerDCAndPending(t *testing.T) {
	records := []RepairSummary{
		{ID: "a", Target: "DC1", State: "complete", Bytes: 2 << 20},
		{ID: "b", Target: "dc1", State: "rolled-back", Bytes: 2 << 20},
		{ID: "c", Target: "DC2", State: "complete", Bytes: 2 << 20},
		{ID: "d", Target: "dc1", State: "pruned", Bytes: 100},
	}
	for _, cfg := range []config.GPOConfig{{RepairBackupKeep: 1, RepairBackupMaxMiB: 512}, {RepairBackupKeep: 10, RepairBackupMaxMiB: 1}} {
		out := repairRetention(append([]RepairSummary(nil), records...), cfg)
		if !out[0].Protected || !out[2].Protected || !out[1].Prunable || out[3].Prunable {
			t.Fatalf("unsafe retention: %+v", out)
		}
		for _, state := range []string{"pending", "pruning"} {
			input := append(append([]RepairSummary(nil), records...), RepairSummary{ID: "pending", Target: "dc3", State: state})
			for _, r := range repairRetention(input, cfg) {
				if r.Prunable {
					t.Fatalf("cleanup during %s", state)
				}
			}
		}
	}
}

func cleanupFixture(t *testing.T) (*repairTestVolume, *os.Root, *RepairRecord) {
	t.Helper()
	v, local, r := repairFixture(t, false)
	ctx := context.Background()
	v.failStage = true
	if e := runRepair(ctx, v, local, r, func() error { return nil }); e == nil {
		t.Fatal("expected partial staging")
	}
	v.failStage = false
	if e := runRepair(ctx, v, local, r, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	// Service backups must be included, even though normal consistency ignores them.
	if e := createDurablePolicyFile(v.Tree(repairBackup(r)), ".sambaadm-service-backup", []byte("service metadata")); e != nil {
		t.Fatal(e)
	}
	var e error
	r.Cleanup, e = scanRepairCleanup(ctx, v, r)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Cleanup) != 2 {
		t.Fatalf("partial staging not included: %+v", r.Cleanup)
	}
	r.State = "pruning"
	if e = saveRepair(local, r); e != nil {
		t.Fatal(e)
	}
	return v, local, r
}

func TestRepairPruneResumesAfterEveryDeleteBoundary(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		for boundary := 1; boundary <= 8; boundary++ {
			v, local, r := cleanupFixture(t)
			liveSignature := r.After.Signature
			v.removes, v.failRemove, v.uncertainRemove = 0, boundary, uncertain
			if e := runRepairPrune(context.Background(), v, local, r); e == nil {
				t.Fatalf("expected failure at %d", boundary)
			}
			r, e := readRepair(local, r.ID)
			if e != nil || r.State != "pruning" {
				t.Fatalf("cleanup not durable: %v", e)
			}
			v.failRemove = 0
			if e = runRepairPrune(context.Background(), v, local, r); e != nil {
				t.Fatal(e)
			}
			r, e = readRepair(local, r.ID)
			if e != nil || r.State != "pruned" || r.After != nil || r.Before != nil {
				t.Fatalf("snapshots retained: %v", e)
			}
			if _, e = v.Tree(repairBackup(r)).Lstat("."); !os.IsNotExist(e) {
				t.Fatal("remote archive retained", e)
			}
			if got, e := captureRepair(context.Background(), v.Tree("live")); e != nil || got.Signature != liveSignature {
				t.Fatal("live tree affected", e)
			}
		}
	}
}

func TestRepairPruneRefusesSymlinksAndChangedACL(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		v, local, r := cleanupFixture(t)
		if symlink {
			if e := v.root.Symlink("GPT.INI", repairBackup(r)+"/link"); e != nil {
				t.Fatal(e)
			}
		} else {
			v.acl[repairBackup(r)+"/GPT.INI"] = nil
		}
		before := v.removes
		if e := runRepairPrune(context.Background(), v, local, r); e == nil {
			t.Fatal("unsafe archive accepted")
		}
		if v.removes != before {
			t.Fatal("unsafe archive deleted data")
		}
	}
}

func TestRepairPruneRefusesChangedOrAddedArchiveObjects(t *testing.T) {
	for _, added := range []bool{false, true} {
		v, local, r := cleanupFixture(t)
		name := "GPT.INI"
		if added {
			name = "unlisted"
		}
		write := writePolicyFile
		if added {
			write = createDurablePolicyFile
		}
		if e := write(v.Tree(repairBackup(r)), name, []byte("changed")); e != nil {
			t.Fatal(e)
		}
		before := v.removes
		if e := runRepairPrune(context.Background(), v, local, r); !errors.Is(e, ErrTopologyConflict) {
			t.Fatal(e)
		}
		if v.removes != before {
			t.Fatal("conflict deleted data")
		}
	}
}

func TestRepairPruneEligibilityAndTombstone(t *testing.T) {
	_, local, r := repairFixture(t, false)
	r.State = "complete"
	if e := saveRepair(local, r); e != nil {
		t.Fatal(e)
	}
	cfg := config.GPOConfig{RepairBackupKeep: 1}
	if e := repairPruneAllowed(local, r, cfg); e == nil {
		t.Fatal("latest archive not protected")
	}
	newer := *r
	newer.ID = uuid.NewString()
	newer.Created = r.Created.Add(time.Second)
	if e := saveRepair(local, &newer); e != nil {
		t.Fatal(e)
	}
	if e := repairPruneAllowed(local, r, cfg); e != nil {
		t.Fatal(e)
	}
	newer.State = "pending"
	if e := saveRepair(local, &newer); e != nil {
		t.Fatal(e)
	}
	if e := repairPruneAllowed(local, r, cfg); e == nil {
		t.Fatal("cleanup allowed during recovery")
	}
	r.State = "pruned"
	r.Before = nil
	r.After = nil
	if e := saveRepair(local, r); e != nil {
		t.Fatal(e)
	}
	if _, e := readRepair(local, r.ID); e != nil {
		t.Fatal(e)
	}
	r.Cleanup = []repairCleanupTree{{Name: "live", Files: []ConsistencyFile{{Path: ".", Kind: "directory"}}}}
	if e := validateRepairCleanup(r); e == nil {
		t.Fatal("live tree accepted")
	}
}
