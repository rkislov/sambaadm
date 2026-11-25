package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sambaadm/internal/config"
	"strings"
	"testing"
	"time"
)

func TestSYSVOLSyncVersionsAndLocalChanges(t *testing.T) {
	snap := func(v string) *repairSnapshot {
		return &repairSnapshot{Signature: v, Objects: []repairObject{{Path: "GPT.INI", Data: []byte("[General]\nVersion=" + v + "\n")}}}
	}
	if e := safeSyncVersions(snap("65538"), snap("131073")); e == nil {
		t.Fatal("computer counter was allowed to decrease")
	}
	if e := safeSyncVersions(snap("131073"), snap("65538")); e == nil {
		t.Fatal("user counter was allowed to decrease")
	}
	if e := safeSyncVersions(snap("65537"), snap("131074")); e != nil {
		t.Fatal(e)
	}
	if e := safeSyncVersions(&repairSnapshot{}, snap("0")); e == nil {
		t.Fatal("unknown target version accepted")
	}
	p := &RepairPlan{Preview: "private-token", record: &RepairRecord{Before: snap("1"), After: snap("2")}, Changes: []ConsistencyDifference{{Path: "GPT.INI", Kind: "content"}}}
	item := SYSVOLSyncItem{}
	syncPlanItem(&item, p, "baseline", nil)
	if item.State != "conflict" {
		t.Fatal(item)
	}
	item = SYSVOLSyncItem{}
	syncPlanItem(&item, p, "1", nil)
	if item.State != "ready" || item.Version != 2 {
		t.Fatal(item)
	}
	raw, _ := json.Marshal(item)
	if strings.Contains(string(raw), "private-token") {
		t.Fatal("private token leaked")
	}
	p.record.Before = p.record.After
	p.Changes = nil
	syncPlanItem(&item, p, "old baseline", nil)
	if item.State != "identical" {
		t.Fatal(item)
	}
}
func TestSYSVOLSyncJournalSurvivesRestartAndRejectsReplay(t *testing.T) {
	s := &GPOService{gpoCfg: config.GPOConfig{DelegationStateDir: filepath.Join(t.TempDir(), "private")}}
	j := &SYSVOLSyncJob{ID: "10000000-0000-0000-0000-000000000001", State: "running", Created: time.Now(), Items: []SYSVOLSyncItem{{State: "running", Preview: "token", Signature: "snapshot"}}}
	if e := s.saveSync(j); e != nil {
		t.Fatal(e)
	}
	loaded, e := s.SYSVOLSyncRead(j.ID)
	if e != nil || loaded.State != "interrupted" || loaded.Items[0].State != "unknown" || loaded.Items[0].Preview != "token" {
		t.Fatal(loaded, e)
	}
	if _, e = s.SYSVOLSyncApply(context.Background(), j.ID, "old", "test", "", true); !errors.Is(e, ErrTopologyConflict) {
		t.Fatal(e)
	}
	root, e := s.syncRoot()
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	st, e := root.Stat(j.ID + ".json")
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal(st, e)
	}
	if _, e = s.SYSVOLSyncRead("../../config"); e == nil {
		t.Fatal("path traversal accepted")
	}
	if e = s.syncRemember(&SYSVOLSyncJob{Input: SYSVOLSyncInput{Source: "source.example"}}, SYSVOLSyncItem{GPO: "policy", Target: "target", Signature: "signed receipt"}); e != nil {
		t.Fatal(e)
	}
	baseline, e := s.syncBaseline("POLICY", "TARGET")
	if e != nil || baseline != "signed receipt" {
		t.Fatal(baseline, e)
	}
}

func TestSYSVOLSourceRejectsEveryWrite(t *testing.T) {
	s := &sysvolShare{readOnly: true}
	for _, err := range []error{s.WriteFile("x", nil, 0600), s.Mkdir("x", 0700), s.MkdirAll("x", 0700), s.Remove("x"), s.RemoveAll("x"), s.Rename("x", "y"), s.SetSecurityInfoRaw("x", 0, nil)} {
		if !errors.Is(err, os.ErrPermission) {
			t.Fatal("source write allowed", err)
		}
	}
	if _, err := s.OpenFile("x", os.O_WRONLY, 0600); !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
}

func TestSYSVOLSyncExcludesLegacyDistribution(t *testing.T) {
	jobs := newJobStore()
	if e := jobs.reserveSYSVOL(); e != nil {
		t.Fatal(e)
	}
	if e := jobs.start(newDistributeJob("policy", "admin")); !errors.Is(e, ErrGPOBulkDeliveryActive) {
		t.Fatal(e)
	}
	jobs.releaseSYSVOL()
	j := newDistributeJob("policy", "admin")
	if e := jobs.start(j); e != nil {
		t.Fatal(e)
	}
	if e := jobs.reserveSYSVOL(); !errors.Is(e, ErrGPOBulkDeliveryActive) {
		t.Fatal(e)
	}
	jobs.update(j.ID, func(j *DistributeJob) { j.Status = JobOK })
	if e := jobs.reserveSYSVOL(); e != nil {
		t.Fatal(e)
	}
	jobs.releaseSYSVOL()
}

func TestSYSVOLSyncRecoveryKeepsKerberosTransport(t *testing.T) {
	_, root, record := repairFixture(t, false)
	record.Kerberos = true
	if e := saveRepair(root, record); e != nil {
		t.Fatal(e)
	}
	loaded, e := readRepair(root, record.ID)
	if e != nil || !loaded.Kerberos {
		t.Fatal("recovery lost transport", e)
	}
}
