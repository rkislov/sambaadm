package service

import (
	"bytes"
	"context"
	"errors"
	"github.com/shirou/gopsutil/v4/cpu"
	"os"
	"path/filepath"
	"runtime"
	"sambaadm/internal/audit"
	"sambaadm/internal/config"
	"strings"
	"testing"
)

func TestProfilePreservesDomainAndShares(t *testing.T) {
	raw := []byte("# original\n[global]\n realm = EXAMPLE.TEST\n server role = active directory domain controller\n # keep comment\n server signing = default\n[team]\n path = /srv/team\n read only = no\n")
	p, _ := profileParameters("secure")
	v, e := patchGlobal(raw, p)
	if e != nil {
		t.Fatal(e)
	}
	for _, text := range []string{"realm = EXAMPLE.TEST", "server role = active directory domain controller", "# keep comment", "[team]\n path = /srv/team\n read only = no"} {
		if !strings.Contains(string(v), text) {
			t.Fatal(string(v))
		}
	}
	if bytes.Contains(v, []byte("server signing = default")) {
		t.Fatal("duplicate old value")
	}
	for _, bad := range []string{"[global]\ninclude = /tmp/a", "[global]\nx = one\\\ntwo", "[global]\n[global]", "[global]\nconfig backend = registry"} {
		if _, e := patchGlobal([]byte(bad), p); e == nil {
			t.Fatal(bad)
		}
	}
}
func TestProfileValidationBackupAndConflict(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "testparm")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0700)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	path := filepath.Join(dir, "smb.conf")
	original := []byte("[global]\nrealm = EXAMPLE.TEST\n[team]\npath = /srv/team\n")
	os.WriteFile(path, original, 0640)
	logger, e := audit.New(filepath.Join(dir, "audit"))
	if e != nil {
		t.Fatal(e)
	}
	defer logger.Close()
	s := newShareService(logger, config.SambaConfig{SMBConf: path})
	plan, e := s.PlanProfile(context.Background(), "compatible")
	if e != nil || !plan.Ready {
		t.Fatal(plan, e)
	}
	backup, e := s.ApplyProfile(context.Background(), "compatible", plan.Revision, "test", "local")
	if e != nil {
		t.Fatal(e)
	}
	saved, _ := os.ReadFile(backup)
	if !bytes.Equal(saved, original) {
		t.Fatal("backup mismatch")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0640 {
		t.Fatal("permissions changed")
	}
	if _, e = s.ApplyProfile(context.Background(), "secure", plan.Revision, "test", "local"); !errors.Is(e, ErrTopologyConflict) {
		t.Fatal(e)
	}
	plan, e = s.PlanProfile(context.Background(), "secure")
	if e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(path)
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 1\n"), 0700)
	if _, e = s.ApplyProfile(context.Background(), "secure", plan.Revision, "test", "local"); e == nil {
		t.Fatal("invalid config saved")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("validation failure modified config")
	}
}
func TestCPUUsageDeltaAndReset(t *testing.T) {
	v := cpuUsage(cpu.TimesStat{User: 10, Idle: 90}, cpu.TimesStat{User: 30, Idle: 170})
	if v == nil || *v != 20 {
		t.Fatal(v)
	}
	if cpuUsage(cpu.TimesStat{Idle: 100}, cpu.TimesStat{Idle: 1}) != nil {
		t.Fatal("reset is not a valid sample")
	}
}
