package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sambaadm/internal/config"
)

func TestTimeConfigPreservesOtherDirectivesAndRejectsUnsafeInput(t *testing.T) {
	raw := []byte("# existing\ndriftfile /var/lib/chrony/drift\nmakestep 1 3\nserver old.example.test iburst\nallow 10.0.0.0/24\n")
	settings := TimeSettings{Mode: "isolated", LocalReference: true, Stratum: 10, Allow: []string{"10.1.0.7/24"}}
	got, err := patchTimeConfig(raw, settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"driftfile /var/lib/chrony/drift", "makestep 1 3", "local stratum 10", "allow 10.1.0.0/24"} {
		if !strings.Contains(string(got), want) {
			t.Fatalf("missing %s: %s", want, got)
		}
	}
	if strings.Contains(string(got), "old.example.test") {
		t.Fatal("old source retained")
	}
	for _, source := range []string{"server foo; reboot", "server $(id)", "server -x", "server foo iburst\nallow all", "server foo iburst iburst"} {
		if _, err := validateTimeSource(source); err == nil {
			t.Errorf("accepted %q", source)
		}
	}
	for _, advanced := range []string{"include /etc/chrony.d/*.conf", "sourcedir /run/chrony", "server foo nts", "local stratum 10junk", "local stratum 10 orphan", "allow all"} {
		if _, err := patchTimeConfig([]byte(advanced), settings); err == nil {
			t.Errorf("rewrote advanced configuration %q", advanced)
		}
	}
	settings.Allow = []string{"0.0.0.0/0"}
	if _, err := patchTimeConfig(raw, settings); err == nil {
		t.Fatal("accepted world-wide access")
	}
}

func testTimeHost(t *testing.T) *timeHost {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chrony.conf")
	if err := os.WriteFile(path, []byte("driftfile /var/lib/chrony/drift\nserver old.example.test iburst\n"), 0640); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Helper.TimeConfig = path
	cfg.Helper.Node = "test-node"
	return &timeHost{cfg: cfg, path: path, unit: "chronyd.service", run: func(context.Context, string, ...string) (string, error) { return "active", nil }}
}
func timeTestRequest() TimeRequest {
	return TimeRequest{Settings: TimeSettings{Mode: "isolated", LocalReference: true, Stratum: 10, Allow: []string{"10.1.0.0/24"}}, Confirm: true}
}
func TestTimeApplyRequiresPreviewAndDetectsStaleConfiguration(t *testing.T) {
	h := testTimeHost(t)
	req := timeTestRequest()
	ctx := context.Background()
	before, _ := os.ReadFile(h.path)
	if _, err := h.apply(ctx, req); !errors.Is(err, ErrTopologyConflict) {
		t.Fatalf("missing preview accepted: %v", err)
	}
	plan, err := h.plan(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, _ := os.ReadFile(h.path)
	if string(unchanged) != string(before) {
		t.Fatal("preview changed configuration")
	}
	req.Revision = plan.Revision
	req.ProposedRevision = plan.ProposedRevision
	if err := os.WriteFile(h.path, append(before, []byte("# concurrent edit\n")...), 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := h.apply(ctx, req); !errors.Is(err, ErrTopologyConflict) {
		t.Fatalf("stale preview accepted: %v", err)
	}
}
func TestTimeApplyBackupAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "rollback"}[fail], func(t *testing.T) {
			h := testTimeHost(t)
			ctx := context.Background()
			req := timeTestRequest()
			before, _ := os.ReadFile(h.path)
			plan, err := h.plan(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			req.Revision = plan.Revision
			req.ProposedRevision = plan.ProposedRevision
			restarts := 0
			h.run = func(_ context.Context, name string, args ...string) (string, error) {
				if name == "systemctl" && args[0] == "restart" {
					restarts++
					if fail && restarts == 1 {
						return "", errors.New("restart failed")
					}
				}
				return "active", nil
			}
			result, err := h.apply(ctx, req)
			after, _ := os.ReadFile(h.path)
			if fail {
				if err == nil || string(after) != string(before) || restarts != 2 {
					t.Fatalf("rollback failed: %v %s %d", err, after, restarts)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(after), "local stratum 10") {
					t.Fatal("config not applied")
				}
				backup, e := os.ReadFile(result.Backup)
				if e != nil || string(backup) != string(before) {
					t.Fatalf("backup invalid: %v", e)
				}
				st, _ := os.Stat(result.Backup)
				if st.Mode().Perm() != 0600 {
					t.Fatal("backup not private")
				}
			}
			st, _ := os.Stat(h.path)
			if st.Mode().Perm() != 0640 {
				t.Fatal("config mode changed")
			}
		})
	}
}
func TestTimeReadOnlyByDefaultAndNoLocalFallback(t *testing.T) {
	h := testTimeHost(t)
	h.cfg.Helper.TimeConfig = ""
	if _, err := h.plan(context.Background(), timeTestRequest()); err == nil {
		t.Fatal("changes enabled by default")
	}
	if err := (TimeService{}).Call(context.Background(), "unknown", "time.inspect", TimeRequest{}, "", "", &TimeStatus{}); err == nil {
		t.Fatal("missing helper accepted")
	}
}
