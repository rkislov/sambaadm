package service

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestDistributionAttemptsEveryTargetAfterFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failures map[string]string
	}{
		{name: "all succeed"},
		{name: "DRS failure still copies same DC and continues", failures: map[string]string{"drs-dc1": "no route to host"}},
		{name: "copy failure still tries next DC", failures: map[string]string{"sysvol-dc1": "permission denied"}},
		{name: "errors on different DCs are retained", failures: map[string]string{"drs-dc1": "no route to host", "sysvol-dc2": "helper unavailable"}},
		{name: "all targets fail", failures: map[string]string{"drs-dc1": "drs1", "sysvol-dc1": "smb1", "drs-dc2": "drs2", "sysvol-dc2": "smb2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &GPOService{jobs: newJobStore()}
			steps := []DistributeStep{{ID: "resolve", Status: StepOK}}
			want := []string{"drs-dc1", "sysvol-dc1", "drs-dc2", "sysvol-dc2"}
			for _, id := range want {
				steps = append(steps, DistributeStep{ID: id, Title: id, Status: StepPending})
			}
			steps = append(steps, DistributeStep{ID: "done", Status: StepPending})
			s.jobs.put(&DistributeJob{ID: "test", Status: JobRunning, Steps: steps})
			var attempted []string
			s.runTargetSteps("test", func(step DistributeStep) error {
				job, _ := s.GetDistributeJob("test")
				if job.Status != JobRunning || job.Progress >= 100 {
					t.Fatalf("polling would stop before all targets: %+v", job)
				}
				attempted = append(attempted, step.ID)
				if message := tc.failures[step.ID]; message != "" {
					return errors.New(message)
				}
				return nil
			})
			if !reflect.DeepEqual(attempted, want) {
				t.Fatalf("attempted %v; want %v", attempted, want)
			}
			job, _ := s.GetDistributeJob("test")
			if job.Progress != 100 {
				t.Fatalf("progress=%d", job.Progress)
			}
			expected := JobOK
			if len(tc.failures) > 0 {
				expected = JobFailed
			}
			if job.Status != expected {
				t.Fatalf("status=%s; want %s", job.Status, expected)
			}
			for _, step := range job.Steps {
				expectedStep := StepOK
				if tc.failures[step.ID] != "" || (step.ID == "done" && len(tc.failures) > 0) {
					expectedStep = StepFailed
				}
				if step.Status != expectedStep {
					t.Errorf("%s: status=%s; want %s", step.ID, step.Status, expectedStep)
				}
				if message := tc.failures[step.ID]; message != "" {
					if step.Message != message || !strings.Contains(job.Error, step.Title+": "+message) {
						t.Errorf("lost failure for %s: %+v", step.ID, job)
					}
				}
			}
			if len(tc.failures) == 0 && job.Error != "" {
				t.Errorf("successful job reports error: %s", job.Error)
			}
		})
	}
}

func TestLooksLikeGUID(t *testing.T) {
	if !looksLikeGUID("{31B2F340-016D-11D2-945F-00C04FB984F9}") {
		t.Fatal("expected guid")
	}
	if looksLikeGUID("Default Domain Policy") {
		t.Fatal("name is not guid")
	}
}

func TestSameHost(t *testing.T) {
	if !sameHost("dc1.example.com", "dc1") {
		t.Fatal("short/fqdn should match")
	}
	if sameHost("dc1", "dc2") {
		t.Fatal("different hosts")
	}
}

func TestBraceGUID(t *testing.T) {
	if braceGUID("31B2F340-016D-11D2-945F-00C04FB984F9") != "{31B2F340-016D-11D2-945F-00C04FB984F9}" {
		t.Fatal("brace")
	}
}
