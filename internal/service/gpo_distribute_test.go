package service

import (
	"context"
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
			if err := s.jobs.start(&DistributeJob{ID: "test", Status: JobRunning, Steps: steps}); err != nil {
				t.Fatal(err)
			}
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

func TestBulkDistributionReplicatesOnceAndContinuesAfterFailure(t *testing.T) {
	s := &GPOService{jobs: newJobStore()}
	plan := distributionPlan{targets: []string{"rodc1", "rwdc2", "rodc3"}, drs: true, sysvol: true}
	policies := []GPO{{GUID: "guid1", DisplayName: "Policy One"}, {GUID: "guid2", DisplayName: "Policy Two"}}
	job := newBulkDistributeJob("admin", plan, policies)
	job.Steps = append(job.Steps, DistributeStep{ID: "done", Status: StepPending})
	if err := s.jobs.start(job); err != nil {
		t.Fatal(err)
	}

	var operations []string
	s.runBulkDistribution(context.Background(), job.ID, plan.targets, func(dc string) error {
		operations = append(operations, "DRS "+dc)
		if dc == "rodc1" {
			return errors.New("DRS denied")
		}
		return nil
	}, func(guid string) (func(string) error, error) {
		operations = append(operations, "read "+guid)
		return func(dc string) error {
			operations = append(operations, guid+" → "+dc)
			if guid == "guid1" && dc == "rwdc2" {
				return errors.New("SYSVOL denied")
			}
			return nil
		}, nil
	})
	want := []string{"DRS rodc1", "DRS rwdc2", "DRS rodc3", "read guid1", "guid1 → rwdc2", "guid1 → rodc3", "read guid2", "guid2 → rwdc2", "guid2 → rodc3"}
	if !reflect.DeepEqual(operations, want) {
		t.Fatalf("operations = %v, want %v", operations, want)
	}
	result, _ := s.GetDistributeJob(job.ID)
	if result.Status != JobFailed || result.Progress != 100 {
		t.Fatalf("unexpected final status: %+v", result)
	}
	for _, detail := range []string{"rodc1: DRS denied", "rodc1: пропущен", "rwdc2: SYSVOL denied", "Policy One"} {
		if !strings.Contains(result.Error, detail) {
			t.Errorf("missing %q in %s", detail, result.Error)
		}
	}
}

func TestBulkDistributionExcludesOtherDeliveries(t *testing.T) {
	store := newJobStore()
	single := newDistributeJob("policy", "admin")
	bulk := newBulkDistributeJob("admin", distributionPlan{}, nil)
	if err := store.start(single); err != nil {
		t.Fatal(err)
	}
	if err := store.start(bulk); !errors.Is(err, ErrGPOBulkDeliveryActive) {
		t.Fatalf("bulk while single pending: %v", err)
	}
	store.update(single.ID, func(j *DistributeJob) { j.Status = JobOK })
	if err := store.start(bulk); err != nil {
		t.Fatal(err)
	}
	if err := store.start(newDistributeJob("policy", "admin")); !errors.Is(err, ErrGPOBulkDeliveryActive) {
		t.Fatalf("single while bulk pending: %v", err)
	}
}
