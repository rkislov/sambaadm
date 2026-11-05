package service

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestOverviewSurveyImport(t *testing.T) {
	const overview = `{"schema":1,"exported":"2026-11-05T12:00:00Z","sections":{"dns":{"source":"DNS","status":"unavailable","finished":"2026-11-05T11:59:59Z"}}}`
	m, err := ParseSurvey(context.Background(), "overview", "dc1", "region", []byte(overview))
	if err != nil || string(m.Overview) != overview {
		t.Fatalf("import overview: %v", err)
	}
	for _, invalid := range []string{strings.Replace(overview, "1,", "2,", 1), strings.Replace(overview, "unavailable", "invalid", 1)} {
		if _, err := ParseSurvey(context.Background(), "overview", "", "", []byte(invalid)); err == nil {
			t.Fatal("invalid overview accepted")
		}
	}
}

func TestCollectedSurveyImport(t *testing.T) {
	path := os.Getenv("SAMBAADM_TEST_COLLECTED_SURVEY")
	if path == "" {
		t.Skip("requires a Linux helper snapshot")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseSurvey(context.Background(), "helper", "", "", data)
	if err != nil || m.Snapshot == nil {
		t.Fatalf("import collected snapshot: %v", err)
	}
}
