package service

import (
	"context"
	"errors"
	"testing"
)

func TestBulkRejectsInvalidSelection(t *testing.T) {
	s := employeeTestService(t)
	for _, action := range []string{"delete", "reset-password", ""} {
		if _, e := s.BulkPreview(context.Background(), action, []string{"alice"}, EmployeeActor{}); !errors.Is(e, ErrEmployeeInput) {
			t.Fatal(e)
		}
	}
	if _, e := s.BulkPreview(context.Background(), "disable", nil, EmployeeActor{}); !errors.Is(e, ErrEmployeeInput) {
		t.Fatal(e)
	}
}
