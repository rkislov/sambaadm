package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sambaadm/internal/config"
	ldapproto "sambaadm/internal/ldap"
	"strings"
	"testing"
	"time"
)

func employeeTestService(t *testing.T) *EmployeeService {
	t.Helper()
	root := filepath.Join(t.TempDir(), "workflows")
	client := ldapproto.NewServiceClient(config.LDAPConfig{BaseDN: "DC=example,DC=com"}, nil)
	return NewEmployeeService(client, nil, root, "svc@example.com", nil)
}
func TestEmployeeValidation(t *testing.T) {
	for _, in := range []EmployeeInput{{Scenario: "unknown", Login: "alice"}, {Scenario: "join", Login: "a/b"}, {Scenario: "join", Login: strings.Repeat("a", 21)}, {Scenario: "offboard", Login: "alice", Activate: true}, {Scenario: "offboard", Login: "alice", AddGroups: []EmployeeRef{{ID: "x"}}}, {Scenario: "transfer", Login: "alice", ForceChange: true}, {Scenario: "join", Login: "alice", RemoveGroups: []EmployeeRef{{}}}} {
		if !errors.Is(validateEmployee(in), ErrEmployeeInput) {
			t.Fatalf("accepted invalid input: %+v", in)
		}
	}
	if e := validateEmployee(EmployeeInput{Scenario: "join", Login: "alice", DisplayName: "Анна Иванова", Activate: true, ForceChange: true}); e != nil {
		t.Fatal(e)
	}
}
func TestEmployeeProtectionAndProjection(t *testing.T) {
	s := employeeTestService(t)
	snap := &employeeSnapshot{Person: EmployeePerson{EmployeeRef: EmployeeRef{ID: strings.Repeat("a", 32), DN: "CN=Alice,DC=example,DC=com"}, Enabled: true}, Values: map[string]string{"sAMAccountName": "alice", "userPrincipalName": "alice@example.com", "userAccountControl": "512"}}
	for _, actor := range []EmployeeActor{{ID: snap.Person.ID}, {DN: snap.Person.DN}} {
		if !errors.Is(s.protect(snap, actor), ErrEmployeeInput) {
			t.Fatal("self protection missing")
		}
	}
	for _, attr := range []string{"adminCount", "servicePrincipalName"} {
		snap.Values[attr] = "1"
		if s.protect(snap, EmployeeActor{}) == nil {
			t.Fatal("service/admin protected")
		}
		delete(snap.Values, attr)
	}
	snap.Values["userPrincipalName"] = "svc@example.com"
	if s.protect(snap, EmployeeActor{}) == nil {
		t.Fatal("configured service protected")
	}
	snap.Values["userPrincipalName"] = "alice@example.com"
	after := *snap
	after.Person.Enabled = false
	after.Values = map[string]string{}
	for k, v := range snap.Values {
		after.Values[k] = v
	}
	after.Values["userAccountControl"] = "514"
	after.USN = "2"
	r := &employeeRecord{}
	if e := verifyEmployeeStep(r, snap, &after, EmployeeStep{Kind: "disable"}); e != nil {
		t.Fatal(e)
	}
	after.Values["title"] = "external change"
	if e := verifyEmployeeStep(r, snap, &after, EmployeeStep{Kind: "disable"}); e == nil {
		t.Fatal("unexpected external change accepted")
	}
}
func TestEmployeeJournalLockCorruptionAndRecovery(t *testing.T) {
	s := employeeTestService(t)
	unlock, e := s.lock()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.lock(); !errors.Is(e, ErrEmployeeBusy) {
		t.Fatal("lock not exclusive", e)
	}
	unlock()
	r := &employeeRecord{Version: 1, BaseDN: s.ldap.BaseDN(), Plan: EmployeePlan{ID: strings.Repeat("a", 32), State: "running", Input: EmployeeInput{Scenario: "join", Login: "alice"}, Created: time.Now()}}
	if e = s.save(r); e != nil {
		t.Fatal(e)
	}
	p, e := s.Get(r.Plan.ID)
	if e != nil || p.State != "interrupted" {
		t.Fatal("interrupted journal recovery", e)
	}
	if _, e = s.Get("../outside"); !errors.Is(e, ErrEmployeeInput) {
		t.Fatal("path traversal", e)
	}
	file := filepath.Join(s.root, r.Plan.ID+".json")
	data, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(strings.ToLower(string(data)), "\"password\":") {
		t.Fatal("password field persisted")
	}
	data = []byte(strings.Replace(string(data), "alice", "other", 1))
	if e = os.WriteFile(file, data, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Get(r.Plan.ID); e == nil {
		t.Fatal("corrupt journal accepted")
	}
	if _, e = s.Apply(context.Background(), r.Plan.ID, r.Plan.Revision, "secret", EmployeeActor{}); e == nil {
		t.Fatal("corrupt journal applied")
	}
}
func TestEmployeePendingOrder(t *testing.T) {
	s := employeeTestService(t)
	r := &employeeRecord{Plan: EmployeePlan{Input: EmployeeInput{Scenario: "join", Activate: true, AddGroups: []EmployeeRef{{ID: "group", Name: "Employees"}}}}}
	steps, e := s.pending(r, nil)
	if e != nil {
		t.Fatal(e)
	}
	kinds := []string{}
	for _, step := range steps {
		kinds = append(kinds, step.Kind)
	}
	if strings.Join(kinds, ",") != "create,add_group,password,enable" {
		t.Fatal(kinds)
	}
}
