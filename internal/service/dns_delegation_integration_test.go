package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestIntegrationDNSDelegation(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	zone := "sambaadm.test"
	child := fmt.Sprintf("route-%d", time.Now().UnixNano()%1000000000)
	ns := "ns." + child + "." + zone
	actor := "dns-test"
	defer func() {
		_ = s.DNS.DeleteRecord(context.Background(), AddDNSRecordInput{Zone: zone, Name: child, Type: "NS", Data: ns}, actor, "")
		_ = s.DNS.DeleteRecord(context.Background(), AddDNSRecordInput{Zone: zone, Name: "ns." + child, Type: "A", Data: "192.0.2.53"}, actor, "")
	}()
	input := DNSDelegationInput{Zone: zone, Child: child, Servers: []DNSNameServer{{Name: ns, Addresses: []string{"192.0.2.53"}}}, Confirm: true}
	p, e := s.DNS.PlanDelegation(ctx, input)
	if e != nil {
		t.Fatal(e)
	}
	input.Revision = p.Revision
	input.ProposedRevision = p.ProposedRevision
	state, e := s.DNS.ApplyDelegation(ctx, input, actor, "")
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, d := range state.Delegations {
		if d.Child == child {
			found = len(d.Servers) == 1 && len(d.Servers[0].Addresses) == 1
		}
	}
	if !found {
		t.Fatal("delegation or glue missing", state)
	}
	if _, e = s.DNS.ApplyDelegation(ctx, input, actor, ""); !errors.Is(e, ErrTopologyConflict) {
		t.Fatal("stale preview accepted", e)
	}
	input = DNSDelegationInput{Zone: zone, Child: child, Remove: true, Confirm: true}
	p, e = s.DNS.PlanDelegation(ctx, input)
	if e != nil {
		t.Fatal(e)
	}
	input.Revision = p.Revision
	input.ProposedRevision = p.ProposedRevision
	if _, e = s.DNS.ApplyDelegation(ctx, input, actor, ""); e != nil {
		t.Fatal(e)
	}
	glue, e := s.DNS.QueryRecordsExact(ctx, zone, "ns."+child, "A")
	if e != nil || len(glue) != 1 {
		t.Fatal("shared glue removed", glue, e)
	}
}
