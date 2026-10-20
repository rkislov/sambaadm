package service

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestScheduleQuarterHours(t *testing.T) {
	days := []string{"00:00-00:15,23:45-24:00", "08:15-09:45", "", "00:00-24:00", "12:00-12:30", "18:30-19:00", ""}
	b, e := EncodeSchedule(days)
	if e != nil {
		t.Fatal(e)
	}
	if len(b) != 188 || binary.LittleEndian.Uint32(b[16:]) != 20 || b[20] != 1 || b[43] != 8 || b[20+24+8] != 14 || b[20+24+9] != 7 {
		t.Fatalf("incorrect AD quarter-hour schedule: %x", b)
	}
	got, ok := DecodeSchedule(b)
	if !ok || !reflect.DeepEqual(got, days) {
		t.Fatalf("roundtrip: %v %v", got, ok)
	}
	for _, bad := range []string{"24:00-24:00", "09:00-08:00", "08:01-09:00", "25:00-26:00", "-1:00-09:00", "xx:00-09:00", "08:00", "08:00-24:15"} {
		d := append([]string(nil), days...)
		d[0] = bad
		if _, e := EncodeSchedule(d); e == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, e := EncodeSchedule(days[:6]); e == nil {
		t.Error("accepted six days")
	}
	b[20] |= 0x80
	if _, ok := DecodeSchedule(b); ok {
		t.Error("unknown bits must not be overwritten")
	}
	b[20] &= 0x0f
	b[16] = 21
	if _, ok := DecodeSchedule(b); ok {
		t.Error("unsupported offset accepted")
	}
	if d, ok := DecodeSchedule(nil); !ok || len(d) != 7 || d[0] != "00:00-24:00" {
		t.Fatal("absent schedule must mean always available")
	}
}
func TestReplicationHealth(t *testing.T) {
	cases := []struct {
		raw, health string
		count       int
	}{
		{`{"repsFrom":[],"repsTo":[]}`, "no-partners", 0},
		{`{"repsFrom":[{"DSA":"DC2","NC dn":"DC=test","last success":"2026-10-20","last attempt message":"was successful"}],"repsTo":[]}`, "healthy", 1},
		{`{"repsFrom":[{"consecutive failures":1,"last success":"2026-10-20","last attempt message":"failed"}],"repsTo":[]}`, "degraded", 1},
		{`{"repsFrom":[],"repsTo":[{"last success":"NTTIME(0)","last attempt message":"was successful"}]}`, "degraded", 1},
		{`{"repsFrom":[{"is deleted":true,"consecutive failures":42}],"repsTo":[]}`, "no-partners", 0},
	}
	for _, c := range cases {
		st, e := parseReplStatus(c.raw)
		if e != nil || st.Health != c.health || len(st.Neighbors) != c.count {
			t.Fatalf("%s: %+v %v", c.raw, st, e)
		}
	}
	for _, raw := range []string{`{}`, `null`, `broken`, `{"repsFrom":"bad","repsTo":[]}`} {
		if _, e := parseReplStatus(raw); e == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if hostnameFromURI("ldaps://[::1]:636") != "::1" {
		t.Error("IPv6 LDAP host")
	}
}
