package samba

import "testing"

func TestResultLines(t *testing.T) {
	r := &Result{Stdout: "a\n\nb\n  c  \n"}
	got := r.Lines()
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("got %#v", got)
	}
}
