package service

import "testing"

func TestApplyPresetDomainRW(t *testing.T) {
	in := CreateShareInput{Name: "docs", Preset: PresetDomainReadWrite}
	ApplyPreset(&in)
	if in.ValidUsers == "" || in.WriteList == "" {
		t.Fatalf("expected domain users lists: %+v", in)
	}
	if in.ReadOnly == nil || *in.ReadOnly {
		t.Fatal("expected read-write")
	}
	if in.DefaultACL == "" {
		t.Fatal("expected default ACL")
	}
}

func TestBuildACLSpec(t *testing.T) {
	got, err := BuildACLSpec("group", "domain users", "rw")
	if err != nil || got != "g:domain users:rw-" {
		t.Fatalf("got %q err=%v", got, err)
	}
	got, err = BuildACLSpec("other", "", "rx")
	if err != nil || got != "o::r-x" {
		t.Fatalf("got %q err=%v", got, err)
	}
}
