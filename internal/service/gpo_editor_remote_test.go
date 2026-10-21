package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"
	"sambaadm/internal/policy"
)

// This test runs on macOS as well as CI: no DC filesystem or Samba tools.
func TestIntegrationRemoteALTEditor(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	name := "Remote-ALT-" + fmt.Sprint(time.Now().UnixNano())
	_, e := s.GPO.Create(ctx, name, "integration", "")
	if e != nil {
		t.Fatal(e)
	}
	entry, e := s.GPO.policyEntry(ctx, name)
	if e != nil {
		t.Fatal(e)
	}
	guid := strings.TrimPrefix(strings.SplitN(entry.DN, ",", 2)[0], "CN=")
	t.Cleanup(func() {
		if e := s.GPO.Delete(context.Background(), guid, "integration", ""); e != nil {
			t.Error(e)
		}
	})
	s.GPO.gpoCfg.EditorEnabled = true
	s.GPO.gpoCfg.SysvolPath = "/does-not-exist/no-local-sysvol"
	s.GPO.gpoCfg.ADMXPath = ""
	base := "sambaadm.test/Policies/" + guid
	template := `sambaadm.test\Policies\PolicyDefinitions\BaseALTSystemdUnits.admx`
	var prior []byte
	var existed bool
	e = s.GPO.remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		if e := sh.MkdirAll(`sambaadm.test\Policies\PolicyDefinitions`, 0755); e != nil {
			return e
		}
		prior, e = sh.ReadFile(template)
		existed = e == nil
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		return sh.WriteFile(template, []byte(editorTestADMX), 0644)
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		e := s.GPO.remote.SYSVOL(context.Background(), s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
			if existed {
				return sh.WriteFile(template, prior, 0644)
			}
			return sh.Remove(template)
		})
		if e != nil {
			t.Error(e)
		}
	})
	before, e := s.GPO.ALTSettings(ctx, guid)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasPrefix(before.TemplateSource, "SYSVOL/") || before.Controller == "" {
		t.Fatalf("not remote: %+v", before)
	}
	var saved *ALTPolicy
	for _, state := range []string{"enabled", "disabled", "not-configured"} {
		saved, e = s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: "chronyd.service", State: state, Revision: before.Revision}, "integration", "")
		if e != nil {
			t.Fatal(e)
		}
		actual := ""
		for _, setting := range saved.Settings {
			if setting.ID == "chronyd.service" {
				actual = setting.State
			}
		}
		if saved.Version != before.Version+1 || actual != state {
			t.Fatalf("bad save: %+v", saved)
		}
		if _, e = s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: "chronyd.service", State: state, Revision: before.Revision}, "integration", ""); !errors.Is(e, ErrPolicyConflict) {
			t.Fatalf("stale: %v", e)
		}
		before = saved
	}
	e = s.GPO.remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		store := &smbPolicyStore{share: sh, base: base}
		data, e := readPolicyFile(store, "Machine/Registry.pol")
		if e != nil {
			return e
		}
		records, e := policy.Parse(data)
		if e != nil {
			return e
		}
		if len(records) != 0 {
			return fmt.Errorf("setting was not removed")
		}
		// Pending journal blocks reads and writes, including a separate process.
		return sh.WriteFile(strings.ReplaceAll(base, "/", `\`)+`\`+editorJournal, []byte("pending"), 0600)
	})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.GPO.ALTSettings(ctx, guid); e == nil {
		t.Fatal("ignored pending save")
	}
	if _, e = s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: "chronyd.service", State: "enabled", Revision: before.Revision}, "integration", ""); e == nil {
		t.Fatal("overwrote pending save")
	}
	e = s.GPO.remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		root := strings.ReplaceAll(base, "/", `\`)
		data, e := sh.ReadFile(root + `\` + editorJournal)
		if e != nil {
			return e
		}
		if !bytes.Equal(data, []byte("pending")) {
			return fmt.Errorf("journal overwritten")
		}
		return sh.Remove(root + `\` + editorJournal)
	})
	if e != nil {
		t.Fatal(e)
	}
	// Two independent service objects model concurrent Mac/server instances.
	peer := &GPOService{remote: s.GPO.remote, ldap: s.GPO.ldap, audit: s.GPO.audit, gpoCfg: s.GPO.gpoCfg}
	start := make(chan struct{})
	result := make(chan error, 2)
	for _, editor := range []*GPOService{s.GPO, peer} {
		go func(g *GPOService) {
			<-start
			_, e := g.SetALTSetting(ctx, guid, ALTChange{ID: "chronyd.service", State: "enabled", Revision: before.Revision}, "integration", "")
			result <- e
		}(editor)
	}
	close(start)
	a, b := <-result, <-result
	if (a == nil) == (b == nil) {
		t.Fatalf("expected exactly one concurrent save: %v / %v", a, b)
	}
	final, e := s.GPO.ALTSettings(ctx, guid)
	if e != nil || final.Version != before.Version+1 {
		t.Fatalf("concurrent result: %+v %v", final, e)
	}
}
