package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	smb2 "github.com/cloudsoda/go-smb2"

	ldapproto "sambaadm/internal/ldap"
	"sambaadm/internal/policy"
)

const typedEditorADMX = `<policyDefinitions><policies><policy name="typed" class="Both" key="Software\BaseALT\EditorTest"><elements><text id="text" valueName="Text" required="true" maxLength="40"/><decimal id="number" valueName="Count" minValue="1" maxValue="9"/><enum id="mode" valueName="Mode"><item displayName="First"><value><string>first</string></value></item><item displayName="Second"><value><string>second</string></value></item></enum><boolean id="lock" key="Software\BaseALT\EditorTestLocks" valueName="Lock"><trueValue><decimal value="1"/></trueValue><falseValue><decimal value="0"/></falseValue></boolean><list id="packages" key="Software\BaseALT\EditorTest\Packages" additive="true"/></elements></policy></policies></policyDefinitions>`

func TestIntegrationRemoteALTCatalog(t *testing.T) {
	s, _ := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	name := "Catalog-" + fmt.Sprint(time.Now().UnixNano())
	if _, e := s.GPO.Create(ctx, name, "test", ""); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := s.GPO.Delete(context.Background(), name, "test", ""); e != nil {
			t.Error(e)
		}
	})
	entry, e := s.GPO.policyEntry(ctx, name)
	if e != nil {
		t.Fatal(e)
	}
	guid := strings.TrimPrefix(strings.SplitN(entry.DN, ",", 2)[0], "CN=")
	s.GPO.gpoCfg.EditorEnabled = true
	s.GPO.gpoCfg.ADMXPath = ""
	s.GPO.gpoCfg.SysvolPath = "/no-local-sysvol"
	template := `sambaadm.test\Policies\PolicyDefinitions\BaseALTEditorIntegration.admx`
	e = s.GPO.remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		if e := sh.MkdirAll(`sambaadm.test\Policies\PolicyDefinitions`, 0755); e != nil {
			return e
		}
		f, e := sh.OpenFile(template, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if e != nil {
			return e
		}
		defer f.Close()
		_, e = f.Write([]byte(typedEditorADMX))
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		e := s.GPO.remote.SYSVOL(context.Background(), s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error { return sh.Remove(template) })
		if e != nil {
			t.Error(e)
		}
	})
	id := "BaseALTEditorIntegration.admx/typed"
	values := map[string]json.RawMessage{"text": json.RawMessage(`"Пример"`), "number": json.RawMessage(`"5"`), "mode": json.RawMessage(`"1"`), "lock": json.RawMessage(`true`), "packages": json.RawMessage(`["curl","vim"]`)}
	before, e := s.GPO.ALTSettingsScope(ctx, guid, "User")
	if e != nil {
		t.Fatal(e)
	}
	saved, e := s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: id, Scope: "User", State: "enabled", Revision: before.Revision, Values: values}, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	if saved.Scope != "User" || saved.Version != 65536 {
		t.Fatalf("wrong scope/version %+v", saved)
	}
	var userData []byte
	e = s.GPO.remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		root := `sambaadm.test\Policies\` + guid
		var e error
		userData, e = sh.ReadFile(root + `\User\Registry.pol`)
		if e != nil {
			return e
		}
		if _, e = sh.Stat(root + `\Machine\Registry.pol`); !os.IsNotExist(e) {
			return fmt.Errorf("machine registry unexpectedly changed: %v", e)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	records, e := policy.Parse(userData)
	if e != nil || len(records) != 6 {
		t.Fatalf("registry records %v %v", records, e)
	}
	// Independent byte expectations for enum/list encoding (REG_SZ UTF-16LE).
	found := false
	for _, r := range records {
		if r.Name == "Mode" {
			found = r.Type == 1 && bytes.Equal(r.Data, []byte{'s', 0, 'e', 0, 'c', 0, 'o', 0, 'n', 0, 'd', 0, 0, 0})
		}
	}
	if !found {
		t.Fatal("enum wire data mismatch")
	}
	invalid := map[string]json.RawMessage{}
	for k, v := range values {
		invalid[k] = v
	}
	invalid["number"] = json.RawMessage(`"10"`)
	if _, e = s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: id, Scope: "User", State: "enabled", Revision: saved.Revision, Values: invalid}, "test", ""); e == nil {
		t.Fatal("accepted out-of-range integer")
	}
	machine, e := s.GPO.ALTSettings(ctx, guid)
	if e != nil {
		t.Fatal(e)
	}
	machine, e = s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: id, Scope: "Machine", State: "enabled", Revision: machine.Revision, Values: values}, "test", "")
	if e != nil || machine.Version != 65537 {
		t.Fatalf("machine version: %+v %v", machine, e)
	}
	e = s.GPO.remote.SYSVOL(ctx, s.GPO.gpoCfg.SMBPort, func(sh *smb2.Share) error {
		data, e := sh.ReadFile(`sambaadm.test\Policies\` + guid + `\User\Registry.pol`)
		if e == nil && !bytes.Equal(data, userData) {
			return fmt.Errorf("machine save overwrote user file")
		}
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	user, e := s.GPO.ALTSettingsScope(ctx, guid, "User")
	if e != nil {
		t.Fatal(e)
	}
	for _, state := range []string{"disabled", "not-configured"} {
		user, e = s.GPO.SetALTSetting(ctx, guid, ALTChange{ID: id, Scope: "User", State: state, Revision: user.Revision}, "test", "")
		if e != nil {
			t.Fatal(e)
		}
		if uint16(user.Version) != 1 {
			t.Fatal("machine version changed")
		}
	}
	meta, e := s.GPO.ldap.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: entry.DN, Scope: ldapproto.ScopeBase(), Filter: "(objectClass=*)", Attributes: []string{"gPCUserExtensionNames", "gPCMachineExtensionNames"}})
	if e != nil || meta.GetAttributeValue("gPCUserExtensionNames") != registryCSE || meta.GetAttributeValue("gPCMachineExtensionNames") != registryCSE {
		t.Fatalf("scope metadata %+v %v", meta, e)
	}
}
