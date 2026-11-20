package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"sambaadm/internal/policy"
)

const testDriveUID = "{11111111-1111-4111-8111-111111111111}"
const driveFixture = `<?xml version="1.0" encoding="utf-8"?><Drives clsid="{8FDDCC1A-0C3C-43CD-A6B4-71A6DF20DA8C}"><!-- retain --><Drive uid="{11111111-1111-4111-8111-111111111111}" desc="keep" removePolicy="1" custom="metadata"><Properties action="U" path="\\server.example.com\share" label="share" letter="Z" useLetter="1" persistent="1" thisDrive="SHOW" allDrives="NOCHANGE" foreign="retained"/><Filters><FilterGroup name="domain\staff"/></Filters></Drive><Drive uid="{22222222-2222-4222-8222-222222222222}"><Properties action="U" path="\\other\share" letter="Y" useLetter="1" persistent="0"/></Drive></Drives>`

func validDriveChange() DriveChange {
	return DriveChange{Revision: "revision", Scope: "User", Operation: "upsert", Drive: DriveMap{Action: "U", Path: `\\server.example.com\share`, Label: "share", Letter: "Z", UseLetter: true, Persistent: true, ThisDrive: "SHOW", AllDrives: "NOCHANGE"}}
}
func TestDriveXMLPreservesOtherItemsAndTargeting(t *testing.T) {
	doc, e := parseDriveXML([]byte(driveFixture))
	if e != nil {
		t.Fatal(e)
	}
	in := validDriveChange()
	in.Drive = doc.items[0].view
	in.Drive.Label = "Документы & <данные>"
	in.Drive.Path = `\\files.example.com\documents`
	data, e := patchDriveXML(doc, in)
	if e != nil {
		t.Fatal(e)
	}
	other := doc.text[doc.items[1].start:doc.items[1].end]
	for _, s := range []string{other, `<Filters><FilterGroup name="domain\staff"/></Filters>`, `custom="metadata"`, `foreign="retained"`, `removePolicy="1"`, `<!-- retain -->`} {
		if !bytes.Contains(data, []byte(s)) {
			t.Fatalf("lost existing metadata: %s", s)
		}
	}
	after, e := parseDriveXML(data)
	if e != nil || len(after.items) != 2 || after.items[0].view.Label != in.Drive.Label || !after.items[0].view.HasFilters {
		t.Fatalf("roundtrip: %+v %v", after, e)
	}
	in.Operation = "move"
	in.Direction = 1
	data, e = patchDriveXML(after, in)
	if e != nil {
		t.Fatal(e)
	}
	moved, e := parseDriveXML(data)
	if e != nil || moved.items[1].view.UID != testDriveUID {
		t.Fatalf("reorder: %v", e)
	}
	in.Operation = "remove"
	data, e = patchDriveXML(moved, in)
	if e != nil {
		t.Fatal(e)
	}
	removed, e := parseDriveXML(data)
	if e != nil || len(removed.items) != 1 || removed.items[0].view.UID == testDriveUID {
		t.Fatalf("remove: %v", e)
	}
}
func TestDriveXMLNewDisabledAndLegacyCredentials(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(`<Drives/>`), encodePolicyText(`<?xml version="1.0" encoding="utf-16"?><Drives></Drives>`, true)} {
		doc, e := parseDriveXML(raw)
		if e != nil {
			t.Fatal(e)
		}
		data, e := patchDriveXML(doc, validDriveChange())
		if e != nil {
			t.Fatal(e)
		}
		out, e := parseDriveXML(data)
		if e != nil || len(out.items) != 1 || out.items[0].view.Path != `\\server.example.com\share` {
			t.Fatalf("new XML %s: %v", data, e)
		}
		in := validDriveChange()
		in.Operation = "set-disabled"
		in.Disabled = true
		data, e = patchDriveXML(out, in)
		if e != nil {
			t.Fatal(e)
		}
		out, e = parseDriveXML(data)
		if e != nil || !out.disabled || len(out.items) != 1 {
			t.Fatal("scope disabled state lost", e)
		}
	}
	raw := strings.Replace(driveFixture, `foreign="retained"`, `foreign="retained" cpassword="SECRET"`, 1)
	doc, e := parseDriveXML([]byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	if doc.items[0].view.ReadOnly == "" {
		t.Fatal("legacy password was made editable")
	}
	b, _ := json.Marshal(doc.items[0].view)
	if bytes.Contains(b, []byte("SECRET")) {
		t.Fatal("legacy password leaked")
	}
}
func TestDriveInputRejectsInvalidPathsAndActions(t *testing.T) {
	for _, path := range []string{`server\share`, `\server\share`, `\\server`, `\\server\\share`, `\\server\..\share`, `\\server\share\..`, "\\\\server\\share\n", `\\server\share:stream`, `\\server\share/other`} {
		in := validDriveChange()
		in.Drive.Path = path
		if !errors.Is(validateDriveChange(in), policy.ErrInvalidValue) {
			t.Fatalf("accepted path %q", path)
		}
	}
	for _, raw := range []string{`<!DOCTYPE Drives><Drives/>`, `<Drives/><Drives/>`, `<Drives><Other/></Drives>`, `<Drives><Drive uid="x"><Properties/><Properties/></Drive></Drives>`} {
		if _, e := parseDriveXML([]byte(raw)); e == nil {
			t.Fatalf("accepted unsafe XML %s", raw)
		}
	}
}
func TestDriveTransactionVersionBackupAndConflict(t *testing.T) {
	for _, scope := range []string{"Machine", "User"} {
		t.Run(scope, func(t *testing.T) {
			script, root := scriptTestSnapshot(t, 7)
			snap, e := loadDriveSnapshot(script.root, script.entry, "dc.example.com", false)
			if e != nil {
				t.Fatal(e)
			}
			in := validDriveChange()
			in.Scope = scope
			in.Revision = snap.view.Revision
			backup, e := saveDriveTransaction(snap, in, func() error { return nil }, func(version uint32, ext string) error {
				expected := uint32(8)
				if scope == "User" {
					expected = 65543
				}
				if version != expected || !strings.Contains(ext, drivesCSE) || !strings.Contains(ext, drivesEditor) || !strings.HasPrefix(ext, "[{00000000-") {
					t.Fatalf("metadata: %d %s", version, ext)
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			if _, e := root.Stat(backup); e != nil {
				t.Fatal("missing backup", e)
			}
			if _, e := root.Stat(editorJournal); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("journal not cleaned", e)
			}
			data, e := root.ReadFile(scope + "/Preferences/Drives/Drives.xml")
			if e != nil {
				t.Fatal(e)
			}
			if _, e = parseDriveXML(data); e != nil {
				t.Fatal(e)
			}
			if _, e := root.Stat("Machine/Registry.pol"); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("registry modified")
			}
			if _, e := root.Stat("User/Scripts/scripts.ini"); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("scripts modified")
			}
		})
	}
	script, root := scriptTestSnapshot(t, 0)
	snap, e := loadDriveSnapshot(script.root, script.entry, "dc", false)
	if e != nil {
		t.Fatal(e)
	}
	in := validDriveChange()
	in.Revision = snap.view.Revision
	_, e = saveDriveTransaction(snap, in, func() error { return ErrPolicyConflict }, func(uint32, string) error { t.Fatal("must not commit after conflict"); return nil })
	if !errors.Is(e, ErrPolicyConflict) {
		t.Fatal(e)
	}
	if _, e := root.Stat("User"); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("conflict created directories")
	}
	_, e = saveDriveTransaction(snap, in, func() error { return nil }, func(uint32, string) error {
		return ldap.NewError(ldap.LDAPResultAssertionFailed, errors.New("concurrent writer"))
	})
	if !errors.Is(e, ErrPolicyConflict) {
		t.Fatal(e)
	}
	if _, e := root.Stat("User"); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("rollback failed to remove created directories")
	}
}
