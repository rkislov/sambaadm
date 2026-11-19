package service

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"path/filepath"
	ldapproto "sambaadm/internal/ldap"
	"testing"
	"time"
)

func TestIntegrationObjectBackupRestore(t *testing.T) {
	services, cfg := integrationServices(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	client := services.Users.ldap
	store := NewObjectBackupService(client, services.GPO, filepath.Join(t.TempDir(), "backups"), services.Audit)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	login := "bk" + suffix
	pc := "pc" + suffix
	user, err := services.Users.Create(ctx, CreateUserInput{Login: login, Description: "restore-profile", Mail: "restore@example.test"}, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Delete(context.Background(), user.DN) })
	pcDN := BuildDN("CN", pc, "CN=Computers,"+cfg.BaseDN)
	err = client.Add(ctx, pcDN, []ldap.Attribute{{Type: "objectClass", Vals: []string{"computer"}}, {Type: "sAMAccountName", Vals: []string{pc + "$"}}, {Type: "userAccountControl", Vals: []string{"4098"}}, {Type: "description", Vals: []string{"restore-workstation"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Delete(context.Background(), pcDN) })
	policyName := "IT-Backup-" + suffix
	_, err = services.GPO.Create(ctx, policyName, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { services.GPO.Delete(context.Background(), policyName, "test", "") })
	snapshot, err := store.Create(ctx, "test", "")
	if err != nil {
		t.Fatal(err)
	}
	var policyObj *ObjectBackupEntry
	for _, o := range snapshot.Objects {
		if o.Kind == "gpo" && o.Name == policyName {
			copy := o
			policyObj = &copy
		}
	}
	if policyObj == nil {
		t.Fatal("GPO missing from backup")
	}
	for _, dn := range []string{user.DN, pcDN} {
		before, err := client.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID", "objectSid"}})
		if err != nil {
			t.Fatal(err)
		}
		guid := hex.EncodeToString(before.GetRawAttributeValue("objectGUID"))
		live, err := store.Preview(ctx, snapshot.ID, guid)
		if err != nil || live.CanRestore {
			t.Fatalf("live object restorable: %+v %v", live, err)
		}
		if err = client.Delete(ctx, dn); err != nil {
			t.Fatal(err)
		}
		plan, err := store.Preview(ctx, snapshot.ID, guid)
		if err != nil {
			t.Fatal(err)
		}
		if !plan.CanRestore {
			t.Fatalf("cannot restore: %+v", plan)
		}
		if err = store.Restore(ctx, snapshot.ID, guid, plan.Revision, "test", ""); err != nil {
			t.Fatal(err)
		}
		after, err := client.SearchOne(ctx, ldapproto.SearchOptions{BaseDN: dn, Scope: ldapproto.ScopeBase(), Attributes: []string{"objectGUID", "objectSid", "description", "userAccountControl"}})
		if err != nil {
			t.Fatal(err)
		}
		for _, attr := range []string{"objectGUID", "objectSid"} {
			if !bytes.Equal(before.GetRawAttributeValue(attr), after.GetRawAttributeValue(attr)) {
				t.Fatalf("identity changed: %s", attr)
			}
		}
		if after.GetAttributeValue("description") == "" {
			t.Fatal("profile not restored")
		}
	}
	if err = services.GPO.Delete(ctx, policyName, "test", ""); err != nil {
		t.Fatal(err)
	}
	plan, err := store.Preview(ctx, snapshot.ID, policyObj.GUID)
	if err != nil || !plan.CanRestore {
		t.Fatalf("GPO plan %+v %v", plan, err)
	}
	if err = store.Restore(ctx, snapshot.ID, policyObj.GUID, plan.Revision, "test", ""); err != nil {
		t.Fatal(err)
	}
	after, _, err := services.GPO.captureNativeBackup(ctx, policyName)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := client.SearchOne(ctx, ldapproto.SearchOptions{Filter: "(&(objectClass=groupPolicyContainer)(displayName=" + ldap.EscapeFilter(policyName) + "))", Attributes: []string{"objectGUID"}})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(restored.GetRawAttributeValue("objectGUID")) == policyObj.GUID {
		t.Fatal("GPO should have a new identity")
	}
	for path, want := range policyObj.Policy.Files {
		if !bytes.Equal(after.Files[path], want) {
			t.Fatalf("policy file mismatch: %s", path)
		}
	}
	t.Log("logical snapshot restored deleted user and workstation with original SID/GUID, and GPO with new identity and SYSVOL files")
}
