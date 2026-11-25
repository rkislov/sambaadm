package dcdemote

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCredentialsAndIdentityGates(t *testing.T) {
	good := Input{Node: "dc2.corp.test", Source: "dc1.corp.test", Realm: "corp.test", Username: "Administrator@corp.test", Password: "SecretA1!"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Input){func(i *Input) { i.Source = i.Node }, func(i *Input) { i.Source = "dc1.other.test" }, func(i *Input) { i.Node = "-x.corp.test" }, func(i *Input) { i.Password = "" }, func(i *Input) { i.Username = "u\n--option" }, func(i *Input) { i.Realm = "corp.test\n" }} {
		in := good
		change(&in)
		if in.Validate() == nil {
			t.Fatal("unsafe identity/credentials accepted")
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", good, good), good.Password) {
		t.Fatal("credentials exposed by formatting")
	}
	e := Engine{Dir: t.TempDir(), Config: "/etc/helper.yaml"}
	if _, err := e.Start(context.Background(), good, false); err == nil {
		t.Fatal("unconfirmed operation accepted")
	}
	good.Confirm = good.Node
	good.Revision = strings.Repeat("g", 64)
	if _, err := e.Start(context.Background(), good, false); err == nil {
		t.Fatal("invalid revision accepted")
	}
	if _, err := e.Read("../status"); err == nil {
		t.Fatal("path traversal accepted")
	}
}
func TestJournalAndProtectedState(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	e := Engine{Dir: dir, Config: "/etc/helper.yaml"}
	if _, err := e.script(); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	os.Mkdir(filepath.Join(dir, id), 0700)
	os.WriteFile(filepath.Join(dir, id, "status.json"), []byte(`{"id":"`+id+`","node":"dc2.corp.test","state":"needs_member","log":["DC retired"]}`), 0600)
	st, err := e.Read(id)
	if err != nil || st.State != "needs_member" {
		t.Fatal(st, err)
	}
	os.Chmod(dir, 0755)
	if _, err := e.script(); err == nil {
		t.Fatal("world-readable state accepted")
	}
}
