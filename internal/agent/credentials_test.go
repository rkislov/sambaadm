package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCredentialProtocolBindsIdentityAndDoesNotPersistSecrets(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{Node: "dc0.example.org", Keys: []ed25519.PublicKey{public}, seen: map[string]int64{}}
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err := v.UseStateDir(state); err != nil {
		t.Fatal(err)
	}
	sign := func(req Request) []byte {
		data, _ := json.Marshal(req)
		raw, _ := json.Marshal(Envelope{Request: data, Signature: ed25519.Sign(key, data)})
		return raw
	}
	credentials := Credentials{Username: "admin@example.org", Password: "not-for-disk-operator-secret"}
	base := Request{Version: CredentialVersion, Node: v.Node, ID: strings.Repeat("a", 32), Time: time.Now().Unix(), Method: "sysvol.stat", Params: json.RawMessage(`{}`), Credentials: &credentials}
	calls := 0
	handler := func(ctx context.Context, method string, _ json.RawMessage) (any, error) {
		calls++
		got, present, err := OperationCredentials(ctx)
		if err != nil || !present || got != credentials {
			t.Error("missing operation identity")
		}
		return nil, fmt.Errorf("synthetic failure %s", got.Password)
	}
	result := v.Dispatch(context.Background(), sign(base), handler)
	if result.Version != CredentialVersion || !strings.Contains(result.Error, "[redacted]") || strings.Contains(result.Error, credentials.Password) {
		t.Fatal("credential protocol or redaction failed")
	}
	for _, change := range []func(*Request){func(r *Request) { r.Version = Version }, func(r *Request) { r.Credentials = nil }, func(r *Request) { r.Method = "health" }} {
		r := base
		r.ID = strings.Repeat("b", 32)
		change(&r)
		if got := v.Dispatch(context.Background(), sign(r), handler); got.Code != "unauthorized" {
			t.Fatal("unsupported credentials accepted")
		}
	}
	if calls != 1 {
		t.Fatal("rejected request reached handler")
	}
	if err := filepath.WalkDir(state, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(raw), credentials.Password) {
			t.Error("password persisted in replay state")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", credentials, credentials), credentials.Password) {
		t.Fatal("credentials visible in formatting")
	}
}

func TestBackgroundCredentialResolverRemainsRevocable(t *testing.T) {
	valid := true
	source := WithCredentials(context.Background(), func() (Credentials, error) {
		if !valid {
			return Credentials{}, fmt.Errorf("session expired")
		}
		return Credentials{Username: "admin", Password: "secret"}, nil
	})
	background := CarryCredentials(context.Background(), source)
	if _, present, err := OperationCredentials(background); !present || err != nil {
		t.Fatal("provider not carried")
	}
	valid = false
	if _, present, err := OperationCredentials(background); !present || err == nil {
		t.Fatal("expired identity silently fell back")
	}
}
