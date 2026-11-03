package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedRequestRejectsTamperReplayWrongNodeAndExpired(t *testing.T) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	v := &Verifier{Node: "dc1.example", Keys: []ed25519.PublicKey{pub}, seen: map[string]int64{}}
	calls := 0
	handler := func(context.Context, string, json.RawMessage) (any, error) { calls++; return "ok", nil }
	sign := func(req Request, k ed25519.PrivateKey) []byte {
		b, _ := json.Marshal(req)
		raw, _ := json.Marshal(Envelope{Request: b, Signature: ed25519.Sign(k, b)})
		return raw
	}
	base := Request{Version: Version, Node: v.Node, ID: strings.Repeat("a", 32), Time: time.Now().Unix(), Method: "health", Params: json.RawMessage(`{}`)}
	raw := sign(base, key)
	if got := v.Dispatch(context.Background(), raw, handler); got.Error != "" {
		t.Fatal(got)
	}
	if got := v.Dispatch(context.Background(), raw, handler); got.Code != "unauthorized" {
		t.Fatal("replay accepted", got)
	}
	for _, test := range []struct {
		name   string
		change func(*Request)
	}{{"node", func(r *Request) { r.Node = "dc2.example" }}, {"expired", func(r *Request) { r.Time -= 200 }}, {"future", func(r *Request) { r.Time += 200 }}, {"version", func(r *Request) { r.Version = 99 }}} {
		t.Run(test.name, func(t *testing.T) {
			req := base
			test.change(&req)
			if got := v.Dispatch(context.Background(), sign(req, key), handler); got.Code != "unauthorized" {
				t.Fatal(got)
			}
		})
	}
	tampered := strings.Replace(string(raw), "health", "delete", 1)
	if got := v.Dispatch(context.Background(), []byte(tampered), handler); got.Code != "unauthorized" {
		t.Fatal("tamper accepted", got)
	}
	_, unknown, _ := ed25519.GenerateKey(rand.Reader)
	if got := v.Dispatch(context.Background(), sign(base, unknown), handler); got.Code != "unauthorized" {
		t.Fatal("unknown key accepted", got)
	}
	if calls != 1 {
		t.Fatal("unauthorized request reached handler", calls)
	}
}
func TestSigningKeyPermissionsAndExclusiveCreation(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private"), filepath.Join(dir, "public")
	if e := GenerateKey(private, public); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadPrivate(private); e != nil {
		t.Fatal(e)
	}
	if e := GenerateKey(private, public); e == nil {
		t.Fatal("overwrote signing key")
	}
	if e := os.Chmod(private, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadPrivate(private); e == nil {
		t.Fatal("publicly readable signing key accepted")
	}
}

func TestReplayRejectedAcrossIndependentHelperProcesses(t *testing.T) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	newVerifier := func() *Verifier {
		v := &Verifier{Node: "dc1", Keys: []ed25519.PublicKey{pub}, seen: map[string]int64{}}
		if e := v.UseStateDir(dir); e != nil {
			t.Fatal(e)
		}
		return v
	}
	req := Request{Version: Version, Node: "dc1", ID: strings.Repeat("c", 32), Time: time.Now().Unix(), Method: "write", Params: json.RawMessage(`{}`)}
	b, _ := json.Marshal(req)
	raw, _ := json.Marshal(Envelope{Request: b, Signature: ed25519.Sign(key, b)})
	calls := 0
	handler := func(context.Context, string, json.RawMessage) (any, error) { calls++; return nil, nil }
	if r := newVerifier().Dispatch(context.Background(), raw, handler); r.Error != "" {
		t.Fatal(r)
	}
	if r := newVerifier().Dispatch(context.Background(), raw, handler); r.Code != "unauthorized" {
		t.Fatal("replay after restart accepted", r)
	}
	if calls != 1 {
		t.Fatal(calls)
	}
}
