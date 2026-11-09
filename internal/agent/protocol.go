// Package agent implements the authenticated control channel to host helpers.
package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const MaxMessage = 96 << 20
const Version = 1

type Request struct {
	Version     int             `json:"version"`
	Node        string          `json:"node"`
	ID          string          `json:"id"`
	Time        int64           `json:"time"`
	Method      string          `json:"method"`
	Params      json.RawMessage `json:"params"`
	Credentials *Credentials    `json:"credentials,omitempty"`
}
type Envelope struct {
	Request   json.RawMessage `json:"request"`
	Signature []byte          `json:"signature"`
}
type Response struct {
	Version int             `json:"version"`
	ID      string          `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
	Code    string          `json:"code,omitempty"`
}
type Handler func(context.Context, string, json.RawMessage) (any, error)

func LoadPrivate(filename string) (ed25519.PrivateKey, error) {
	st, e := os.Lstat(filename)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("agent private key must be a regular private file (0600)")
	}
	b, e := os.ReadFile(filename)
	if e != nil {
		return nil, e
	}
	raw, e := base64.StdEncoding.DecodeString(string(bytesTrim(b)))
	if e != nil || len(raw) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid agent Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(raw), nil
}
func bytesTrim(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}
func GenerateKey(privateFile, publicFile string) error {
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	write := func(name string, b []byte, mode os.FileMode) error {
		f, e := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if e != nil {
			return e
		}
		_, e = f.WriteString(base64.StdEncoding.EncodeToString(b) + "\n")
		if e == nil {
			e = f.Sync()
		}
		return errors.Join(e, f.Close())
	}
	if e = write(privateFile, priv.Seed(), 0600); e != nil {
		return e
	}
	return write(publicFile, pub, 0644)
}

type Verifier struct {
	Node     string
	Keys     []ed25519.PublicKey
	mu       sync.Mutex
	seen     map[string]int64
	stateDir string
}

func NewVerifier(node string, files []string) (*Verifier, error) {
	v := &Verifier{Node: node, seen: map[string]int64{}}
	if node == "" || len(files) == 0 {
		return nil, fmt.Errorf("helper node and trusted public keys are required")
	}
	for _, name := range files {
		st, e := os.Lstat(name)
		if e != nil {
			return nil, e
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0022 != 0 || !trustedOwner(st) {
			return nil, fmt.Errorf("trusted public key must be a regular file not writable by group or others")
		}
		b, e := os.ReadFile(name)
		if e != nil {
			return nil, e
		}
		raw, e := base64.StdEncoding.DecodeString(string(bytesTrim(b)))
		if e != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid helper trusted public key")
		}
		v.Keys = append(v.Keys, ed25519.PublicKey(raw))
	}
	return v, nil
}
func (v *Verifier) Dispatch(ctx context.Context, raw []byte, handler Handler) Response {
	out := Response{Version: Version}
	var env Envelope
	if len(raw) > MaxMessage || json.Unmarshal(raw, &env) != nil {
		return unauthorized(out)
	}
	valid := false
	for _, key := range v.Keys {
		if ed25519.Verify(key, env.Request, env.Signature) {
			valid = true
			break
		}
	}
	if !valid {
		return unauthorized(out)
	}
	var req Request
	if json.Unmarshal(env.Request, &req) != nil || (req.Version != Version && req.Version != CredentialVersion) || req.Node != v.Node || len(req.ID) != 32 || len(req.Method) > 80 {
		return unauthorized(out)
	}
	if id, e := hex.DecodeString(req.ID); e != nil || len(id) != 16 {
		return unauthorized(out)
	}
	// Version 2 is mandatory when forwarding credentials, so older helpers
	// cannot silently ignore them and fall back to a service identity.
	if req.Credentials != nil {
		if req.Version != CredentialVersion || !req.Credentials.Valid() || !strings.HasPrefix(req.Method, "sysvol.") {
			return unauthorized(out)
		}
	} else if req.Version != Version {
		return unauthorized(out)
	}
	out.Version = req.Version
	out.ID = req.ID
	now := time.Now().Unix()
	if req.Time < now-90 || req.Time > now+30 {
		return unauthorized(out)
	}
	v.mu.Lock()
	for id, t := range v.seen {
		if t < now-120 {
			delete(v.seen, id)
		}
	}
	_, replay := v.seen[req.ID]
	full := len(v.seen) >= 10000
	if !replay && !full {
		v.seen[req.ID] = now
	}
	v.mu.Unlock()
	if replay || full {
		return unauthorized(out)
	}
	if e := v.remember(req, now); e != nil {
		return unauthorized(out)
	}
	if req.Credentials != nil {
		credentials := *req.Credentials
		ctx = WithCredentials(ctx, func() (Credentials, error) { return credentials, nil })
	}
	result, e := handler(ctx, req.Method, req.Params)
	if req.Credentials != nil {
		e = RedactCredentialError(e, *req.Credentials)
	}
	if e != nil {
		out.Error = e.Error()
		switch {
		case errors.Is(e, os.ErrNotExist):
			out.Code = "not-found"
		case errors.Is(e, os.ErrExist):
			out.Code = "exists"
		case errors.Is(e, os.ErrPermission):
			out.Code = "permission"
		}
		return out
	}
	out.Result, e = json.Marshal(result)
	if e != nil {
		out.Error = "helper response encoding failed"
	}
	return out
}
func unauthorized(out Response) Response {
	out.Error = "helper authentication rejected"
	out.Code = "unauthorized"
	return out
}
