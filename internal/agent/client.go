package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Node struct {
	Name       string `mapstructure:"name"`
	Transport  string `mapstructure:"transport"`
	Endpoint   string `mapstructure:"endpoint"`
	SSHKey     string `mapstructure:"ssh_key"`
	KnownHosts string `mapstructure:"known_hosts"`
	CACert     string `mapstructure:"ca_cert"`
}
type Config struct {
	PrivateKey string `mapstructure:"private_key"`
	HostNode   string `mapstructure:"host_node"`
	Nodes      []Node `mapstructure:"nodes"`
}
type Client struct {
	Config      Config
	mu          sync.Mutex
	key         ed25519.PrivateKey
	httpClients map[string]*http.Client
}

func (c *Client) signingKey() (ed25519.PrivateKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.key == nil {
		key, e := LoadPrivate(c.Config.PrivateKey)
		if e != nil {
			return nil, e
		}
		c.key = key
	}
	return c.key, nil
}
func (c *Client) httpClient(node *Node) (*http.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client := c.httpClients[node.Name]; client != nil {
		return client, nil
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS13}
	if node.CACert != "" {
		pem, e := os.ReadFile(node.CACert)
		if e != nil {
			return nil, e
		}
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("invalid helper CA")
		}
		tc.RootCAs = roots
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tc, Proxy: http.ProxyFromEnvironment}, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("helper redirects are not allowed") }}
	if c.httpClients == nil {
		c.httpClients = map[string]*http.Client{}
	}
	c.httpClients[node.Name] = client
	return client, nil
}

func (c *Client) Has(name string) bool {
	for _, n := range c.Config.Nodes {
		if strings.EqualFold(n.Name, name) {
			return true
		}
	}
	return false
}
func (c *Client) Call(ctx context.Context, name, method string, in, out any) error {
	var node *Node
	for i := range c.Config.Nodes {
		if strings.EqualFold(c.Config.Nodes[i].Name, name) {
			node = &c.Config.Nodes[i]
			break
		}
	}
	if node == nil {
		return fmt.Errorf("no sambaadm-helper configured for node %q", name)
	}
	key, e := c.signingKey()
	if e != nil {
		return fmt.Errorf("load sambaadm-helper signing key: %w", e)
	}
	params, e := json.Marshal(in)
	if e != nil {
		return e
	}
	nonce := make([]byte, 16)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	req := Request{Version: Version, Node: node.Name, ID: hex.EncodeToString(nonce), Time: time.Now().Unix(), Method: method, Params: params}
	if strings.HasPrefix(method, "sysvol.") {
		credentials, present, err := OperationCredentials(ctx)
		if err != nil {
			return err
		}
		if present {
			req.Version = CredentialVersion
			req.Credentials = &credentials
		}
	}
	data, e := json.Marshal(req)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(Envelope{Request: data, Signature: ed25519.Sign(key, data)})
	if e != nil {
		return e
	}
	if len(raw) > MaxMessage {
		return fmt.Errorf("helper request exceeds limit")
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var response []byte
	switch node.Transport {
	case "ssh":
		if node.Endpoint == "" || strings.HasPrefix(node.Endpoint, "-") || strings.ContainsAny(node.Endpoint, " \t\r\n/\\") {
			return fmt.Errorf("invalid helper SSH endpoint")
		}
		if node.SSHKey == "" || node.KnownHosts == "" {
			return fmt.Errorf("helper SSH requires ssh_key and known_hosts")
		}
		args := []string{"-T", "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oIdentitiesOnly=yes", "-oConnectTimeout=10", "-oUserKnownHostsFile=" + node.KnownHosts, "-i", node.SSHKey, "--", node.Endpoint, "sambaadm-helper stdio"}
		cmd := exec.CommandContext(ctx, "ssh", args...)
		var input bytes.Buffer
		if e = WriteFrame(&input, raw); e != nil {
			return e
		}
		cmd.Stdin = &input
		var output cappedBuffer
		output.remaining = MaxMessage + 4
		cmd.Stdout = &output
		if e = cmd.Run(); e != nil {
			return fmt.Errorf("SSH helper request unconfirmed on %s; verify operation status before retrying", node.Name)
		}
		response, e = ReadFrame(bytes.NewReader(output.Bytes()))
		if e != nil {
			return e
		}
	case "https":
		if !strings.HasPrefix(node.Endpoint, "https://") {
			return fmt.Errorf("helper API requires HTTPS")
		}
		client, e := c.httpClient(node)
		if e != nil {
			return e
		}
		r, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(node.Endpoint, "/")+"/v1/execute", bytes.NewReader(raw))
		if e != nil {
			return e
		}
		r.Header.Set("Content-Type", "application/json")
		res, e := client.Do(r)
		if e != nil {
			return fmt.Errorf("HTTPS helper request unconfirmed on %s: %w", node.Name, e)
		}
		defer res.Body.Close()
		response, e = io.ReadAll(io.LimitReader(res.Body, MaxMessage+1))
		if e != nil {
			return e
		}
		if res.StatusCode != 200 || len(response) > MaxMessage {
			return fmt.Errorf("helper HTTP response rejected: %d", res.StatusCode)
		}
	default:
		return fmt.Errorf("helper transport must be ssh or https")
	}
	var result Response
	if json.Unmarshal(response, &result) != nil || result.ID != req.ID || result.Version != req.Version {
		return fmt.Errorf("helper %s rejected the request or session credential protocol; check its version and trusted signing key", node.Name)
	}
	if result.Error != "" {
		switch result.Code {
		case "not-found":
			return &os.PathError{Op: method, Path: node.Name + " " + result.Error, Err: os.ErrNotExist}
		case "exists":
			return &os.PathError{Op: method, Path: node.Name + " " + result.Error, Err: os.ErrExist}
		case "permission":
			return &os.PathError{Op: method, Path: node.Name + " " + result.Error, Err: os.ErrPermission}
		}
		return fmt.Errorf("helper %s: %s", node.Name, result.Error)
	}
	if out != nil {
		return json.Unmarshal(result.Result, out)
	}
	return nil
}
func WriteFrame(w io.Writer, b []byte) error {
	if len(b) > MaxMessage {
		return fmt.Errorf("helper message exceeds limit")
	}
	if e := binary.Write(w, binary.BigEndian, uint32(len(b))); e != nil {
		return e
	}
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return e
}
func ReadFrame(r io.Reader) ([]byte, error) {
	var n uint32
	if e := binary.Read(r, binary.BigEndian, &n); e != nil {
		return nil, e
	}
	if n > MaxMessage {
		return nil, fmt.Errorf("helper message exceeds limit")
	}
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}

type cappedBuffer struct {
	bytes.Buffer
	remaining int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.remaining {
		return 0, fmt.Errorf("helper response exceeds limit")
	}
	b.remaining -= len(p)
	return b.Buffer.Write(p)
}
