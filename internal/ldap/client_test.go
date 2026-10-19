package ldap

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"sambaadm/internal/config"
	"sambaadm/internal/testldap"
)

func TestServiceIdentitySurvivesParallelUserBindsAndReconnect(t *testing.T) {
	server := testldap.New(t, map[string]string{"service": "service-pass", "alice": "alice-pass", "bob": "bob-pass"}, func(q testldap.Search) ([]testldap.Entry, int64) {
		return []testldap.Entry{{DN: "CN=entry", Attributes: map[string][]string{"boundAs": {q.User}}}}, 0
	})
	cfg := config.LDAPConfig{URI: server.URI(), BaseDN: "DC=example,DC=com", Bind: config.BindConfig{User: "service", Type: "simple"}}
	shared := NewServiceClient(cfg, func() string { return "service-pass" })
	defer shared.Close()
	ctx := context.Background()
	check := func() {
		entries, e := shared.Search(ctx, SearchOptions{})
		if e != nil {
			t.Error(e)
			return
		}
		if len(entries) != 1 || entries[0].GetAttributeValue("boundAs") != "service" {
			t.Errorf("service query used browser identity: %+v", entries)
		}
	}
	check()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			user, pass := "alice", "alice-pass"
			if i%2 == 1 {
				user, pass = "bob", "bob-pass"
			}
			login := NewClient(cfg)
			defer login.Close()
			if e := login.BindSimple(ctx, user, pass); e != nil {
				t.Error(e)
			}
			check()
		}(i)
	}
	wg.Wait()
	if e := shared.BindSimple(ctx, "alice", "alice-pass"); e == nil {
		t.Fatal("service identity can be rebound")
	}
	if e := shared.BindAnonymous(ctx); e == nil {
		t.Fatal("service identity can become anonymous")
	}
	check()
	// Force a peer disconnect and exercise automatic authenticated reconnect.
	connection, err := shared.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	server.CloseConnections()
	deadline := time.Now().Add(time.Second)
	for !connection.IsClosing() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !connection.IsClosing() {
		t.Fatal("client did not observe peer disconnect")
	}
	check()
	serviceBinds := 0
	for _, b := range server.Binds() {
		if b.User == "service" {
			serviceBinds++
		}
	}
	if serviceBinds != 2 {
		t.Fatalf("expected service rebind after disconnect, got %d", serviceBinds)
	}
	for _, b := range server.Binds() {
		if !b.Success {
			t.Fatalf("unexpected bind failure: %+v", b)
		}
	}
}
func TestServiceClientNeverPublishesFailedBind(t *testing.T) {
	server := testldap.New(t, map[string]string{"service": "correct"}, func(q testldap.Search) ([]testldap.Entry, int64) { return nil, 0 })
	cfg := config.LDAPConfig{URI: server.URI(), Bind: config.BindConfig{User: "service"}}
	pass := "wrong"
	client := NewServiceClient(cfg, func() string { return pass })
	defer client.Close()
	if _, e := client.Conn(context.Background()); e == nil {
		t.Fatal("invalid service password accepted")
	}
	if client.conn != nil {
		t.Fatal("failed bind was published")
	}
	pass = "correct"
	if _, e := client.Conn(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(server.Binds()) != 2 {
		t.Fatalf("expected fresh connection after failure: %+v", server.Binds())
	}
	if server.Binds()[0].Connection == server.Binds()[1].Connection {
		t.Fatal("failed connection was reused")
	}
}
func TestServiceClientRequiresCredentialsAndHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := NewClient(config.LDAPConfig{URI: "ldaps://127.0.0.1:1"})
	if e := c.Connect(ctx); e != context.Canceled {
		t.Fatalf("canceled context: %v", e)
	}
	for _, cfg := range []config.LDAPConfig{{}, {Bind: config.BindConfig{User: "service"}}} {
		c := NewServiceClient(cfg, func() string { return "" })
		if e := c.Connect(context.Background()); e == nil || !strings.Contains(e.Error(), "not configured") {
			t.Fatalf("missing service credentials: %v", e)
		}
	}
	raw := NewClient(config.LDAPConfig{URI: "ldap://127.0.0.1:1"})
	if e := raw.BindSimple(context.Background(), "alice", ""); e == nil {
		t.Fatal("empty password accepted")
	}
}

func TestEncodedLDAPISocketAndTLSHandshakeCancellation(t *testing.T) {
	if runtime.GOOS != "windows" {
		dir, err := os.MkdirTemp("/tmp", "sa-ldapi-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		// Keep Unix socket paths below the platform's sockaddr_un limit.
		if len(dir) > 70 {
			t.Skip("temporary directory path too long for Unix sockets")
		}
		path := filepath.Join(dir, "ldap.sock")
		listener, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		done := make(chan struct{})
		go func() {
			defer close(done)
			c, e := listener.Accept()
			if e == nil {
				c.Close()
			}
		}()
		client := NewClient(config.LDAPConfig{URI: "ldapi://" + url.PathEscape(path)})
		if e := client.Connect(context.Background()); e != nil {
			t.Fatal(e)
		}
		client.Close()
		<-done
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := listener.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	client := NewClient(config.LDAPConfig{URI: "ldaps://" + listener.Addr().String()})
	if e := client.Connect(ctx); e == nil {
		client.Close()
		t.Fatal("silent TLS peer accepted")
	}
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(time.Second):
		t.Fatal("no accepted TLS connection")
	}
}
