package adremote

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestRPCCancellationClosesBlockedSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &rpcDialer{ctx: ctx}
	stop := context.AfterFunc(ctx, d.close)
	defer stop()
	c, err := d.DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	done := make(chan error, 1)
	go func() { var b [1]byte; _, e := c.Read(b[:]); done <- e }()
	cancel()
	select {
	case err = <-done:
		if err == nil {
			t.Fatal("read succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock transport")
	}
	if _, err = d.DialContext(context.Background(), "tcp", listener.Addr().String()); err == nil {
		t.Fatal("closed RPC accepted new transport")
	}
	d.close()
}
