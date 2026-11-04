package adremote

import (
	"context"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"net"
	"sync"
	"time"
)

// RPC's SMB shutdown performs network I/O without a context. Own the sockets
// so cancellation also interrupts Mount, Unmount and Logoff in the dependency.
type rpcDialer struct {
	ctx     context.Context
	mu      sync.Mutex
	sockets []net.Conn
	closed  bool
}

func (d *rpcDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.ctx.Err() != nil {
		c.Close()
		return nil, context.Canceled
	}
	d.sockets = append(d.sockets, c)
	return c, nil
}
func (d *rpcDialer) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, c := range d.sockets {
		_ = c.Close()
	}
	d.sockets = nil
}

type boundedRPC struct {
	dcerpc.Conn
	dialer *rpcDialer
	cancel context.CancelFunc
	stop   func() bool
}

func (c *boundedRPC) Close(ctx context.Context) error {
	c.dialer.close()
	c.stop()
	c.cancel()
	return c.Conn.Close(ctx)
}
