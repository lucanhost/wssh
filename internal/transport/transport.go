// Package transport provides WebSocket-to-net.Conn bridging for SSH over
// WebSocket.
//
// The core mechanism wraps a WebSocket connection into a net.Conn interface,
// allowing golang.org/x/crypto/ssh to run unmodified over WebSocket binary
// frames.
//
// # Binary Frames
//
// All WebSocket messages use websocket.MessageBinary. Text frames would
// corrupt the SSH protocol stream.
//
// # Keepalive
//
// Both Accept and Dial start a background goroutine that sends WebSocket
// ping frames every 15 seconds (5 second timeout). This survives idle-killing
// proxies and firewalls. The goroutine exits on ping failure or connection
// close.
package transport

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	keepaliveInterval = 15 * time.Second
	keepaliveTimeout  = 5 * time.Second
)

// Accept upgrades the HTTP request to a WebSocket connection and returns it
// wrapped in a net.Conn suitable for serving SSH over. Messages are
// exchanged as binary frames only, frames larger than 1 MiB are rejected,
// and a keepalive goroutine pings the peer every 15 seconds; closing the
// returned conn stops the keepalive. WebSocket compression is disabled.
func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go keepalive(context.Background(), c, done)
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	c.SetReadLimit(1 << 20)
	return &connWithDone{Conn: nc, done: done}, nil
}

// Dial connects to the WebSocket endpoint at rawURL and returns the
// connection wrapped in a net.Conn suitable for driving SSH over. Messages
// are exchanged as binary frames only, frames larger than 1 MiB are
// rejected, and a keepalive goroutine pings the peer every 15 seconds;
// closing the returned conn stops the keepalive. WebSocket compression is
// disabled.
func Dial(ctx context.Context, rawURL string) (net.Conn, error) {
	c, _, err := websocket.Dial(ctx, rawURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	go keepalive(context.Background(), c, done)
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	c.SetReadLimit(1 << 20)
	return &connWithDone{Conn: nc, done: done}, nil
}

type connWithDone struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *connWithDone) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

func keepalive(ctx context.Context, c *websocket.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, keepaliveTimeout)
			if err := c.Ping(pingCtx); err != nil {
				cancel()
				return
			}
			cancel()
		}
	}
}
