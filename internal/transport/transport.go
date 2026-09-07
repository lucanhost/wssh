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