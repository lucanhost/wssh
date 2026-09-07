package transport

import (
	"context"
	"net"
	"net/http"
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
	go keepalive(r.Context(), c)
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

func Dial(ctx context.Context, rawURL string) (net.Conn, error) {
	c, _, err := websocket.Dial(ctx, rawURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	go keepalive(ctx, c)
	return websocket.NetConn(ctx, c, websocket.MessageBinary), nil
}

func keepalive(ctx context.Context, c *websocket.Conn) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
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
