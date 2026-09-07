package transport

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestDialAcceptRoundTrip(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nc, err := Accept(w, r)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer nc.Close()
		buf := make([]byte, 3)
		if _, err := io.ReadFull(nc, buf); err != nil {
			t.Errorf("read: %v", err)
			return
		}
		if string(buf) != "abc" {
			t.Errorf("got %q want %q", buf, "abc")
		}
		_, _ = nc.Write([]byte("xyz"))
	}))
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nc, err := Dial(ctx, wsURL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer nc.Close()
	if _, err := nc.Write([]byte("abc")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(nc, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "xyz" {
		t.Fatalf("got %q want %q", buf, "xyz")
	}
}

func TestDialSendsBinaryFrames(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer c.Close(websocket.StatusNormalClosure, "")
		typ, reader, err := c.Reader(context.Background())
		if err != nil {
			t.Errorf("reader: %v", err)
			return
		}
		if typ != websocket.MessageBinary {
			t.Errorf("frame type = %v, want MessageBinary", typ)
		}
		_, _ = io.Copy(io.Discard, reader)
	}))
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nc, err := Dial(ctx, wsURL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer nc.Close()
	if _, err := nc.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
}

func TestReadLimitRejectsOversizedMessage(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nc, err := Accept(w, r)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		defer nc.Close()
		buf := make([]byte, 64*1024)
		if _, err := io.ReadFull(nc, buf); err != nil {
			t.Fatalf("read mid-size: %v", err)
		}
		if _, err := nc.Write([]byte("ok")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}))
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nc, err := Dial(ctx, wsURL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer nc.Close()

	if _, err := nc.Write(make([]byte, 64*1024)); err != nil {
		t.Fatalf("write mid-size: %v", err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(nc, buf); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(buf) != "ok" {
		t.Fatalf("got %q want %q", buf, "ok")
	}

	up2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nc, err := Accept(w, r)
		if err != nil {
			t.Fatalf("Accept2: %v", err)
		}
		defer nc.Close()

		buf := make([]byte, 1<<20+1)
		n, err := nc.Read(buf)
		if err != nil || n != len(buf) {
			t.Fatalf("first read: got %d bytes, err=%v", n, err)
		}

		readBuf := make([]byte, 1)
		n, err = nc.Read(readBuf)
		if err == nil {
			t.Fatal("expected error for oversized message, got nil")
		}
		if !errors.Is(err, websocket.ErrMessageTooBig) {
			t.Fatalf("expected ErrMessageTooBig, got: %v", err)
		}
	}))
	defer up2.Close()

	wsURL2 := "ws" + strings.TrimPrefix(up2.URL, "http")
	nc2, err := Dial(ctx, wsURL2)
	if err != nil {
		t.Fatalf("Dial2: %v", err)
	}

	largeMsg := make([]byte, 1<<20+1)
	if _, err := nc2.Write(largeMsg); err != nil {
		t.Fatalf("write oversized: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	nc2.Close()
}
