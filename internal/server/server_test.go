package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"wssh/internal/transport"
)

func newTestServer(t *testing.T, authorizedKeys string, rate float64) (*Server, string) {
	t.Helper()
	hostSigner, _ := testSigner(t)
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(akPath, []byte(authorizedKeys), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		Signer:             hostSigner,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		Rate:               rate,
		Burst:              1,
		AuthorizedKeysPath: func(*user.User) string { return akPath },
	})
	t.Cleanup(s.Close)
	mux := http.NewServeMux()
	mux.Handle("/ws", s.WebSocketHandler())
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)
	return s, "ws" + strings.TrimPrefix(up.URL, "http") + "/ws"
}

func dialTestSSH(t *testing.T, wsURL, username string, signer ssh.Signer) *ssh.Client {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	netConn, err := transport.Dial(ctx, wsURL)
	if err != nil {
		cancel()
		t.Fatalf("websocket dial: %v", err)
	}
	cfg := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, chans, reqs, err := ssh.NewClientConn(netConn, "test:1", cfg)
	if err != nil {
		netConn.Close()
		cancel()
		t.Fatalf("ssh connect: %v", err)
	}
	t.Cleanup(func() { conn.Close(); cancel() })
	return ssh.NewClient(conn, chans, reqs)
}

func currentUser(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	return u.Username
}

func TestExecLoopback(t *testing.T) {
	signer, line := testSigner(t)
	_, wsURL := newTestServer(t, line, 0)
	cl := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	if err := sess.Run("echo exec-ok"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := out.String(); got != "exec-ok\n" {
		t.Fatalf("output = %q, want %q", got, "exec-ok\n")
	}
}

func TestExitStatusPropagated(t *testing.T) {
	signer, line := testSigner(t)
	_, wsURL := newTestServer(t, line, 0)
	cl := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess, _ := cl.NewSession()
	defer sess.Close()
	err := sess.Run("exit 7")
	exitErr, ok := err.(*ssh.ExitError)
	if !ok {
		t.Fatalf("err = %v, want *ssh.ExitError", err)
	}
	if exitErr.ExitStatus() != 7 {
		t.Fatalf("exit status = %d, want 7", exitErr.ExitStatus())
	}
}

func TestAuthFailureClosesConnection(t *testing.T) {
	_, line := testSigner(t)
	_, wsURL := newTestServer(t, line, 0)
	wrong, _ := testSigner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	netConn, err := transport.Dial(ctx, wsURL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ClientConfig{
		User:            currentUser(t),
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(wrong)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	_, _, _, err = ssh.NewClientConn(netConn, "test:1", cfg)
	if err == nil {
		t.Fatal("auth with unknown key succeeded")
	}
}

func TestRateLimitedUpgradeRejected(t *testing.T) {
	_, line := testSigner(t)
	_, wsURL := newTestServer(t, line, 100)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	first, err := transport.Dial(ctx, wsURL)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	first.Close()
	if _, err := transport.Dial(ctx, wsURL); err == nil {
		t.Fatal("second immediate dial passed rate limit (burst=1)")
	}
}
