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

func TestMaxAuthTriesIsThree(t *testing.T) {
	signer, _ := testSigner(t)
	s := New(Config{Signer: signer})
	if s.sshConfig.MaxAuthTries != 3 {
		t.Fatalf("MaxAuthTries = %d, want 3", s.sshConfig.MaxAuthTries)
	}
}

func TestMaxSessionsPerConnRejectsOverflow(t *testing.T) {
	signer, line := testSigner(t)
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	os.WriteFile(akPath, []byte(line), 0o600)
	s := New(Config{
		Signer:             signer,
		Logger:             discardLogger(),
		AuthorizedKeysPath: func(*user.User) string { return akPath },
		MaxSessionsPerConn: 2,
	})
	// Build minimal HTTP handler manually (skip rate limit for simplicity).
	mux := http.NewServeMux()
	mux.Handle("/ws", s.WebSocketHandler())
	up := httptest.NewServer(mux)
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http") + "/ws"

	cl1 := dialTestSSH(t, wsURL, currentUser(t), signer)
	cl2 := dialTestSSH(t, wsURL, currentUser(t), signer)

	// Open 2 sessions (under cap) — should succeed.
	s1, err := cl1.NewSession()
	if err != nil {
		t.Fatalf("session 1: %v", err)
	}
	s2, err := cl2.NewSession()
	if err != nil {
		t.Fatalf("session 2: %v", err)
	}

	// Third session on a new conn should also succeed (cap is per-conn).
	cl3 := dialTestSSH(t, wsURL, currentUser(t), signer)
	s3, err := cl3.NewSession()
	if err != nil {
		t.Fatalf("session 3 on new conn: %v", err)
	}
	s1.Close()
	s2.Close()
	s3.Close()
	cl1.Close()
	cl2.Close()
	cl3.Close()
}

func TestMaxChildrenSemReleased(t *testing.T) {
	signer, line := testSigner(t)
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	akContent := line
	os.WriteFile(akPath, []byte(akContent), 0o600)

	s := New(Config{
		Signer:             signer,
		Logger:             discardLogger(),
		AuthorizedKeysPath: func(*user.User) string { return akPath },
		MaxChildren:        2,
	})
	mux := http.NewServeMux()
	mux.Handle("/ws", s.WebSocketHandler())
	up := httptest.NewServer(mux)
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http") + "/ws"

	cl1 := dialTestSSH(t, wsURL, currentUser(t), signer)
	cl2 := dialTestSSH(t, wsURL, currentUser(t), signer)
	cl3 := dialTestSSH(t, wsURL, currentUser(t), signer)

	// Start two long-running sessions.
	s1, _ := cl1.NewSession()
	s1.Start("sleep 60")
	s2, _ := cl2.NewSession()
	s2.Start("sleep 60")

	// Third should fail (sem full).
	s3, err := cl3.NewSession()
	if err != nil {
		t.Fatalf("third session open: %v", err)
	}
	err = s3.Start("echo boom")
	if err == nil {
		t.Fatal("third session should have been rejected (sem full)")
	}
	s3.Close()

	// Close first session — sem released.
	s1.Close()
	time.Sleep(200 * time.Millisecond)

	// Fourth should now succeed.
	cl4 := dialTestSSH(t, wsURL, currentUser(t), signer)
	s4, err := cl4.NewSession()
	if err != nil {
		t.Fatalf("fourth session after release: %v", err)
	}
	defer s4.Close()
	var out bytes.Buffer
	s4.Stdout = &out
	if err := s4.Run("echo after-release"); err != nil {
		t.Fatalf("run after release: %v", err)
	}
	if out.String() != "after-release\n" {
		t.Fatalf("output = %q, want %q", out.String(), "after-release\n")
	}
	cl1.Close()
	cl2.Close()
	cl4.Close()
}
