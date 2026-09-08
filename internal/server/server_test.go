package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
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
	mux := http.NewServeMux()
	mux.Handle("/ws", s.WebSocketHandler())
	up := httptest.NewServer(mux)
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http") + "/ws"

	cl1 := dialTestSSH(t, wsURL, currentUser(t), signer)
	cl2 := dialTestSSH(t, wsURL, currentUser(t), signer)

	s1, err := cl1.NewSession()
	if err != nil {
		t.Fatalf("session 1: %v", err)
	}
	s1b, err := cl1.NewSession()
	if err != nil {
		t.Fatalf("session 1b: %v", err)
	}
	s2, err := cl2.NewSession()
	if err != nil {
		t.Fatalf("session 2: %v", err)
	}

	_, err = cl1.NewSession()
	if err == nil {
		t.Fatal("third session on same conn should have been rejected")
	}
	openErr, ok := err.(*ssh.OpenChannelError)
	if !ok {
		t.Fatalf("expected *ssh.OpenChannelError, got %T: %v", err, err)
	}
	if openErr.Reason != ssh.ResourceShortage {
		t.Fatalf("reason = %v, want ResourceShortage", openErr.Reason)
	}

	cl3 := dialTestSSH(t, wsURL, currentUser(t), signer)
	s3, err := cl3.NewSession()
	if err != nil {
		t.Fatalf("session 3 on new conn: %v", err)
	}
	s1.Close()
	s1b.Close()
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

	s1, _ := cl1.NewSession()
	s1.Start("sleep 60")
	s2, _ := cl2.NewSession()
	s2.Start("sleep 60")

	s3, err := cl3.NewSession()
	if err != nil {
		t.Fatalf("third session open: %v", err)
	}
	err = s3.Start("echo boom")
	if err == nil {
		t.Fatal("third session should have been rejected (sem full)")
	}
	s3.Close()

	s1.Close()
	time.Sleep(300 * time.Millisecond)

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
	cl3.Close()
	cl4.Close()
}

func TestMaxChildrenSemNotLeakedOnMalformedExec(t *testing.T) {
	signer, line := testSigner(t)
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	os.WriteFile(akPath, []byte(line), 0o600)

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

	s1, _ := cl1.NewSession()
	s1.Start("sleep 60")
	s2, _ := cl2.NewSession()
	s2.Start("sleep 60")

	s1.Close()
	time.Sleep(300 * time.Millisecond)

	cl3 := dialTestSSH(t, wsURL, currentUser(t), signer)
	ch, _, err := cl3.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open channel: %v", err)
	}
	for i := 0; i < 5; i++ {
		ok, err := ch.SendRequest("exec", true, []byte{0x00})
		if ok {
			t.Fatal("expected false reply for malformed exec")
		}
		_ = err
	}
	ch.Close()
	cl3.Close()

	cl4 := dialTestSSH(t, wsURL, currentUser(t), signer)
	s4, err := cl4.NewSession()
	if err != nil {
		t.Fatalf("valid session after malformed execs: %v", err)
	}
	defer s4.Close()
	var out bytes.Buffer
	s4.Stdout = &out
	if err := s4.Run("echo ok"); err != nil {
		t.Fatalf("valid exec failed: %v", err)
	}
	if out.String() != "ok\n" {
		t.Fatalf("output = %q, want %q", out.String(), "ok\n")
	}

	s2.Close()
	cl1.Close()
	cl2.Close()
	cl4.Close()
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

// stallConn accepts writes, then blocks reads until the deadline set by
// serveConn expires — simulating a Slowloris client that never completes
// the SSH handshake.
type stallConn struct {
	mu        sync.Mutex
	deadline  time.Time
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *stallConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	var timer <-chan time.Time
	if !d.IsZero() {
		timer = time.After(time.Until(d))
	}
	select {
	case <-timer:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *stallConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(b), nil
	}
}

func (c *stallConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *stallConn) LocalAddr() net.Addr  { return dummyAddr{} }
func (c *stallConn) RemoteAddr() net.Addr { return dummyAddr{} }
func (c *stallConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *stallConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *stallConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

// recordingConn records SetDeadline calls while delegating to a real conn.
type recordingConn struct {
	net.Conn
	mu       sync.Mutex
	deadline []time.Time
}

func (c *recordingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = append(c.deadline, t)
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

// Rewrites the package-level handshakeTimeout (restored via t.Cleanup); must
// not run under t.Parallel, which would race other tests' handshakes.
func TestServeConnHandshakeDeadline(t *testing.T) {
	s := newAuthServer(t, "")
	old := handshakeTimeout
	handshakeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = old })

	sc := &stallConn{closed: make(chan struct{})}
	s.handshakeSem <- struct{}{}
	s.wg.Add(1)
	done := make(chan struct{})
	go func() {
		s.serveConn(sc, "test:1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveConn did not return after handshake deadline")
	}
	sc.mu.Lock()
	d := sc.deadline
	sc.mu.Unlock()
	if d.IsZero() {
		t.Fatal("handshake deadline was not set before ssh.NewServerConn")
	}
}

func TestServeConnClearsDeadlineAfterHandshake(t *testing.T) {
	signer, line := testSigner(t)
	s := newAuthServer(t, line)
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	rcCh := make(chan *recordingConn, 1)
	errCh := make(chan error, 1)
	go func() {
		sc, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		rc := &recordingConn{Conn: sc}
		rcCh <- rc // channel send happens-before the main goroutine's receive
		s.handshakeSem <- struct{}{}
		s.wg.Add(1)
		s.serveConn(rc, ln.Addr().String())
	}()

	addr := ln.Addr().String()
	cfg := &ssh.ClientConfig{
		User:            u.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	netConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = netConn.SetDeadline(time.Now().Add(10 * time.Second))
	conn, chans, reqs, err := ssh.NewClientConn(netConn, addr, cfg)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	_ = chans // test opens no channels; closing the client ends serveConn

	var rc *recordingConn
	var ok bool
	for i := 0; i < 100; i++ {
		select {
		case rc = <-rcCh:
		case err := <-errCh:
			t.Fatalf("Accept failed: %v", err)
		default:
		}
		if rc != nil {
			rc.mu.Lock()
			if len(rc.deadline) > 0 && rc.deadline[len(rc.deadline)-1].IsZero() {
				ok = true
			}
			rc.mu.Unlock()
		}
		if ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = netConn.SetDeadline(time.Time{})
	if !ok {
		t.Fatal("deadline not cleared after successful handshake")
	}
}

func TestMaxHandshakesDefault(t *testing.T) {
	signer, _ := testSigner(t)
	s := New(Config{Signer: signer})
	if cap(s.handshakeSem) != 64 {
		t.Fatalf("default MaxHandshakes = %d, want 64", cap(s.handshakeSem))
	}
	s2 := New(Config{Signer: signer, MaxHandshakes: 2})
	if cap(s2.handshakeSem) != 2 {
		t.Fatalf("MaxHandshakes = %d, want 2", cap(s2.handshakeSem))
	}
}

func newMaxHandshakesServer(t *testing.T, maxHandshakes int) (*Server, string, string, ssh.Signer) {
	t.Helper()
	signer, line := testSigner(t)
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(akPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		Signer:             signer,
		Logger:             discardLogger(),
		AuthorizedKeysPath: func(*user.User) string { return akPath },
		MaxHandshakes:      maxHandshakes,
	})
	t.Cleanup(s.Close)
	mux := http.NewServeMux()
	mux.Handle("/ws", s.WebSocketHandler())
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)
	wsURL := "ws" + strings.TrimPrefix(up.URL, "http") + "/ws"
	httpURL := "http" + strings.TrimPrefix(up.URL, "http") + "/ws"
	return s, wsURL, httpURL, signer
}

func TestMaxHandshakesSemRejectsAtCapacity(t *testing.T) {
	_, wsURL, httpURL, signer := newMaxHandshakesServer(t, 1)

	held, err := transport.Dial(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer held.Close()

	resp, err := http.Get(httpURL)
	if err != nil {
		t.Fatalf("probe get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("probe status = %d, want 503 while handshake in flight", resp.StatusCode)
	}

	held.Close()
	var recovered *ssh.Client
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		netConn, err := transport.Dial(ctx, wsURL)
		if err != nil {
			cancel()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		cfg := &ssh.ClientConfig{
			User:            currentUser(t),
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         2 * time.Second,
		}
		conn, chans, reqs, err := ssh.NewClientConn(netConn, "test:1", cfg)
		cancel()
		if err != nil {
			netConn.Close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		recovered = ssh.NewClient(conn, chans, reqs)
		break
	}
	if recovered == nil {
		t.Fatal("handshake slot not released after stalled handshake closed")
	}
	defer recovered.Close()
	sess, err := recovered.NewSession()
	if err != nil {
		t.Fatalf("session after recovery: %v", err)
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	if err := sess.Run("echo recovered"); err != nil {
		t.Fatalf("run after recovery: %v", err)
	}
	if out.String() != "recovered\n" {
		t.Fatalf("output = %q, want %q", out.String(), "recovered\n")
	}
}

func TestMaxHandshakesSemReleasedAfterHandshake(t *testing.T) {
	_, wsURL, _, signer := newMaxHandshakesServer(t, 1)

	cl1 := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess1, err := cl1.NewSession()
	if err != nil {
		t.Fatalf("session 1: %v", err)
	}
	if err := sess1.Start("sleep 60"); err != nil {
		t.Fatalf("start long-lived session: %v", err)
	}

	cl2 := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess2, err := cl2.NewSession()
	if err != nil {
		t.Fatalf("session 2: %v", err)
	}
	defer sess2.Close()
	var out bytes.Buffer
	sess2.Stdout = &out
	if err := sess2.Run("echo while-alive"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.String() != "while-alive\n" {
		t.Fatalf("output = %q, want %q", out.String(), "while-alive\n")
	}

	sess1.Close()
	cl1.Close()
	cl2.Close()
}
