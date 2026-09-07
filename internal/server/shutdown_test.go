package server

import (
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
)

func TestWaitDrainsActiveSessions(t *testing.T) {
	signer, line := testSigner(t)
	srv, wsURL := newTestServer(t, line, 0)
	cl := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("sleep 30"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	done := make(chan struct{})
	go func() {
		srv.Wait()
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Wait returned while session active")
	case <-time.After(500 * time.Millisecond):
	}

	cl.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Wait did not return after connection close")
	}
}

func TestWaitTimeoutReturnsFalseOnHungSession(t *testing.T) {
	signer, line := testSigner(t)
	_, wsURL := newTestServer(t, line, 0)
	cl := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("sleep 60"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	shortSrv, shortWSURL := newTestServerWithTimeout(t, line, 0, 500*time.Millisecond)
	shortCl := dialTestSSH(t, shortWSURL, currentUser(t), signer)
	shortSess, err := shortCl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := shortSess.Start("sleep 60"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	done := make(chan bool, 1)
	go func() {
		done <- shortSrv.WaitTimeout(500 * time.Millisecond)
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("WaitTimeout returned true while hung session still active")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WaitTimeout did not return within expected window")
	}
	shortCl.Close()
}

func newTestServerWithTimeout(t *testing.T, authorizedKeys string, rate float64, timeout time.Duration) (*Server, string) {
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
		ShutdownTimeout:    timeout,
	})
	t.Cleanup(s.Close)
	mux := http.NewServeMux()
	mux.Handle("/ws", s.WebSocketHandler())
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)
	return s, "ws" + strings.TrimPrefix(up.URL, "http") + "/ws"
}
