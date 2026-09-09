package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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

	"github.com/lucanhost/wssh/internal/server"
)

func startLoopbackServer(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	os.WriteFile(akPath, ssh.MarshalAuthorizedKey(signer.PublicKey()), 0o600)
	srv := server.New(server.Config{
		Signer:             signer,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuthorizedKeysPath: func(*user.User) string { return akPath },
	})
	t.Cleanup(srv.Close)
	mux := http.NewServeMux()
	mux.Handle("/ws", srv.WebSocketHandler())
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)
	return up.URL, signer
}

func loopbackClient(t *testing.T) *ssh.Client {
	t.Helper()
	upURL, signer := startLoopbackServer(t)
	u, _ := user.Current()
	username := u.Username
	if idx := strings.LastIndex(username, "\\"); idx != -1 {
		username = username[idx+1:]
	}
	tgt, err := ParseTarget("ws://" + username + "@" + strings.TrimPrefix(upURL, "http://") + "/ws")
	if err != nil {
		t.Fatal(err)
	}
	cl, err := Connect(context.Background(), tgt, []ssh.Signer{signer}, ssh.InsecureIgnoreHostKey())
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { cl.Close() })
	return cl
}

func TestRunCommandOutputAndExitCode(t *testing.T) {
	cl := loopbackClient(t)
	var out bytes.Buffer
	err := RunCommand(cl, "echo client-ok", &out, io.Discard)
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if strings.TrimSpace(out.String()) != "client-ok" {
		t.Fatalf("output = %q", out.String())
	}
	err = RunCommand(cl, "exit 9", &out, io.Discard)
	if ExitCode(err) != 9 {
		t.Fatalf("ExitCode(err) = %d, want 9 (err=%v)", ExitCode(err), err)
	}
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 9 {
		t.Fatalf("err not ExitError{9}: %v", err)
	}
}

func TestExitCodeMapping(t *testing.T) {
	if ExitCode(nil) != 0 {
		t.Fatal("nil → 0")
	}
	if ExitCode(io.EOF) != 255 {
		t.Fatal("generic → 255")
	}
	if ExitCode(&ExitError{Code: 3}) != 3 {
		t.Fatal("ExitError → code")
	}
}

func TestConnectSurvivesDialTimeout(t *testing.T) {
	cl := loopbackClient(t)
	time.Sleep(1100 * time.Millisecond)
	var out bytes.Buffer
	err := RunCommand(cl, "echo alive", &out, io.Discard)
	if err != nil {
		t.Fatalf("RunCommand after sleep: %v", err)
	}
	if strings.TrimSpace(out.String()) != "alive" {
		t.Fatalf("output = %q", out.String())
	}
}
