package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

	"wssh/internal/client"
	"wssh/internal/server"
)

func startServer(t *testing.T, rate float64, burst int) (target *client.Target, clientSigner ssh.Signer) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err = ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(akPath, ssh.MarshalAuthorizedKey(clientSigner.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := server.New(server.Config{
		Signer:             hostSigner,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		Rate:               rate,
		Burst:              burst,
		AuthorizedKeysPath: func(*user.User) string { return akPath },
	})
	t.Cleanup(srv.Close)
	mux := http.NewServeMux()
	mux.Handle("/ws", srv.WebSocketHandler())
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)

	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	target, err = client.ParseTarget("ws://" + u.Username + "@" + strings.TrimPrefix(up.URL, "http://") + "/ws")
	if err != nil {
		t.Fatal(err)
	}
	return target, clientSigner
}

func TestE2EExec(t *testing.T) {
	target, signer := startServer(t, 0, 0)
	cl, err := client.Connect(context.Background(), target, []ssh.Signer{signer}, ssh.InsecureIgnoreHostKey())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cl.Close()
	var out bytes.Buffer
	if err := client.RunCommand(cl, "echo e2e-ok", &out, io.Discard); err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.String() != "e2e-ok\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestE2EExitCode(t *testing.T) {
	target, signer := startServer(t, 0, 0)
	cl, err := client.Connect(context.Background(), target, []ssh.Signer{signer}, ssh.InsecureIgnoreHostKey())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer cl.Close()
	err = client.RunCommand(cl, "exit 4", io.Discard, io.Discard)
	if client.ExitCode(err) != 4 {
		t.Fatalf("exit code = %d (err=%v)", client.ExitCode(err), err)
	}
}

func TestE2EAuthReject(t *testing.T) {
	target, _ := startServer(t, 0, 0)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)
	wrong, err := ssh.NewSignerFromKey(wrongPriv)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = client.Connect(ctx, target, []ssh.Signer{wrong}, ssh.InsecureIgnoreHostKey())
	if err == nil {
		t.Fatal("unauthorized key connected")
	}
}

func TestE2EPTYShell(t *testing.T) {
	target, signer := startServer(t, 0, 0)
	cl, err := client.Connect(context.Background(), target, []ssh.Signer{signer}, ssh.InsecureIgnoreHostKey())
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatalf("pty: %v", err)
	}
	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr
	stdin, _ := sess.StdinPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	io.WriteString(stdin, "echo e2e-pty\nexit\n")
	if err := sess.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if !strings.Contains(stdout.String()+stderr.String(), "e2e-pty") {
		t.Fatalf("pty output missing marker: %q", stdout.String()+stderr.String())
	}
}

func TestE2ERateLimit(t *testing.T) {
	target, signer := startServer(t, 1, 1)
	cl, err := client.Connect(context.Background(), target, []ssh.Signer{signer}, ssh.InsecureIgnoreHostKey())
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	cl.Close()
	_, err = client.Connect(context.Background(), target, []ssh.Signer{signer}, ssh.InsecureIgnoreHostKey())
	if err == nil {
		t.Fatal("second immediate connect bypassed rate limit")
	}
}

func TestE2ETargetDefaults(t *testing.T) {
	tg, err := client.ParseTarget("user@host")
	if err != nil {
		t.Fatal(err)
	}
	if tg.Scheme != "ws" || tg.Port != 80 || tg.Path != "/ws" || tg.User != "user" || tg.Host != "host" {
		t.Fatalf("defaults wrong: %+v", tg)
	}
}
