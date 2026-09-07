package server

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Bytes()
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestShellWithPTY(t *testing.T) {
	signer, line := testSigner(t)
	_, wsURL := newTestServer(t, line, 0)
	cl := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestPty("xterm-256color", 24, 80, nil); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	out := &syncBuffer{}
	sess.Stdout = out
	sess.Stderr = out
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}
	if _, err := io.WriteString(stdin, "echo pty-ok\nexit\n"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-time.After(10 * time.Second):
		t.Fatal("shell session did not exit")
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
	}
	if !bytes.Contains(out.Bytes(), []byte("pty-ok")) {
		t.Fatalf("output %q missing %q", out.String(), "pty-ok")
	}
}

func TestShellWithoutPTY(t *testing.T) {
	signer, line := testSigner(t)
	_, wsURL := newTestServer(t, line, 0)
	cl := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess, _ := cl.NewSession()
	defer sess.Close()
	out := &syncBuffer{}
	sess.Stdout = out
	sess.Stderr = out
	stdin, _ := sess.StdinPipe()
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell without pty: %v", err)
	}
	io.WriteString(stdin, "echo pipes-ok\nexit\n")
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-time.After(10 * time.Second):
		t.Fatal("shell session did not exit")
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
	}
	if !bytes.Contains(out.Bytes(), []byte("pipes-ok")) {
		t.Fatalf("output %q missing %q", out.String(), "pipes-ok")
	}
}

func TestWindowChangeAfterSpawn(t *testing.T) {
	signer, line := testSigner(t)
	_, wsURL := newTestServer(t, line, 0)
	cl := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess, _ := cl.NewSession()
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	sess.Stdout = io.Discard
	sess.Stderr = io.Discard
	stdin, _ := sess.StdinPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	if err := sess.WindowChange(50, 200); err != nil {
		t.Fatalf("WindowChange: %v", err)
	}
	io.WriteString(stdin, "echo resized\nexit\n")
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-time.After(10 * time.Second):
		t.Fatal("shell session did not exit")
	case err := <-done:
		if err != nil {
			t.Fatalf("Wait: %v", err)
		}
	}
}

func TestCtrlCSignalsForegroundProcess(t *testing.T) {
	signer, line := testSigner(t)
	_, wsURL := newTestServer(t, line, 0)
	cl := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess, _ := cl.NewSession()
	defer sess.Close()
	if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	sess.Stdout = io.Discard
	sess.Stderr = io.Discard
	stdin, _ := sess.StdinPipe()
	if err := sess.Start(`sh -c 'trap "exit 42" INT; while :; do sleep 1; done'`); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if _, err := stdin.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-time.After(10 * time.Second):
		t.Fatal("SIGINT from Ctrl+C did not interrupt remote process")
	case err := <-done:
		var exitErr *ssh.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("Wait err = %v, want exit error via SIGINT", err)
		}
		if exitErr.ExitStatus() != 42 && exitErr.ExitStatus() != 130 {
			t.Fatalf("exit status = %d, want 42 (trap) or 130 (SIGINT propagation)", exitErr.ExitStatus())
		}
	}
}

func TestSignalNamesCoversStandardSignals(t *testing.T) {
	standard := map[syscall.Signal]string{
		syscall.SIGHUP:    "HUP",
		syscall.SIGINT:    "INT",
		syscall.SIGQUIT:   "QUIT",
		syscall.SIGILL:    "ILL",
		syscall.SIGABRT:   "ABRT",
		syscall.SIGFPE:    "FPE",
		syscall.SIGKILL:   "KILL",
		syscall.SIGSEGV:   "SEGV",
		syscall.SIGPIPE:   "PIPE",
		syscall.SIGALRM:   "ALRM",
		syscall.SIGTERM:   "TERM",
		syscall.SIGCHLD:   "CHLD",
		syscall.SIGCONT:   "CONT",
		syscall.SIGSTOP:   "STOP",
		syscall.SIGTSTP:   "TSTP",
		syscall.SIGTTIN:   "TTIN",
		syscall.SIGTTOU:   "TTOU",
		syscall.SIGURG:    "URG",
		syscall.SIGXCPU:   "XCPU",
		syscall.SIGXFSZ:   "XFSZ",
		syscall.SIGVTALRM: "VTALRM",
		syscall.SIGPROF:   "PROF",
		syscall.SIGWINCH:  "WINCH",
		syscall.SIGIO:     "IO",
		syscall.SIGPWR:    "PWR",
		syscall.SIGSYS:    "SYS",
	}
	for sig, want := range standard {
		if got := signalNames[sig]; got != want {
			t.Errorf("signalNames[%v] = %q, want %q", int(sig), got, want)
		}
	}
}
