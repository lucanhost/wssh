// Package client implements an SSH-over-WebSocket client.
//
// It dials a WebSocket URL, establishes an SSH connection over it, and
// provides either an interactive shell or one-shot command execution.
//
// # Target Parsing
//
// Targets use the format [ws://|wss://]user@host[:port][/path].
//
// # Host Key Verification
//
// The HostKeyCallback wraps golang.org/x/crypto/ssh/knownhosts and adds
// trust-on-first-use (TOFU) support with interactive prompts.
//
// # Modes
//
//   - Interactive shell (RunShell): raw terminal mode, SIGWINCH resize,
//     exit code 130 on Ctrl+C.
//   - Exec (RunCommand): one-shot command, exit code from remote exit-status.
package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"wssh/internal/termval"
	"wssh/internal/transport"
)

const connectTimeout = 10 * time.Second

// Connect dials the target's WebSocket URL, performs the SSH handshake with
// the given signers and host key callback, and returns the established
// client. Both the WebSocket dial and the SSH handshake are bounded by a
// 10-second timeout. On SSH handshake failure the underlying connection is
// closed before returning the error.
func Connect(ctx context.Context, t *Target, signers []ssh.Signer, hostKeyCb ssh.HostKeyCallback) (*ssh.Client, error) {
	dialCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	netConn, err := transport.Dial(dialCtx, t.WebSocketURL())
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}
	cfg := &ssh.ClientConfig{
		User:            t.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: hostKeyCb,
		Timeout:         connectTimeout,
	}
	conn, chans, reqs, err := ssh.NewClientConn(netConn, t.SSHAddr(), cfg)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("ssh connect: %w", err)
	}
	return ssh.NewClient(conn, chans, reqs), nil
}

// ExitError reports the remote command's exit status.
type ExitError struct {
	// Code is the exit status reported by the remote SSH server.
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

// ExitCode maps a session error to a process exit code: 0 for nil, the
// remote exit status for an *ExitError (directly or wrapped), and 255 for
// any other failure.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return 255
}

func mapWaitError(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		return &ExitError{Code: exitErr.ExitStatus()}
	}
	return err
}

// RunCommand runs command on the remote host in exec mode — no PTY, no raw
// terminal — writing output to stdout and stderr, and returns an *ExitError
// carrying the remote exit status.
func RunCommand(c *ssh.Client, command string, stdout, stderr io.Writer) error {
	sess, err := c.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdout = stdout
	sess.Stderr = stderr
	return mapWaitError(sess.Run(command))
}

// RunShell starts an interactive remote shell: it puts the local terminal
// into raw mode, requests a PTY sized to the current window, forwards
// stdin/stdout/stderr, and resizes the remote PTY on SIGWINCH. SIGINT and
// SIGTERM restore the terminal, close the session, and exit the process
// with code 130. Stdin must be a terminal, or an error is returned.
func RunShell(c *ssh.Client) error {
	sess, err := c.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return errors.New("stdin is not a terminal; pass a command for exec mode")
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("raw mode: %w", err)
	}
	restore := func() { _ = term.Restore(fd, oldState) }
	defer restore()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)
	done := make(chan struct{})
	defer close(done)
	defer signal.Stop(sigCh)
	go func() {
		for {
			select {
			case <-done:
				return
			case sig := <-sigCh:
				switch sig {
				case syscall.SIGWINCH:
					w, h, err := term.GetSize(fd)
					if err == nil {
						_ = sess.WindowChange(h, w)
					}
				default:
					restore()
					_ = sess.Close()
					os.Exit(130)
				}
			}
		}
	}()

	w, h, err := term.GetSize(fd)
	if err != nil {
		w, h = 80, 24
	}
	termEnv := os.Getenv("TERM")
	if !termval.Valid(termEnv) {
		termEnv = "xterm-256color"
	}
	if err := sess.RequestPty(termEnv, h, w, nil); err != nil {
		return fmt.Errorf("pty request: %w", err)
	}
	sess.Stdin = os.Stdin
	sess.Stdout = os.Stdout
	sess.Stderr = os.Stderr
	if err := sess.Shell(); err != nil {
		return fmt.Errorf("shell request: %w", err)
	}
	return mapWaitError(sess.Wait())
}
