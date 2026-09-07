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

	"wssh/internal/transport"
)

const connectTimeout = 10 * time.Second

func Connect(ctx context.Context, t *Target, signers []ssh.Signer, hostKeyCb ssh.HostKeyCallback) (*ssh.Client, error) {
	netConn, err := transport.Dial(ctx, t.WebSocketURL())
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

type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

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
	defer signal.Stop(sigCh)
	go func() {
		for sig := range sigCh {
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
	}()

	w, h, err := term.GetSize(fd)
	if err != nil {
		w, h = 80, 24
	}
	termEnv := os.Getenv("TERM")
	if termEnv == "" {
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
