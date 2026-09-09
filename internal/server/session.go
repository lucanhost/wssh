package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"

	pty "github.com/aymanbagabas/go-pty"
	"golang.org/x/crypto/ssh"

	"github.com/lucanhost/wssh/internal/termval"
)

type ptyRequest struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	Modelist string
}

type windowChangeRequest struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

type execRequest struct {
	Command string
}

type exitStatusRequest struct {
	Status uint32
}

type exitSignalRequest struct {
	SignalName   string
	CoreDumped   bool
	ErrorMessage string
	LanguageTag  string
}

func clampWinsize(rows, cols uint32) (uint16, uint16, bool) {
	if rows == 0 || cols == 0 {
		if rows == 0 {
			rows = 24
		}
		if cols == 0 {
			cols = 80
		}
		return uint16(rows), uint16(cols), true
	}
	if rows > 0xFFFF {
		rows = 0xFFFF
	}
	if cols > 0xFFFF {
		cols = 0xFFFF
	}
	return uint16(rows), uint16(cols), true
}

func resolveShellAndArgs(shell string, cmd string) (string, []string) {
	if shell == "" {
		if runtime.GOOS == "windows" {
			if _, err := exec.LookPath("pwsh.exe"); err == nil {
				shell = "pwsh.exe"
			} else if _, err := exec.LookPath("powershell.exe"); err == nil {
				shell = "powershell.exe"
			} else {
				shell = "cmd.exe"
			}
		} else {
			shell = "/bin/sh"
		}
	}
	if cmd == "" {
		return shell, nil
	}
	lower := strings.ToLower(shell)
	if strings.Contains(lower, "cmd.exe") || strings.HasSuffix(lower, "cmd") {
		return shell, []string{"/C", cmd}
	}
	if strings.Contains(lower, "powershell") || strings.Contains(lower, "pwsh") {
		return shell, []string{"-Command", cmd}
	}
	return shell, []string{"-c", cmd}
}

func (s *Server) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, u *user.User, shell string) {
	var (
		cmd       any
		pt        pty.Pty
		stdinPipe *os.File
		term      string
		havePTY   bool
		cols      uint16 = 80
		rows      uint16 = 24
		mu        sync.Mutex
		semHeld   bool
	)
	defer func() {
		switch c := cmd.(type) {
		case *pty.Cmd:
			if c != nil && c.Process != nil {
				_ = c.Process.Kill()
			}
		case *exec.Cmd:
			if c != nil && c.Process != nil {
				_ = c.Process.Kill()
			}
		}
		mu.Lock()
		if pt != nil {
			_ = pt.Close()
		}
		mu.Unlock()
		if stdinPipe != nil {
			_ = stdinPipe.Close()
		}
	}()

	for req := range requests {
		switch req.Type {
		case "pty-req":
			var p ptyRequest
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				req.Reply(false, nil)
				continue
			}
			term = p.Term
			if !termval.Valid(term) {
				term = "xterm-256color"
			}
			havePTY = true
			r, c, ok := clampWinsize(p.Rows, p.Columns)
			if !ok {
				req.Reply(false, nil)
				continue
			}
			rows, cols = r, c
			mu.Lock()
			if pt != nil {
				_ = pt.Resize(int(cols), int(rows))
			}
			mu.Unlock()
			req.Reply(true, nil)

		case "window-change":
			var p windowChangeRequest
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				req.Reply(false, nil)
				continue
			}
			r, c, ok := clampWinsize(p.Rows, p.Columns)
			if !ok {
				req.Reply(false, nil)
				continue
			}
			rows, cols = r, c
			mu.Lock()
			if pt != nil {
				_ = pt.Resize(int(cols), int(rows))
			}
			mu.Unlock()
			req.Reply(true, nil)

		case "shell", "exec":
			if cmd != nil {
				req.Reply(false, nil)
				continue
			}
			kind := req.Type
			var execCmd string
			if req.Type == "exec" {
				var p execRequest
				if err := ssh.Unmarshal(req.Payload, &p); err != nil {
					req.Reply(false, nil)
					continue
				}
				execCmd = p.Command
			}
			if s.childrenSem != nil {
				select {
				case s.childrenSem <- struct{}{}:
					semHeld = true
				default:
					s.logger.Warn("max children reached", "user", u.Username, "type", kind)
					req.Reply(false, nil)
					continue
				}
			}
			release := func() {
				if semHeld && s.childrenSem != nil {
					<-s.childrenSem
				}
			}
			shellPath, shellArgs := resolveShellAndArgs(shell, execCmd)
			var err error
			cmd, pt, stdinPipe, err = s.startProcess(u, shellPath, term, havePTY, cols, rows, shellArgs, channel)
			if err != nil {
				s.logger.Error("process start failed", "user", u.Username, "type", kind, "err", err)
				cmd = nil
				release()
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			s.logger.Info("session opened", "user", u.Username, "type", kind, "pty", havePTY)
			go s.reap(channel, cmd, pt, stdinPipe, &mu, u, release)

		default:
			req.Reply(false, nil)
		}
	}
}

func (s *Server) startProcess(u *user.User, shell string, term string, havePTY bool, cols, rows uint16, shellArgs []string, channel ssh.Channel) (any, pty.Pty, *os.File, error) {
	if havePTY {
		pt, err := pty.New()
		if err != nil {
			return nil, nil, nil, err
		}
		cmd := pt.Command(shell, shellArgs...)
		cmd.Dir = u.HomeDir
		cmd.Env = []string{
			"HOME=" + u.HomeDir,
			"USER=" + u.Username,
			"SHELL=" + shell,
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		}
		if term != "" {
			cmd.Env = append(cmd.Env, "TERM="+term)
		}
		if err := setupProcAttrs(cmd, u); err != nil {
			_ = pt.Close()
			return nil, nil, nil, err
		}
		_ = pt.Resize(int(cols), int(rows))
		if err := cmd.Start(); err != nil {
			_ = pt.Close()
			return nil, nil, nil, err
		}
		return cmd, pt, nil, nil
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	cmd := exec.Command(shell, shellArgs...)
	cmd.Dir = u.HomeDir
	cmd.Env = []string{
		"HOME=" + u.HomeDir,
		"USER=" + u.Username,
		"SHELL=" + shell,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if term != "" {
		// Non-PTY sessions have no terminal; still propagate TERM when set
		// for consistency with PTY sessions.
		cmd.Env = append(cmd.Env, "TERM="+term)
	}
	if err := setupExecProcAttrs(cmd, u); err != nil {
		return nil, nil, nil, err
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, nil, nil, err
	}
	cmd.Stdin = pr
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()
	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		return nil, nil, nil, err
	}
	pr.Close()
	go io.Copy(pw, channel)
	return cmd, nil, pw, nil
}

// ErrMalformedCredential is returned when the authenticated user's uid or
// gid cannot be parsed as unsigned 32-bit integers. The session fails
// closed — it is never started under the daemon's own credentials.
var ErrMalformedCredential = errors.New("malformed uid or gid in user record")

func (s *Server) reap(channel ssh.Channel, cmd any, pt pty.Pty, stdinPipe *os.File, mu *sync.Mutex, u *user.User, release func()) {
	defer release()
	var copyWG sync.WaitGroup
	if pt != nil {
		copyWG.Add(1)
		go func() {
			defer copyWG.Done()
			io.Copy(channel, pt)
		}()
		go io.Copy(pt, channel)
	}
	var err error
	switch c := cmd.(type) {
	case *pty.Cmd:
		err = c.Wait()
	case *exec.Cmd:
		err = c.Wait()
	default:
		err = fmt.Errorf("unknown command type %T", cmd)
	}
	if pt != nil {
		if mu != nil {
			mu.Lock()
			_ = pt.Close()
			mu.Unlock()
		} else {
			_ = pt.Close()
		}
	}
	if stdinPipe != nil {
		_ = stdinPipe.Close()
	}
	copyWG.Wait()
	info := parseExitStatus(err)
	if err != nil && info.signaled {
		channel.SendRequest("exit-signal", false, ssh.Marshal(exitSignalRequest{
			SignalName:  info.signalName,
			CoreDumped:  info.coreDumped,
			LanguageTag: "en",
		}))
		_ = channel.Close()
		s.logger.Info("session closed", "user", u.Username, "signal", info.signalName)
		return
	}
	if err != nil && !info.signaled {
		// Log non-zero exits at appropriate level: parseExitStatus
		// normalizes unknown failures to status 1.
		if _, ok := err.(*exec.ExitError); !ok {
			// Check for pty.Cmd-wrapped exit errors via string matching
			// is unnecessary; just log unexpected wait errors.
			s.logger.Error("child wait error", "err", err)
		}
	}
	channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{Status: info.status}))
	_ = channel.Close()
	s.logger.Info("session closed", "user", u.Username, "status", info.status)
}
