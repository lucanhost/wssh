package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"

	"wssh/internal/termval"
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

var signalNames = map[syscall.Signal]string{
	syscall.SIGHUP:  "HUP",
	syscall.SIGINT:  "INT",
	syscall.SIGQUIT: "QUIT",
	syscall.SIGILL:  "ILL",
	syscall.SIGABRT: "ABRT",
	syscall.SIGFPE:  "FPE",
	syscall.SIGKILL: "KILL",
	syscall.SIGSEGV: "SEGV",
	syscall.SIGPIPE: "PIPE",
	syscall.SIGALRM: "ALRM",
	syscall.SIGTERM: "TERM",
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

func (s *Server) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, u *user.User, shell string) {
	var (
		cmd       *exec.Cmd
		ptyFile   *os.File
		stdinPipe *os.File
		term      string
		havePTY   bool
		winSize   pty.Winsize
		mu        sync.Mutex
	)
	defer func() {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		mu.Lock()
		if ptyFile != nil {
			_ = ptyFile.Close()
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
			winSize = pty.Winsize{Rows: r, Cols: c}
			mu.Lock()
			if ptyFile != nil {
				_ = pty.Setsize(ptyFile, &winSize)
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
			winSize = pty.Winsize{Rows: r, Cols: c}
			mu.Lock()
			if ptyFile != nil {
				_ = pty.Setsize(ptyFile, &winSize)
			}
			mu.Unlock()
			req.Reply(true, nil)

		case "shell", "exec":
			if cmd != nil {
				req.Reply(false, nil)
				continue
			}
			var shellArgs []string
			kind := req.Type
			if req.Type == "exec" {
				var p execRequest
				if err := ssh.Unmarshal(req.Payload, &p); err != nil {
					req.Reply(false, nil)
					continue
				}
				shellArgs = []string{"-c", p.Command}
			}
			var err error
			cmd, ptyFile, stdinPipe, err = s.startProcess(u, shell, term, havePTY, winSize, shellArgs, channel)
			if err != nil {
				s.logger.Error("process start failed", "user", u.Username, "type", kind, "err", err)
				cmd = nil
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			s.logger.Info("session opened", "user", u.Username, "type", kind, "pty", havePTY)
			go s.reap(channel, cmd, ptyFile, stdinPipe, &mu, u)

		default:
			req.Reply(false, nil)
		}
	}
}

func (s *Server) startProcess(u *user.User, shell string, term string, havePTY bool, winSize pty.Winsize, shellArgs []string, channel ssh.Channel) (*exec.Cmd, *os.File, *os.File, error) {
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
	if havePTY && term != "" {
		cmd.Env = append(cmd.Env, "TERM="+term)
	}
	attrs := &syscall.SysProcAttr{}
	cred, err := credentialsFor(u)
	if err != nil {
		return nil, nil, nil, err
	}
	if cred != nil {
		attrs.Credential = cred
	}
	if havePTY {
		attrs.Setsid = true
		attrs.Setctty = true
		f, err := pty.StartWithAttrs(cmd, &winSize, attrs)
		if err != nil {
			return nil, nil, nil, err
		}
		return cmd, f, nil, nil
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

var ErrMalformedCredential = errors.New("malformed uid or gid in user record")

func credentialsFor(u *user.User) (*syscall.Credential, error) {
	if os.Geteuid() != 0 {
		return nil, nil
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, ErrMalformedCredential
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, ErrMalformedCredential
	}
	groups := []uint32{}
	if gidStrings, err := u.GroupIds(); err == nil {
		for _, gs := range gidStrings {
			g, err := strconv.ParseUint(gs, 10, 32)
			if err != nil {
				continue
			}
			groups = append(groups, uint32(g))
		}
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}, nil
}

func (s *Server) reap(channel ssh.Channel, cmd *exec.Cmd, ptyFile *os.File, stdinPipe *os.File, mu *sync.Mutex, u *user.User) {
	var copyWG sync.WaitGroup
	if ptyFile != nil {
		copyWG.Add(1)
		go func() {
			defer copyWG.Done()
			io.Copy(channel, ptyFile)
		}()
		go io.Copy(ptyFile, channel)
	}
	err := cmd.Wait()
	if ptyFile != nil {
		if mu != nil {
			mu.Lock()
			_ = ptyFile.Close()
			mu.Unlock()
		} else {
			_ = ptyFile.Close()
		}
	}
	if stdinPipe != nil {
		_ = stdinPipe.Close()
	}
	copyWG.Wait()
	status := uint32(0)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if waitStatus, ok := exitErr.Sys().(syscall.WaitStatus); ok && waitStatus.Signaled() {
				name, ok := signalNames[waitStatus.Signal()]
				if !ok {
					name = fmt.Sprintf("%d", int(waitStatus.Signal()))
				}
				channel.SendRequest("exit-signal", false, ssh.Marshal(exitSignalRequest{
					SignalName:  name,
					CoreDumped:  waitStatus.CoreDump(),
					LanguageTag: "en",
				}))
				_ = channel.Close()
				s.logger.Info("session closed", "user", u.Username, "signal", name)
				return
			}
			if code := exitErr.ExitCode(); code >= 0 {
				status = uint32(code)
			} else {
				status = 255
			}
		} else {
			status = 255
			s.logger.Error("child wait error", "err", err)
		}
	}
	channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusRequest{Status: status}))
	_ = channel.Close()
	s.logger.Info("session closed", "user", u.Username, "status", status)
}
