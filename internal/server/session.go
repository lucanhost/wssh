package server

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

type ptyRequest struct {
	Term    string
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
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
	syscall.SIGHUP:  "SIGHUP",
	syscall.SIGINT:  "SIGINT",
	syscall.SIGQUIT: "SIGQUIT",
	syscall.SIGILL:  "SIGILL",
	syscall.SIGABRT: "SIGABRT",
	syscall.SIGFPE:  "SIGFPE",
	syscall.SIGKILL: "SIGKILL",
	syscall.SIGSEGV: "SIGSEGV",
	syscall.SIGPIPE: "SIGPIPE",
	syscall.SIGALRM: "SIGALRM",
	syscall.SIGTERM: "SIGTERM",
}

func (s *Server) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, u *user.User, shell string) {
	var (
		cmd     *exec.Cmd
		ptyFile *os.File
		term    string
		havePTY bool
		winSize pty.Winsize
	)
	defer func() {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		if ptyFile != nil {
			_ = ptyFile.Close()
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
			havePTY = true
			winSize = pty.Winsize{Rows: uint16(p.Rows), Cols: uint16(p.Columns)}
			if ptyFile != nil {
				_ = pty.Setsize(ptyFile, &winSize)
			}
			req.Reply(true, nil)

		case "window-change":
			var p windowChangeRequest
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				req.Reply(false, nil)
				continue
			}
			winSize = pty.Winsize{Rows: uint16(p.Rows), Cols: uint16(p.Columns)}
			if ptyFile != nil {
				_ = pty.Setsize(ptyFile, &winSize)
			}
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
			cmd, ptyFile, err = s.startProcess(u, shell, term, havePTY, winSize, shellArgs, channel)
			if err != nil {
				s.logger.Error("process start failed", "user", u.Username, "type", kind, "err", err)
				cmd = nil
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			s.logger.Info("session opened", "user", u.Username, "type", kind, "pty", havePTY)
			go s.reap(channel, cmd, ptyFile, u)

		default:
			req.Reply(false, nil)
		}
	}
}

func (s *Server) startProcess(u *user.User, shell string, term string, havePTY bool, winSize pty.Winsize, shellArgs []string, channel ssh.Channel) (*exec.Cmd, *os.File, error) {
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
	if cred := credentialsFor(u); cred != nil {
		attrs.Credential = cred
	}
	if havePTY {
		if winSize.Rows == 0 && winSize.Cols == 0 {
			winSize = pty.Winsize{Rows: 24, Cols: 80}
		}
		f, err := pty.StartWithAttrs(cmd, &winSize, attrs)
		if err != nil {
			return nil, nil, err
		}
		return cmd, f, nil
	}
	cmd.Stdin = channel
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return cmd, nil, nil
}

func credentialsFor(u *user.User) *syscall.Credential {
	if os.Geteuid() != 0 {
		return nil
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil
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
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}
}

func (s *Server) reap(channel ssh.Channel, cmd *exec.Cmd, ptyFile *os.File, u *user.User) {
	if ptyFile != nil {
		go io.Copy(channel, ptyFile)
		go io.Copy(ptyFile, channel)
	}
	err := cmd.Wait()
	if ptyFile != nil {
		_ = ptyFile.Close()
	}
	status := uint32(0)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			if waitStatus, ok := exitErr.Sys().(syscall.WaitStatus); ok && waitStatus.Signaled() {
				name, ok := signalNames[waitStatus.Signal()]
				if !ok {
					name = fmt.Sprintf("SIG%d", int(waitStatus.Signal()))
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
