//go:build !windows

package server

import (
	"fmt"
	"os/exec"
	"syscall"
)

// exitInfo describes how a child process terminated.
type exitInfo struct {
	status     uint32
	signaled   bool
	signalName string
	coreDumped bool
}

var signalNames = map[syscall.Signal]string{
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
	syscall.SIGSYS:    "SYS",
}

// parseExitStatus maps a Wait error to an exitInfo. Signaled processes
// report signaled=true; otherwise the exit code is returned. Unknown
// failures default to status 1, never 255.
func parseExitStatus(err error) exitInfo {
	if err == nil {
		return exitInfo{status: 0}
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if waitStatus, ok := exitErr.Sys().(syscall.WaitStatus); ok && waitStatus.Signaled() {
			name, ok := signalNames[waitStatus.Signal()]
			if !ok {
				name = fmt.Sprintf("%d", int(waitStatus.Signal()))
			}
			return exitInfo{
				signaled:   true,
				signalName: name,
				coreDumped: waitStatus.CoreDump(),
			}
		}
		if code := exitErr.ExitCode(); code >= 0 {
			return exitInfo{status: uint32(code)}
		}
	}
	return exitInfo{status: 1}
}
