//go:build windows

package server

import (
	"os/exec"
)

// exitInfo describes how a child process terminated.
type exitInfo struct {
	status     uint32
	signaled   bool
	signalName string
	coreDumped bool
}

// parseExitStatus maps a Wait error to an exitInfo on Windows. The exit
// code is returned when non-negative; otherwise status 1 is used.
func parseExitStatus(err error) exitInfo {
	if err == nil {
		return exitInfo{status: 0}
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if code := exitErr.ExitCode(); code >= 0 {
			return exitInfo{status: uint32(code)}
		}
	}
	return exitInfo{status: 1}
}
