//go:build !windows

package main

import "syscall"

// sysProcAttr returns the process attributes for the daemonized child on
// Unix: a new session detached from the controlling terminal.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
