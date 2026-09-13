//go:build windows

package main

import "syscall"

// sysProcAttr is never called on Windows (daemonize stays in the
// foreground there) but must exist for the shared daemonize code to build.
func sysProcAttr() *syscall.SysProcAttr {
	return nil
}
