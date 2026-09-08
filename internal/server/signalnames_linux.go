//go:build linux

package server

import "syscall"

// SIGPWR is not defined on all platforms (e.g. darwin), so the entry is
// registered here to keep the package buildable everywhere while preserving
// the signal name on Linux.
func init() {
	signalNames[syscall.SIGPWR] = "PWR"
}
