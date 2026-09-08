//go:build linux

package server

import (
	"syscall"
	"testing"
)

func TestSignalNamesSIGPWRLinux(t *testing.T) {
	if got := signalNames[syscall.SIGPWR]; got != "PWR" {
		t.Errorf("signalNames[%v] = %q, want %q", int(syscall.SIGPWR), got, "PWR")
	}
}
