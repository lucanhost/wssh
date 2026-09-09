//go:build !windows

package client

import (
	"os"
	"os/signal"
	"syscall"
)

func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)
}

func isWinch(sig os.Signal) bool {
	return sig == syscall.SIGWINCH
}
