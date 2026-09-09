//go:build windows

package client

import (
	"os"
	"os/signal"
)

func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt)
}

func isWinch(sig os.Signal) bool {
	return false
}
