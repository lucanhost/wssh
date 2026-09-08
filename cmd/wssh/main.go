// Command wssh is an SSH-over-WebSocket client.
//
// It connects to a wsshd server via WebSocket and provides either an
// interactive shell or one-shot command execution.
//
// # Usage
//
//	wssh [flags] [ws://|wss://]user@host[:port][/path] [command...]
//
// If command is present, runs in exec mode (one-shot). Otherwise, opens an
// interactive shell with raw terminal mode and SIGWINCH resize support.
//
// # Host Key Verification
//
// By default, wssh verifies host keys against ~/.ssh/known_hosts and fails
// closed on changed keys (MITM detection). Use --accept-new-host-key to
// trust unknown hosts on first use.
//
// # Example
//
//	wssh user@example.com
//	wssh user@example.com -- ls -la
//	wssh wss://user@example.com:443/ws -- ping -c3 8.8.8.8
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lucanhost/wssh/internal/client"
)

// version is stamped at build time via -ldflags="-X main.version=..."
var version = "dev"

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wssh: %v\n", err)
		os.Exit(2)
	}
	var keys multiFlag
	flag.Var(&keys, "i", "private key path (repeatable)")
	knownHosts := flag.String("known-hosts", filepath.Join(home, ".ssh", "known_hosts"), "known hosts file")
	acceptNew := flag.Bool("accept-new-host-key", false, "automatically accept unknown host keys (TOFU)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: wssh [flags] [ws://|wss://]user@host[:port][/path] [command...]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Printf("wssh %s\n", version)
		os.Exit(0)
	}

	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}
	target, err := client.ParseTarget(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "wssh: %v\n", err)
		os.Exit(2)
	}
	if note := client.PlaintextNote(target); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
	command := strings.Join(args[1:], " ")

	signers, err := client.LoadSigners(keys, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wssh: %v\n", err)
		os.Exit(2)
	}
	hostKeyCb := client.HostKeyCallback(client.HostKeyOptions{
		KnownHostsPath: *knownHosts,
		AcceptNew:      *acceptNew,
	})

	sshClient, err := client.Connect(context.Background(), target, signers, hostKeyCb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wssh: %v\n", err)
		os.Exit(255)
	}
	defer sshClient.Close()

	if command != "" {
		err = client.RunCommand(sshClient, command, os.Stdout, os.Stderr)
	} else {
		err = client.RunShell(sshClient)
	}
	os.Exit(client.ExitCode(err))
}
