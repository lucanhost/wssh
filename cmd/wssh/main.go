package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"wssh/internal/client"
)

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
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: wssh [flags] [ws://|wss://]user@host[:port][/path] [command...]\n")
		flag.PrintDefaults()
	}
	flag.Parse()

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
