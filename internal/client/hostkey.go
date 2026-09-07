package client

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

type HostKeyOptions struct {
	KnownHostsPath string
	AcceptNew      bool
	In             io.Reader
	Out            io.Writer
}

func HostKeyCallback(opts HostKeyOptions) ssh.HostKeyCallback {
	var base ssh.HostKeyCallback
	var baseErr error
	if _, err := os.Stat(opts.KnownHostsPath); err == nil {
		kh, err := knownhosts.New(opts.KnownHostsPath)
		if err != nil {
			baseErr = fmt.Errorf("wssh: cannot parse %s: %w", opts.KnownHostsPath, err)
		} else {
			base = kh
		}
	}
	in, out := opts.In, opts.Out
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stderr
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		reader := bufio.NewReader(in)
		if baseErr != nil {
			return baseErr
		}
		if base != nil {
			err := base(hostname, tcpAddr(hostname), key)
			if err == nil {
				return nil
			}
			var keyErr *knownhosts.KeyError
			if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
			} else {
				if errors.As(err, &keyErr) {
					return fmt.Errorf("wssh: host key for %s does not match the known_hosts entry (possible MITM); connection refused", hostname)
				}
				return fmt.Errorf("wssh: host key check failed: %w", err)
			}
		}
		if opts.AcceptNew {
			return appendKnownHost(opts.KnownHostsPath, hostname, key)
		}
		fmt.Fprintf(out, "The authenticity of host '%s' can't be established.\n", hostname)
		fmt.Fprintf(out, "%s key fingerprint is %s.\n", key.Type(), ssh.FingerprintSHA256(key))
		fmt.Fprintf(out, "Are you sure you want to continue connecting (yes/no)? ")
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return errors.New("wssh: host key verification aborted")
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		if answer != "yes" && answer != "y" {
			return errors.New("wssh: host key verification failed: user declined")
		}
		return appendKnownHost(opts.KnownHostsPath, hostname, key)
	}
}

type tcpAddr string

func (a tcpAddr) Network() string { return "tcp" }
func (a tcpAddr) String() string  { return string(a) }

func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("wssh: refusing to append to symlink %s", path)
	}
	entry := fmt.Sprintf("%s %s\n", hostname, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("wssh: cannot append to %s: %w", path, err)
	}
	defer f.Close()
	_, err = f.WriteString(entry)
	return err
}
