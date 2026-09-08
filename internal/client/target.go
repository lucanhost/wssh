package client

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Target is a parsed connection target.
type Target struct {
	// Scheme is "ws" or "wss".
	Scheme string
	// User is the remote OS username used for SSH authentication.
	User string
	// Host is the hostname or IP address without brackets.
	Host string
	// Port is the TCP port; 80 for ws:// and 443 for wss:// by default.
	Port int
	// Path is the WebSocket endpoint path; defaults to /ws.
	Path string
}

// ParseTarget parses a connection target of the form
// [ws://|wss://]user@host[:port][/path]. A missing scheme defaults to
// ws://, the port defaults to 80 for ws:// and 443 for wss://, and a
// missing path defaults to /ws. The username is required; the scheme must
// be ws or wss; the port must be 1-65535. For example, "alice@server"
// yields ws://alice@server:80/ws and "wss://bob@srv:8443" yields
// wss://bob@srv:8443/ws.
func ParseTarget(s string) (*Target, error) {
	if !strings.Contains(s, "://") {
		s = "ws://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: %w", s, err)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, errors.New("target must include a user: [ws://|wss://]user@host[:port][/path]")
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "ws" && scheme != "wss" {
		return nil, fmt.Errorf("unsupported scheme %q (want ws or wss)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("target must include a host")
	}
	port := 80
	if scheme == "wss" {
		port = 443
	}
	if p := u.Port(); p != "" {
		port, err = strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
	}
	path := u.Path
	if path == "" {
		path = "/ws"
	}
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New("path must start with /")
	}
	return &Target{Scheme: scheme, User: u.User.Username(), Host: host, Port: port, Path: path}, nil
}

// WebSocketURL returns the full WebSocket URL to dial, for example
// wss://example.com:443/ws.
func (t *Target) WebSocketURL() string {
	return fmt.Sprintf("%s://%s%s", t.Scheme, net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), t.Path)
}

// SSHAddr returns the host:port address used by the SSH layer and for
// known_hosts matching.
func (t *Target) SSHAddr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}
