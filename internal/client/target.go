package client

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Target struct {
	Scheme string
	User   string
	Host   string
	Port   int
	Path   string
}

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

func (t *Target) WebSocketURL() string {
	return fmt.Sprintf("%s://%s%s", t.Scheme, net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), t.Path)
}

func (t *Target) SSHAddr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}
