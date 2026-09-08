// Package server implements an SSH-over-WebSocket daemon.
//
// It accepts WebSocket upgrades, wraps them into net.Conn, and runs a full
// SSH server (golang.org/x/crypto/ssh) over the WebSocket binary stream.
//
// # Authentication
//
// Public-key authentication only. The PublicKeyCallback reads
// ~/.ssh/authorized_keys for the target OS user and matches against the
// presented key.
//
// # Sessions
//
// Each authenticated connection can open multiple session channels. Each
// channel supports pty-req, window-change, shell, and exec requests.
// PTY sessions spawn with Setsid+Setctty to create a controlling terminal.
//
// # Privilege Drop
//
// In root mode (geteuid() == 0), sessions drop privileges to the
// authenticated user's UID/GID via syscall.Credential before spawning the
// shell. Non-root mode can only serve the current user.
//
// # Graceful Shutdown
//
// Wait blocks until all active sessions close. WaitTimeout adds a deadline.
package server

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/lucanhost/wssh/internal/transport"
)

// Config configures a Server. Zero values for optional fields are replaced
// with defaults by New.
type Config struct {
	// Signer is the SSH host key signer; required.
	Signer ssh.Signer
	// Logger receives connection and session logs; nil discards all output.
	Logger *slog.Logger
	// Rate is the permitted WebSocket upgrade rate per client IP, in
	// requests per second; 0 disables rate limiting.
	Rate float64
	// Burst is the token-bucket burst size above Rate; 0 means 5.
	Burst int
	// AuthorizedKeysPath, when non-nil, overrides the location of a user's
	// authorized_keys file; the default is $HOME/.ssh/authorized_keys.
	AuthorizedKeysPath func(*user.User) string
	// MaxSessionsPerConn caps session channels per SSH connection; 0 means 10.
	MaxSessionsPerConn int
	// MaxChildren caps concurrently running child processes; 0 means 256.
	MaxChildren int
	// MaxHandshakes caps concurrent in-flight SSH handshakes; excess
	// upgrades receive HTTP 503; 0 means 64.
	MaxHandshakes int
	// TrustedProxies lists CIDRs (or bare IPs) whose forwarding headers are
	// trusted when extracting the real client IP; invalid entries are logged
	// and ignored. Empty means the client IP is always taken from RemoteAddr.
	TrustedProxies []string
}

// Server is an SSH-over-WebSocket daemon. It upgrades HTTP requests to
// WebSocket connections, runs the SSH server handshake over them, and serves
// session channels (shell/exec), dropping privileges to the authenticated
// user when running as root.
type Server struct {
	sshConfig          ssh.ServerConfig
	logger             *slog.Logger
	root               bool
	currentUsername    string
	authorizedKeysPath func(*user.User) string
	limiter            *transport.RateLimiter
	trustedProxies     []*net.IPNet
	wg                 sync.WaitGroup
	maxSessionsPerConn int
	childrenSem        chan struct{}
	handshakeSem       chan struct{}
}

// New creates a Server from cfg, applying defaults for omitted fields:
// Burst 5, MaxSessionsPerConn 10, MaxChildren 256, MaxHandshakes 64, and a
// logger that discards output. Root mode is enabled when the process runs
// with euid 0. TrustedProxies entries may be CIDRs or bare IPs (bare IPv4
// becomes /32, bare IPv6 becomes /128). A rate limiter is created only when
// cfg.Rate is greater than 0.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Burst == 0 {
		cfg.Burst = 5
	}
	if cfg.MaxSessionsPerConn == 0 {
		cfg.MaxSessionsPerConn = 10
	}
	if cfg.MaxChildren == 0 {
		cfg.MaxChildren = 256
	}
	if cfg.MaxHandshakes == 0 {
		cfg.MaxHandshakes = 64
	}
	s := &Server{
		logger:             cfg.Logger,
		root:               os.Geteuid() == 0,
		currentUsername:    currentUserFromOS(),
		authorizedKeysPath: cfg.AuthorizedKeysPath,
		maxSessionsPerConn: cfg.MaxSessionsPerConn,
		childrenSem:        make(chan struct{}, cfg.MaxChildren),
		handshakeSem:       make(chan struct{}, cfg.MaxHandshakes),
	}
	for _, entry := range cfg.TrustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			s.logger.Warn("ignoring invalid trusted proxy entry", "entry", entry, "err", err)
			continue
		}
		s.trustedProxies = append(s.trustedProxies, cidr)
	}
	if cfg.Rate > 0 {
		s.limiter = transport.NewRateLimiter(cfg.Rate, cfg.Burst, time.Minute)
	}
	s.sshConfig = ssh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
		ServerVersion:     "SSH-2.0-wssh",
		MaxAuthTries:      3,
	}
	s.sshConfig.AddHostKey(cfg.Signer)
	return s
}

func currentUserFromOS() string {
	u, err := user.Current()
	if err != nil {
		return os.Getenv("USER")
	}
	return u.Username
}

// handshakeTimeout bounds the time allowed for the SSH handshake (version
// exchange, key exchange, and authentication), mirroring OpenSSH's
// LoginGraceTime. It is a variable so tests can shorten it.
var handshakeTimeout = 60 * time.Second

// Root reports whether the server runs in root mode (euid 0), where it
// authenticates any OS user and drops privileges to the authenticated user
// before spawning processes.
func (s *Server) Root() bool { return s.root }

// WebSocketHandler returns an http.Handler that upgrades WebSocket requests
// and serves SSH over them. It rate-limits upgrades per client IP (HTTP 429
// when exceeded; the IP honors TrustedProxies), admits at most
// MaxHandshakes concurrent SSH handshakes (HTTP 503 beyond that), and serves
// each accepted connection in its own goroutine.
func (s *Server) WebSocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		if s.limiter != nil && !s.limiter.Allow(ip) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		select {
		case s.handshakeSem <- struct{}{}:
		default:
			http.Error(w, "too many concurrent handshakes", http.StatusServiceUnavailable)
			return
		}
		netConn, err := transport.Accept(w, r)
		if err != nil {
			<-s.handshakeSem
			s.logger.Warn("websocket upgrade failed", "remote", r.RemoteAddr, "err", err)
			return
		}
		s.wg.Add(1)
		go s.serveConn(netConn, r.RemoteAddr)
	})
}

func (s *Server) serveConn(netConn net.Conn, remoteAddr string) {
	defer s.wg.Done()
	defer netConn.Close()
	if err := netConn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		s.logger.Warn("ssh handshake deadline not set", "remote", remoteAddr, "err", err)
	}
	sconn, chans, reqs, err := ssh.NewServerConn(netConn, &s.sshConfig)
	<-s.handshakeSem
	if err != nil {
		s.logger.Warn("ssh handshake failed", "remote", remoteAddr, "err", err)
		return
	}
	_ = netConn.SetDeadline(time.Time{}) // handshake done; allow long-lived sessions
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	s.logger.Info("connection authenticated", "user", sconn.User(), "remote", remoteAddr)

	var sessionCount int
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		if sessionCount >= s.maxSessionsPerConn {
			_ = newChannel.Reject(ssh.ResourceShortage, "too many sessions")
			continue
		}
		sessionCount++
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			s.logger.Warn("channel accept failed", "err", err)
			sessionCount--
			continue
		}
		ext := sconn.Permissions.Extensions
		u := &user.User{
			Uid:      ext["uid"],
			Gid:      ext["gid"],
			Username: ext["user"],
			Name:     ext["user"],
			HomeDir:  ext["home"],
		}
		go s.handleSession(channel, channelRequests, u, ext["shell"])
	}
}

// Wait blocks until every connection accepted by the server has finished.
func (s *Server) Wait() {
	s.wg.Wait()
}

// WaitTimeout blocks until every connection has finished or the timeout
// expires, whichever comes first. A timeout of 0 or less waits indefinitely.
// It reports whether the drain completed.
func (s *Server) WaitTimeout(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	if timeout <= 0 {
		<-done
		return true
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		s.logger.Warn("shutdown drain timed out", "timeout", timeout)
		return false
	}
}

// Close releases server resources, stopping the rate limiter's background
// eviction goroutine if one was created.
func (s *Server) Close() {
	if s.limiter != nil {
		s.limiter.Close()
	}
}
