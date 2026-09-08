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

	"wssh/internal/transport"
)

type Config struct {
	Signer             ssh.Signer
	Logger             *slog.Logger
	Rate               float64
	Burst              int
	AuthorizedKeysPath func(*user.User) string
	MaxSessionsPerConn int
	MaxChildren        int
	MaxHandshakes      int
	TrustedProxies     []string
}

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

func (s *Server) Root() bool { return s.root }

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

func (s *Server) Wait() {
	s.wg.Wait()
}

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

func (s *Server) Close() {
	if s.limiter != nil {
		s.limiter.Close()
	}
}
