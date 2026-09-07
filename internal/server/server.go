package server

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
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
	ShutdownTimeout    time.Duration
}

type Server struct {
	sshConfig          ssh.ServerConfig
	logger             *slog.Logger
	root               bool
	currentUsername    string
	authorizedKeysPath func(*user.User) string
	limiter            *transport.RateLimiter
	wg                 sync.WaitGroup
	maxSessionsPerConn int
	childrenSem        chan struct{}
	shutdownTimeout    time.Duration
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
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
	s := &Server{
		logger:             cfg.Logger,
		root:               os.Geteuid() == 0,
		currentUsername:    currentUserFromOS(),
		authorizedKeysPath: cfg.AuthorizedKeysPath,
		maxSessionsPerConn: cfg.MaxSessionsPerConn,
		childrenSem:        make(chan struct{}, cfg.MaxChildren),
		shutdownTimeout:    cfg.ShutdownTimeout,
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

func (s *Server) Root() bool { return s.root }

func (s *Server) WebSocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if s.limiter != nil && !s.limiter.Allow(ip) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		netConn, err := transport.Accept(w, r)
		if err != nil {
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
	sconn, chans, reqs, err := ssh.NewServerConn(netConn, &s.sshConfig)
	if err != nil {
		s.logger.Warn("ssh handshake failed", "remote", remoteAddr, "err", err)
		return
	}
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
	if timeout <= 0 {
		timeout = s.shutdownTimeout
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
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
