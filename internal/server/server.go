package server

import (
	"io"
	"log/slog"
	"os"
	"os/user"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"wssh/internal/transport"
)

type Config struct {
	Signer  ssh.Signer
	Logger  *slog.Logger
	Rate    float64
	Burst   int
	AuthorizedKeysPath func(*user.User) string
}

type Server struct {
	sshConfig          ssh.ServerConfig
	logger             *slog.Logger
	root               bool
	currentUsername    string
	authorizedKeysPath func(*user.User) string
	limiter            *transport.RateLimiter
	wg                 sync.WaitGroup
}

func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Burst == 0 {
		cfg.Burst = 5
	}
	s := &Server{
		logger:             cfg.Logger,
		root:               os.Geteuid() == 0,
		currentUsername:    currentUser(),
		authorizedKeysPath: cfg.AuthorizedKeysPath,
	}
	if cfg.Rate > 0 {
		s.limiter = transport.NewRateLimiter(cfg.Rate, cfg.Burst, time.Minute)
	}
	s.sshConfig = ssh.ServerConfig{
		PublicKeyCallback: s.publicKeyCallback,
		ServerVersion:     "SSH-2.0-wssh",
		MaxAuthTries:      6,
	}
	s.sshConfig.AddHostKey(cfg.Signer)
	return s
}

func currentUser() string {
	u, err := user.Current()
	if err != nil {
		return os.Getenv("USER")
	}
	return u.Username
}

func (s *Server) Root() bool { return s.root }
