// Command wsshd is an SSH-over-WebSocket daemon.
//
// It serves a complete SSH server (golang.org/x/crypto/ssh) over WebSocket
// binary frames, allowing SSH clients to connect through firewalls that block
// port 22 but allow HTTP/HTTPS (80/443).
//
// # Authentication
//
// wsshd supports public-key authentication only. It reads authorized keys from
// ~/.ssh/authorized_keys for the target OS user.
//
// # Privilege Model
//
//   - Root mode (geteuid() == 0): accepts connections for any OS user and
//     drops privileges to that user before spawning a shell.
//   - Non-root mode: accepts connections only for the current OS user.
//
// # Configuration
//
// Configuration is via CLI flags or an optional TOML config file (-config).
// Precedence: explicit CLI flag > config file > built-in default.
//
// # Example
//
//	wsshd -addr :8080 -hostkey /etc/wssh/host_key
//	wsshd -addr :443 -cert cert.pem -key key.pem
//	wsshd -config /etc/wssh/wsshd.toml
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/lucanhost/wssh/internal/config"
	"github.com/lucanhost/wssh/internal/server"
)

// version is stamped at build time via -ldflags="-X main.version=..."
var version = "dev"

// daemonEnv is set to "1" in the child process spawned by daemonize so the
// child skips re-daemonizing.
const daemonEnv = "_WSSHD_DAEMON"

// daemonize re-executes the current binary as a detached background process
// and exits the parent, unless the process is already the daemonized child
// (daemonEnv set) or is on Windows, where session detachment is unsupported
// and wsshd stays in the foreground.
//
// The child inherits the working directory (relative -config/-hostkey paths
// keep resolving) and receives the parent's arguments plus -D, with stdin,
// stdout, and stderr redirected to /dev/null.
func daemonize() {
	if os.Getenv(daemonEnv) == "1" {
		return
	}
	if runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "wsshd: background daemonization is not supported on Windows; running in the foreground")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wsshd: daemonize: resolve executable: %v\n", err)
		os.Exit(1)
	}
	args := make([]string, 0, len(os.Args)+1)
	args = append(args, os.Args...)
	args = append(args, "-D")
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wsshd: daemonize: open %s: %v\n", os.DevNull, err)
		os.Exit(1)
	}
	env := append(os.Environ(), daemonEnv+"=1")
	proc, err := os.StartProcess(exe, args, &os.ProcAttr{
		Env:   env,
		Files: []*os.File{devnull, devnull, devnull},
		Sys:   sysProcAttr(),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "wsshd: daemonize: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wsshd daemonized with PID %d\n", proc.Pid)
	_ = proc.Release()
	os.Exit(0)
}

// tcpKeepAliveListener wraps a TCP listener to enable TCP keepalive and
// disable Nagle's algorithm on accepted connections; without TCP_NODELAY
// every interactive SSH keystroke can incur a ~40ms Nagle buffering delay.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return nil, err
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	tc.SetNoDelay(true)
	return tc, nil
}

func main() {
	defaultHostKey := "/etc/wssh/host_key"
	if runtime.GOOS == "windows" {
		if cfgDir, err := os.UserConfigDir(); err == nil {
			defaultHostKey = filepath.Join(cfgDir, "wssh", "host_key")
		}
	}
	var (
		addr           = flag.String("addr", ":8080", "HTTP listen address")
		path           = flag.String("path", "/ws", "WebSocket endpoint path")
		hostKey        = flag.String("hostkey", defaultHostKey, "SSH host key path (ed25519/RSA; auto-generated when missing)")
		cert           = flag.String("cert", "", "TLS certificate file (enables HTTPS/WSS)")
		key            = flag.String("key", "", "TLS private key file")
		rate           = flag.Float64("rate", 1, "upgrade requests per second per IP (burst 5); 0 disables")
		trustedProxies = flag.String("trusted-proxies", "", "comma-separated CIDRs/bare IPs trusted to send forwarding headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)")
		foreground     = flag.Bool("D", false, "run in foreground (do not daemonize)")
		configPath     = flag.String("config", "", "TOML config file path")
		showVersion    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Printf("wsshd %s\n", version)
		os.Exit(0)
	}
	if !*foreground {
		daemonize()
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var fileOverlay *config.Overlay
	if *configPath != "" {
		var err error
		fileOverlay, err = config.Load(*configPath)
		if err != nil {
			logger.Error("config", "path", *configPath, "err", err)
			os.Exit(1)
		}
	}

	cliOverlay := &config.Overlay{}
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "addr":
			cliOverlay.Addr = addr
		case "path":
			cliOverlay.Path = path
		case "hostkey":
			cliOverlay.HostKey = hostKey
		case "cert":
			cliOverlay.Cert = cert
		case "key":
			cliOverlay.Key = key
		case "rate":
			r := *rate
			cliOverlay.Rate = &r
		case "trusted-proxies":
			cliOverlay.TrustedProxies = splitList(*trustedProxies)
		}
	})

	resolved := config.Merge(config.Defaults(), fileOverlay, cliOverlay)
	if err := resolved.Validate(); err != nil {
		logger.Error(err.Error())
		os.Exit(2)
	}

	wsPath := resolved.Path
	if !strings.HasPrefix(wsPath, "/") {
		wsPath = "/" + wsPath
	}

	signer, err := server.LoadOrGenerateHostKey(resolved.HostKey)
	if err != nil {
		logger.Error("host key", "err", err)
		os.Exit(1)
	}
	srv := server.New(server.Config{
		Signer:         signer,
		Logger:         logger,
		Rate:           resolved.Rate,
		Burst:          5,
		TrustedProxies: resolved.TrustedProxies,
	})
	defer srv.Close()

	mux := http.NewServeMux()
	mux.Handle(wsPath, srv.WebSocketHandler())
	hs := &http.Server{
		Addr:              resolved.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ln, err := net.Listen("tcp", resolved.Addr)
	if err != nil {
		logger.Error("listen", "err", err)
		os.Exit(1)
	}
	if tcpLn, ok := ln.(*net.TCPListener); ok {
		ln = tcpKeepAliveListener{tcpLn}
	}
	tlsMode := "plain"
	if resolved.Cert != "" {
		certPair, err := tls.LoadX509KeyPair(resolved.Cert, resolved.Key)
		if err != nil {
			logger.Error("tls", "err", err)
			os.Exit(1)
		}
		hs.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certPair}}
		ln = tls.NewListener(ln, hs.TLSConfig)
		tlsMode = "tls"
	}

	logger.Info("wsshd listening",
		"addr", resolved.Addr, "path", wsPath, "tls", tlsMode,
		"mode", map[bool]string{true: "root", false: "non-root"}[srv.Root()],
		"hostkey", resolved.HostKey,
	)
	if *configPath != "" {
		logger.Info("using config file", "path", *configPath)
	}
	if len(resolved.TrustedProxies) > 0 {
		logger.Info("trusting client IP from forwarding headers; trusted proxies: " + strings.Join(resolved.TrustedProxies, ","))
	} else if resolved.Rate > 0 {
		logger.Info("rate limiting keys on RemoteAddr; if fronted by a TLS proxy, enforce rate limits at the proxy")
	}

	errCh := make(chan error, 1)
	go func() { errCh <- hs.Serve(ln) }()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		logger.Error("serve", "err", err)
		os.Exit(1)
	case <-sigCh:
	}
	logger.Info("shutting down; draining active sessions")
	_ = hs.Shutdown(context.Background())
	const shutdownTimeout = 30 * time.Second
	srv.WaitTimeout(shutdownTimeout)
	logger.Info("wsshd stopped")
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
