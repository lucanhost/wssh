package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"wssh/internal/server"
)

func main() {
	var (
		addr           = flag.String("addr", ":8080", "HTTP listen address")
		path           = flag.String("path", "/ws", "WebSocket endpoint path")
		hostKey        = flag.String("hostkey", "/etc/wssh/host_key", "SSH host key path (ed25519/RSA; auto-generated when missing)")
		cert           = flag.String("cert", "", "TLS certificate file (enables HTTPS/WSS)")
		key            = flag.String("key", "", "TLS private key file")
		rate           = flag.Float64("rate", 1, "upgrade requests per second per IP (burst 5); 0 disables")
		trustedProxies = flag.String("trusted-proxies", "", "comma-separated CIDRs/bare IPs trusted to send forwarding headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)")
	)
	flag.Parse()
	var proxyList []string
	for _, p := range strings.Split(*trustedProxies, ",") {
		if p = strings.TrimSpace(p); p != "" {
			proxyList = append(proxyList, p)
		}
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	if (*cert == "") != (*key == "") {
		logger.Error("-cert and -key must be given together")
		os.Exit(2)
	}
	wsPath := *path
	if !strings.HasPrefix(wsPath, "/") {
		wsPath = "/" + wsPath
	}

	signer, err := server.LoadOrGenerateHostKey(*hostKey)
	if err != nil {
		logger.Error("host key", "err", err)
		os.Exit(1)
	}
	srv := server.New(server.Config{
		Signer:         signer,
		Logger:         logger,
		Rate:           *rate,
		Burst:          5,
		TrustedProxies: proxyList,
	})
	defer srv.Close()

	mux := http.NewServeMux()
	mux.Handle(wsPath, srv.WebSocketHandler())
	hs := &http.Server{Addr: *addr, Handler: mux}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		logger.Error("listen", "err", err)
		os.Exit(1)
	}
	tlsMode := "plain"
	if *cert != "" {
		certPair, err := tls.LoadX509KeyPair(*cert, *key)
		if err != nil {
			logger.Error("tls", "err", err)
			os.Exit(1)
		}
		hs.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certPair}}
		ln = tls.NewListener(ln, hs.TLSConfig)
		tlsMode = "tls"
	}

	logger.Info("wsshd listening",
		"addr", *addr, "path", wsPath, "tls", tlsMode,
		"mode", map[bool]string{true: "root", false: "non-root"}[srv.Root()],
		"hostkey", *hostKey,
	)
	if len(proxyList) > 0 {
		logger.Info("trusting client IP from forwarding headers; trusted proxies: " + strings.Join(proxyList, ","))
	} else if *rate > 0 {
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
