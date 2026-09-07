# wssh

SSH-over-WebSocket daemon and client in pure Go.

## Limitations

- Per-IP HTTP-level rate limiting on WebSocket upgrade requests keys on the real
  client IP when the direct peer is in `-trusted-proxies` (forwarding headers:
  `CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`); otherwise it keys on
  `RemoteAddr`. If wsshd is fronted by a proxy that is not listed, all clients
  share the proxy's IP — add the proxy's CIDRs to `-trusted-proxies` or enforce
  limits at the proxy layer.
- No SSH port forwarding, X11 forwarding, agent forwarding, SCP, or SFTP
  subsystems (out of scope).
- Public-key authentication only; password and keyboard-interactive auth are
  deliberately unsupported.
- WebSocket message read limit is 1 MiB per frame; larger SSH packets cause the connection to close.

## Configuration (wsshd)

`wsshd` reads an optional TOML config file via `-config PATH`. Precedence:
explicit CLI flag > config file > built-in default. Omitting `-config` keeps
pure flag behavior. A missing or malformed file passed via `-config` is a fatal
startup error.

\`\`\`toml
# /etc/wssh/wsshd.toml
addr    = ":8080"
path    = "/ws"
hostkey = "/etc/wssh/host_key"
# cert  = "/etc/wssh/cert.pem"
# key   = "/etc/wssh/key.pem"
rate    = 1.0
# trusted_proxies = ["10.0.0.0/8"]
\`\`\`

- `rate = 0` disables rate limiting (it is NOT treated as "unset").
- `cert` and `key` must be set together, whether via file or flags.

