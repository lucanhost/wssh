# wssh

SSH-over-WebSocket daemon and client in pure Go.

## Limitations

- Per-IP HTTP-level rate limiting on WebSocket upgrade requests keys on `RemoteAddr`.
  If wsshd is fronted by a TLS-terminating proxy (e.g. nginx, Cloudflare), all
  clients share the proxy's IP and rate limiting is ineffective — enforce limits
  at the proxy layer instead.
- No SSH port forwarding, X11 forwarding, agent forwarding, SCP, or SFTP
  subsystems (out of scope).
- Public-key authentication only; password and keyboard-interactive auth are
  deliberately unsupported.
- WebSocket message read limit is 1 MiB per frame; larger SSH packets cause the connection to close.
