# wssh

SSH-over-WebSocket daemon and client in pure Go.

## Features

- Full SSH protocol (key exchange, auth, channels, PTY) tunneled over WebSocket
  binary frames — no protocol modification
- `wsshd`: daemon with public-key auth, root/non-root modes, privilege drop,
  PTY + exec sessions, per-IP rate limiting, reverse-proxy-aware client IP
  extraction
- `wssh`: CLI client with interactive shell (raw terminal, SIGWINCH resize) and
  one-shot exec mode
- TOML config file support with CLI-flag override precedence
- Host key verification: known_hosts, TOFU prompt, hard-fail on changed keys

## Installation

### From source

Requires Go 1.26+.

```bash
git clone https://github.com/lucanhost/wssh.git
cd wssh
make build
```

Binaries are placed in `bin/wsshd` and `bin/wssh`.

### Via `go install`

```bash
go install github.com/lucanhost/wssh/cmd/wsshd@latest
go install github.com/lucanhost/wssh/cmd/wssh@latest
```

Binaries are placed in `$GOPATH/bin` (or `$HOME/go/bin`).

### From release

Download pre-built binaries from the
[Releases](https://github.com/lucanhost/wssh/releases) page.

## Quick Start

```bash
# Start the server (plain ws://, auto-generates host key)
./bin/wsshd -addr :8080 -hostkey /etc/wssh/host_key

# Start with TLS
./bin/wsshd -addr :443 -cert cert.pem -key key.pem

# Connect (interactive shell)
wssh user@example.com

# One-shot exec
wssh user@example.com -- ls -la

# Explicit scheme/port/path
wssh wss://user@example.com:443/ws -- ping -c3 8.8.8.8
```

Exit codes: `0` success, remote exit status for exec, `130` Ctrl+C,
`255` connection failure, `2` usage/config error.

## Configuration (wsshd)

`wsshd` reads an optional TOML config file via `-config PATH`. Precedence:
explicit CLI flag > config file > built-in default. Omitting `-config` keeps
pure flag behavior. A missing or malformed file passed via `-config` is a fatal
startup error.

```toml
# /etc/wssh/wsshd.toml
#
# wsshd configuration file. Enable with:  wsshd -config /etc/wssh/wsshd.toml
# Precedence: explicit CLI flag > config file value > built-in default.
# A commented-out key uses its default. `rate = 0` disables rate limiting.

addr    = ":8080"                # HTTP listen address
path    = "/ws"                  # WebSocket endpoint path
hostkey = "/etc/wssh/host_key"   # SSH host key (auto-generated ed25519 if missing)

# TLS certificate + key. Provide BOTH or NEITHER. Present → serve wss://.
# cert  = "/etc/wssh/cert.pem"
# key   = "/etc/wssh/key.pem"

rate    = 1.0                    # upgrade requests/sec per IP (burst 5); 0 disables

# CIDRs/IPs trusted to send client-IP headers behind a reverse proxy / CDN.
# Empty → X-Forwarded-For / X-Real-IP / CF-Connecting-IP are ignored.
# trusted_proxies = ["10.0.0.0/8", "172.16.0.0/12"]
```

- `rate = 0` disables rate limiting (it is NOT treated as "unset").
- `cert` and `key` must be set together, whether via file or flags.
- When `-trusted-proxies` is set in the config file, an absent CLI flag does
  not clear it — to remove trusted proxies, edit the config file.

### wsshd flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | HTTP listen address |
| `-path` | `/ws` | WebSocket endpoint path |
| `-hostkey` | `/etc/wssh/host_key` | SSH host key path (auto-generated if missing) |
| `-cert` | (none) | TLS certificate file (enables wss://) |
| `-key` | (none) | TLS private key file |
| `-rate` | `1` | Upgrade requests/sec/IP (burst 5); `0` disables |
| `-trusted-proxies` | (none) | Comma-separated CIDRs trusted for forwarding headers |
| `-config` | (none) | TOML config file path |

### wssh flags

| Flag | Default | Description |
|------|---------|-------------|
| `-i` | `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` | Private key path (repeatable) |
| `--known-hosts` | `~/.ssh/known_hosts` | Known hosts file |
| `--accept-new-host-key` | `false` | Trust-on-first-use for unknown hosts |

## Security

- **Public-key authentication only** — no password or keyboard-interactive auth
- **StrictModes** — refuses auth if `~/.ssh`, `authorized_keys`, or the home
  directory are group/world-writable or owned by the wrong user
- **Privilege drop** — root-mode sessions drop to the authenticated user's
  UID/GID before spawning a shell
- **Handshake limits** — 60s deadline on SSH handshake (cleared post-auth);
  concurrent in-flight handshakes capped (HTTP 503 at capacity)
- **Rate limiting** — per-IP token bucket with idle eviction and bounded entry
  count; reverse-proxy-aware via `-trusted-proxies`
- **Host key verification** — known_hosts check, hard-fail on changed keys,
  TOFU interactive prompt; refuses to append through symlinks
- **Environment sanitization** — child processes receive only `HOME`, `USER`,
  `SHELL`, `PATH`, `TERM`
- **WebSocket origin policy** — cross-origin browser requests rejected by
  default; do NOT set `OriginPatterns: ["*"]` (enables cross-site WebSocket
  hijacking)

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
- WebSocket message read limit is 1 MiB per frame; larger SSH packets cause
  the connection to close.
- `trusted_proxies` precedence: an empty or absent `-trusted-proxies` flag never
  clears a list set in the TOML config file. The config overlay only applies
  values that are actually set, and an empty flag value parses to no list at
  all, so the file's list survives. To clear the list, remove the
  `trusted_proxies` key from the TOML file (or set it to `trusted_proxies = []`).
  A non-empty `-trusted-proxies CIDR1,CIDR2` overrides the file as usual.
- WebSocket origin policy: `wsshd` keeps the `coder/websocket` default, which
  rejects upgrades whose `Origin` header does not match the host (no
  `OriginPatterns` are configured). Do not add permissive origin patterns to
  the accept path — allowing all origins would re-introduce cross-site
  WebSocket hijacking.

## Building

```bash
make build        # CGO_ENABLED=0, -trimpath, stripped binaries → bin/
make test         # go test ./... -race
make ci           # vet + test + govulncheck
make clean        # rm -rf bin
```

## License

[MIT](LICENSE)
