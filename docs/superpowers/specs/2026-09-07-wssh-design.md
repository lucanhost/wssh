# wssh — SSH over WebSocket: Design

Date: 2026-09-07
Status: Approved (design walkthrough complete)

## Overview

wssh is a pure Go project that tunnels a full SSH protocol implementation over
WebSocket connections. It produces two binaries:

- **`wsshd`** — daemon: HTTP(S) server that upgrades requests at a configurable
  path to WebSocket and serves a complete SSH server (`golang.org/x/crypto/ssh`)
  over the WebSocket binary stream.
- **`wssh`** — CLI client: dials a WebSocket URL, establishes an SSH connection
  over it, and bridges the local terminal (interactive shell) or runs a one-shot
  command (`exec`).

Core trick: `x/crypto/ssh` operates on `net.Conn`; `github.com/coder/websocket`
provides `websocket.NetConn()` which wraps a WebSocket into a `net.Conn`. The
entire SSH protocol — key exchange, auth, channels, PTY — runs transparently
over WebSocket binary frames with no modification to the SSH library.

## Requirements Summary

- Binary WebSocket frames only (`websocket.MessageBinary`) — text frames would
  corrupt the SSH handshake.
- WebSocket ping/pong keepalives to survive idle-killing proxies/firewalls.
- Public key auth only. No password auth, ever.
- Root mode (any OS user + privilege drop) / non-root mode (current user only).
- PTY allocation, `window-change`, `shell`, `exec` SSH requests.
- Zombie process cleanup on disconnect.
- Per-IP HTTP-level rate limiting on WebSocket upgrade requests.
- Structured logging via `log/slog`.
- Go 1.21+.

## Architecture

```
wssh/
  cmd/wsshd/main.go        — flag parsing, wiring, logging setup
  cmd/wssh/main.go         — flag parsing, wiring, exit codes
  internal/transport/      — WebSocket accept/dial → net.Conn; rate limiting
  internal/server/         — SSH server config, auth, session loop, PTY,
                             privilege drop, zombie cleanup
  internal/client/         — SSH client, host key verification, raw mode,
                             SIGWINCH, shell/exec modes
```

Thin command entrypoints; all logic in `internal/` packages so each unit is
testable in isolation.

## Binaries & Flags

### wsshd

| Flag      | Default            | Meaning                                          |
|-----------|--------------------|--------------------------------------------------|
| `-addr`   | `:8080`            | HTTP listen address                              |
| `-path`   | `/ws`              | WebSocket endpoint path                          |
| `-hostkey`| `/etc/wssh/host_key` | Host key file (ed25519 or RSA)                 |
| `-cert`   | (none)             | TLS certificate; enables HTTPS/WSS              |
| `-key`    | (none)             | TLS private key                                  |
| `-rate`   | `1`                | Upgrade requests/sec/IP (burst 5). `0` disables  |

- `-cert` and `-key` must be given together; present → serve TLS.
- Host key file missing → auto-generate ed25519, save with mode `0600`, log
  warning, continue. Unparseable existing file → fatal error.
- Root mode is implicit: `os.Geteuid() == 0` → accept any OS user with valid
  keys + privilege drop; otherwise accept only the current OS user. Mode is
  logged at startup.

### wssh

```
wssh [flags] [ws://|wss://]user@host[:port][/path] [command...]
```

| Flag                        | Meaning                                   |
|-----------------------------|-------------------------------------------|
| `-i`                        | Private key path (repeatable)             |
| `--known-hosts`             | Known hosts file (default `~/.ssh/known_hosts`) |
| `--accept-new-host-key`     | Trust-on-first-use for unknown host keys  |

Target parsing rules:

1. No `://` prefix → prepend `ws://` (plaintext default; SSH protocol still
   applies its own crypto — `wss://` recommended behind TLS proxies).
2. `net/url.Parse`: username from userinfo (**required** — error if absent),
   host/port from `u.Host`.
3. Port default: `ws://` → 80, `wss://` → 443. Specified inline
   (`user@host:2222`); there is no separate `--port` flag.
4. Path: empty → `/ws`; explicit path (`user@host/ws/custom`) honored as-is.

Examples:

- `wssh alice@server` → `ws://alice@server:80/ws`
- `wssh wss://bob@srv:8443` → `wss://bob@srv:8443/ws`
- `wssh -i ~/.ssh/deploy carol@box:8080 -- ls -la` → exec `ls -la` over
  `ws://carol@box:8080/ws`

Trailing arguments after the target (following `--` or the first non-flag
token) form the exec command; present → exec mode, absent → interactive shell.

## Transport Layer (`internal/transport`)

```go
func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error)
func Dial(ctx context.Context, rawURL string) (net.Conn, error)
```

- `websocket.Accept` / `websocket.Dial` with:
  - `CompressionMode: websocket.CompressionDisabled` — SSH carries its own
    encryption; compression adds overhead and side-channel surface.
  - `KeepAlivePingOptions` — library-managed ping/pong (15s interval), no
    hand-rolled keepalive goroutines.
- `websocket.NetConn()` uses binary data messages by design; transport tests
  assert binary opcodes explicitly to guard regressions.
- Closing the returned `net.Conn` closes the underlying WebSocket cleanly.
- Per-IP rate limiting on the server side: `x/time/rate.Limiter` per client IP
  (from `http.Request.RemoteAddr`, IP portion only), stored in a map guarded by
  `sync.RWMutex`. Exceeding the limit → HTTP 429 before any WebSocket upgrade.
  Default 1 req/s, burst 5; `-rate 0` disables.

## SSH Server (`internal/server`)

### Connection lifecycle

Rate-limited WebSocket upgrade → `transport.Accept` → `ssh.NewServerConn` →
per-connection goroutine serves channels → each accepted `session` channel gets
its own goroutine. Multiple sessions per SSH connection are allowed.

### Authentication (public key only)

`ssh.ServerConfig` registers **only** `PublicKeyCallback` (no
`PasswordCallback`, no `KeyboardInteractiveCallback`):

1. `conn.User()` → OS username.
2. Root mode: `user.Lookup(name)`, read `<home>/.ssh/authorized_keys`, parse
   each line with `ssh.ParseAuthorizedKey`. Non-root mode: reject unless the
   name equals the current OS user; keys still read from the current user's
   `authorized_keys`.
3. Match with `ssh.KeysEqual` → accept.

Keys are parsed per-connection (no cache — picks up file changes, avoids
stale-key bugs).

### Session channel requests

| Request         | Handling                                                    |
|-----------------|-------------------------------------------------------------|
| `pty-req`       | Parse into `pty.Winsize`; remember `TERM` env var            |
| `window-change` | `pty.Setsize` on the live PTY (before spawn: update the stored size used at spawn) |
| `shell`         | Spawn user's shell with PTY                                 |
| `exec`          | Run command; PTY if `pty-req` preceded, else plain pipes    |
| anything else   | Reply false                                                  |

Shell details:

- Shell path from `user.Shell` (`/etc/passwd` via `user.Lookup`).
- cwd = user's home directory.
- Environment: minimal set — `HOME`, `USER`, `TERM` (from `pty-req`),
  `PATH`, `SHELL`.

### PTY & privilege drop

Root mode spawns the shell via:

```go
pty.StartWithAttrs(cmd, &winsize, &syscall.SysProcAttr{
    Setsid:     true,
    Setctty:    true,
    Credential: &syscall.Credential{Uid, Gid, Groups},
})
```

One call handles PTY allocation, session detachment, controlling TTY, and the
UID/GID drop (primary + supplementary groups). Non-root mode: identical path
with zero-value credential.

### Keepalive

Clients send `keepalive@openssh.com` global requests; `x/crypto/ssh`
auto-replies to unknown global requests, and any reply proves liveness. No
server-side keepalive code required; the client enforces the timeout.

### Cleanup

When the channel closes or the WebSocket drops: `SIGKILL` the child, close the
PTY fd, and `cmd.Wait()` in a goroutine (reaps the zombie). Both `io.Copy`
directions (channel ↔ PTY) run in goroutines; whichever finishes first kills
the child. Connection teardown also closes `ssh.ServerConn`.

## SSH Client (`internal/client`)

### Connect

Parse target → `transport.Dial` (TLS for `wss://`) → `ssh.NewClientConn` with
`ssh.ClientConfig{User, Auth: []ssh.AuthMethod{PublicKey(signers...)},
HostKeyCallback, Timeout: 10s}` → `ssh.NewClient` → `OpenSession("session")`.

### Host key verification

Callback wraps `knownhosts.New(file)`:

- **Known + match** → accept.
- **Known + changed** → hard error, always.
- **Unknown + `--accept-new-host-key`** → append to known_hosts, accept.
- **Unknown without flag** → OpenSSH-style interactive prompt:

  ```
  The authenticity of host 'server:8080' can't be established.
  ED25519 key fingerprint is SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SYs.
  Are you sure you want to continue connecting (yes/no)?
  ```

  `yes` → append and connect; `no` or EOF → abort with non-zero exit.
  Fingerprint is `ssh.FingerprintSHA256(key)` (matches `ssh-keygen`).

Appended known_hosts entries use `[host]:port` form (port omitted for 80/443).

### Key loading

`-i` flags (repeatable) plus defaults `~/.ssh/id_ed25519`, `~/.ssh/id_rsa`.
Each parsed with `ssh.ParsePrivateKey`; unreadable/invalid files are skipped
with a warning; no usable keys → error.

### Interactive shell mode

1. `term.MakeRaw(os.Stdin)`; restore via `defer` (also on SIGINT/SIGTERM).
2. `session.RequestPty(os.Getenv("TERM"), rows, cols)` with current terminal
   size.
3. Goroutine: `SIGWINCH` → `session.WindowChange(rows, cols)`.
4. Wire `stdin → session.Stdin`, `session.Stdout → os.Stdout`,
   `session.Stderr → os.Stderr` via goroutines.
5. `session.Wait()`; exit status from `*ssh.ExitError` becomes the process
   exit code.
6. Ctrl+D → stdin EOF → close session stdin → server shell exits → clean
   teardown.

### Exec mode

No raw mode, no PTY. `session.Run(command)` with stdout/stderr wired; exit
code propagated.

## Logging

- wsshd: `slog.New(slog.NewTextHandler(os.Stderr, nil))`.
  - Startup: listen address, path, root/non-root mode, host key path.
  - Per-connection: auth success/failure (user, IP), session open/close, exec
    commands.
- wssh: errors and warnings to stderr.

## Error Handling

- wsshd: fatal at startup for bad flags/keys/listen errors. Per-connection
  errors logged, connection dropped — daemon keeps serving.
- wssh: connection/auth failures → clear message to stderr + non-zero exit.
  Terminal state always restored (defer) before exit.

## Testing

- **Unit**
  - transport: `httptest` server — binary opcode asserted; rate limiting
    returns 429; dial URL handling.
  - client: table-driven target parsing (scheme default, port default, path
    append, missing user).
  - server: authorized_keys parsing/matching.
- **Integration (in-process e2e)**
  - Start server on random port with temp host key + temp authorized_keys
    containing a generated test key → connect client → exec `echo hi` → assert
    output and exit code.
  - Shell mode: feed `echo hi\nexit\n` on stdin, assert output.
  - Non-root enforcement: connecting as another user is rejected.
  - Privilege drop itself: manual root-run test (CI runs non-root).

## Dependencies (exact)

| Module                     | Purpose                          |
|----------------------------|----------------------------------|
| `golang.org/x/crypto`      | SSH protocol, knownhosts         |
| `github.com/coder/websocket` | WebSocket (not gorilla, not nhooyr) |
| `github.com/creack/pty`    | PTY allocation                   |
| `golang.org/x/term`        | Terminal raw mode                |
| `golang.org/x/time`        | Rate limiting                    |

## Out of Scope (YAGNI)

- Port forwarding / X11 / agent forwarding / SCP / SFTP subsystems.
- SSH compression.
- `env` request forwarding.
- Client config file (`~/.ssh/config` parsing).
- IPv6-specific handling beyond what `net` provides free.
