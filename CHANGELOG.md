# Changelog

See [GitHub Releases](https://github.com/lucanhost/wssh/releases) for
auto-generated release notes from commit history.

## [Unreleased]

- `wsshd`: fix Windows public-key auth rejecting every connection when the
  service account is a `DOMAIN\user` name — the non-root user check now
  compares on the local part, matching the domain-stripped username the
  `wssh` client offers
- `wsshd`: spawn Windows shell/exec children with a usable host
  environment (`SystemRoot`, `ComSpec`, a Windows `PATH`, `PATHEXT`,
  `TEMP`) instead of the hardcoded Unix `PATH`, so external commands
  resolve and `cmd.exe` initializes correctly
- `wsshd` (Windows): reap the spawned process tree on session teardown via
  a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` — closing the job
  kills the whole tree (a `cmd.exe` and descendants such as a grandchild
  `ping.exe`) in one call, so a closed session frees its `MaxChildren` slot
  promptly instead of `cmd.Wait()` blocking on inherited stdio handles; the
  PTY session path now uses the same sanitized child environment as exec
  (previously it kept the hardcoded Unix `PATH`)

## [0.3.0] - 2026-09-13

- `wsshd` daemonizes by default: re-executes itself detached (`Setsid`,
  stdio → `/dev/null`, working directory preserved) and prints the child
  PID; new `-D` flag opts out to run in the foreground (use `-D` under
  systemd or when debugging). Windows does not support daemonization and
  always runs in the foreground
- Normalize shell-output assertions with `strings.TrimSpace` so Windows
  `\r\n` line endings pass CI
- Fix Windows `lookupShell`: fall back to `%COMSPEC%` / `cmd.exe` so the
  auth `shell` extension is never empty
- Fix cross-platform CI: macOS shell lookup via `dscl` fallback, Windows
  SID bypass for authorized_keys checks, `DOMAIN\user` stripping in
  client/E2E targets, Unix-permission test skips and mode-check guard on
  Windows, flake-proof rate-limiter eviction assertion

## [0.2.0] - 2026-09-10

- Native Windows support: `wsshd` runs with ConPTY via
  `aymanbagabas/go-pty` (replaces `creack/pty`), shell auto-resolution to
  `pwsh.exe` / `powershell.exe` / `cmd.exe` with `/C` / `-Command` args,
  `CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW` process attrs, default host
  key under `%AppData%\wssh\host_key`; `wssh` handles `os.Interrupt` only
  and polls for terminal resizes (500ms) since `SIGWINCH` is unavailable
- Fix random exit 255: unknown wait failures now report status 1, signaled
  processes send `exit-signal` with name/core-dump, client maps signal
  deaths to exit code 128
- WebSocket keepalive tolerates brief blips: 30s interval, 15s timeout,
  3 consecutive ping failures before drop; `TCP_NODELAY` enforced on
  dial and listener
- Unix permission checks (`Stat_t` uid/mode) and credential dropping
  isolated behind `!windows` build tags; Windows skips them
- CI now matrix-tests linux/windows/macos; releases add
  windows/amd64 + windows/arm64 with `.exe` suffix

## [0.1.1] - 2026-09-09

- Idle sessions no longer exit 255 behind proxies that drop quiet
  connections: client and server send SSH-level `keepalive@openssh.com`
  requests every 10 seconds
- WebSocket keepalive closes the connection on ping timeout so the SSH
  layer sees EOF instead of hanging on a dead conn
- TCP_NODELAY enabled on the server listener and client dial, removing
  ~40ms Nagle buffering on interactive keystrokes

## [0.1.0] - 2026-09-08

Initial release.

- `wsshd`: SSH-over-WebSocket daemon — public-key auth, root/non-root modes
  with privilege drop, PTY + exec sessions, per-IP rate limiting with
  reverse-proxy-aware client IP extraction, TOML config file, handshake caps,
  StrictModes permission checks
- `wssh`: CLI client — interactive shell (raw terminal, SIGWINCH resize) and
  one-shot exec mode, known_hosts verification with TOFU prompt, exit-code
  propagation
- `-version` flag on both binaries; release binaries stamped via
  `-ldflags -X main.version`
- Release artifacts for linux/darwin on amd64/arm64

[Unreleased]: https://github.com/lucanhost/wssh/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/lucanhost/wssh/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/lucanhost/wssh/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/lucanhost/wssh/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/lucanhost/wssh/releases/tag/v0.1.0
