# wssh Security Hardening — Design

Date: 2026-09-08
Status: Approved
Scope: Full audit action plan (4 security/stability fixes + housekeeping), minimal approach (A1), no new config surface.

## Background

Security audit of `lucanhost/wssh` produced a prioritized action plan. All claims were
verified against source before acceptance:

| ID | Claim | Verified at |
|----|-------|-------------|
| C1 | No `StrictModes` check when reading `authorized_keys` | `internal/server/auth.go:73` (`os.Open` with no `os.Stat`) |
| H1 | SSH handshake has no deadline → Slowloris goroutine/FD exhaustion | `internal/server/server.go:125` (`ssh.NewServerConn(netConn, ...)`), `serveConn` has no test coverage |
| H2 | `RateLimiter.entries` map unbounded → OOM via spoofed/IPv6 sources | `internal/transport/ratelimit.go:42` (unconditional insert), sweep every 60s (`server.go:84`) |
| H3 | `http.Server` created with zero timeouts → HTTP-level slowloris on upgrade path | `cmd/wsshd/main.go:92` |

Corrections to the audit, kept out of scope by verification:

- **CSWSH**: `coder/websocket` rejects cross-origin upgrades by default (empty
  `OriginPatterns` = same-origin only, confirmed via library docs). Not a vulnerability.
  wssh ships a Go client, not a browser client, so no legitimate user is blocked by the
  default. Operator-facing `OriginPatterns` config is deferred until browser frontends exist.
- **`exec` via `shell -c`** and **shell-from-`/etc/passwd`**: match OpenSSH/Unix behavior.
  Not defects.

## Design

### 1. StrictModes — `internal/server/auth.go`

New function `checkStrictModes(u *user.User, path string) error`, called from
`loadAuthorizedKeys` before `os.Open`.

- Stat the full chain: `u.HomeDir`, `filepath.Dir(path)`, then `path`.
- Each entry must satisfy:
  - owner uid == `u.Uid` or `0` (root) — read via `syscall.Stat_t` (Unix-only; consistent
    with existing `SysProcAttr` credential usage in the repo)
  - no group/other write bits: `mode.Perm()&0o022 == 0`
- `0644`/`0600` key files and `0755`/`0700` dirs remain legal (OpenSSH parity).
- Any violation → error from `loadAuthorizedKeys` → `publicKeyCallback` rejects auth with
  a `slog.Warn` naming the offending path and reason. Fail closed.
- Symlinks: followed (`os.Stat` semantics), ownership/perm checks apply to the target —
  matches OpenSSH.

### 2. Handshake deadline — `internal/server/server.go`

- `const handshakeTimeout = 60 * time.Second` (tighter than OpenSSH's default 120s
  `LoginGraceTime`).
- In `serveConn`, before `ssh.NewServerConn`: `netConn.SetDeadline(time.Now().Add(handshakeTimeout))`.
- On successful handshake: `netConn.SetDeadline(time.Time{})` — clear, so long-lived
  sessions and the 15s keepalive ping are unaffected.
- Stalled handshake → deadline error → logged + conn closed, goroutine and FD released.
- The WS-backed `net.Conn` from `transport.Accept` supports deadlines (`websocket.NetConn`).

### 3. Rate limiter entry cap — `internal/transport/ratelimit.go`

- Unexported `const maxEntries = 10000`. `NewRateLimiter` signature unchanged.
- In `Allow`, when inserting a new key and `len(entries) >= maxEntries`:
  1. Delete stale entries (`lastSeen` older than TTL cutoff) — same predicate as `sweep`.
  2. If still at cap, evict the single oldest entry by `lastSeen` (linear scan).
- Map size never exceeds `maxEntries` regardless of source-IP volume.
- Linear scan is O(n) only on insert-at-cap with n ≤ 10k — no `container/list` LRU needed.
- Eviction of an active (recently-seen) client under sustained saturation only costs that
  client a fresh burst — same failure mode as any LRU at capacity, acceptable for a
  connection-rate limiter.

### 4. HTTP server timeouts — `cmd/wsshd/main.go`

- `ReadHeaderTimeout: 10 * time.Second`, `IdleTimeout: 120 * time.Second`.
- Deliberately **no** `ReadTimeout` / `WriteTimeout`: `websocket.Accept` hijacks the
  connection and the hijacked conn inherits deadlines set by `net/http` — a `ReadTimeout`
  would kill live SSH-over-WS sessions mid-stream. Dead-session cleanup remains the job of
  the existing keepalive (15s ping, 5s ping timeout).

### 5. Housekeeping

- Add `LICENSE` — MIT, copyright `lucanhost`.
- `.github/workflows/ci.yml`: replace `go-version: '1.21'` with `go-version-file: go.mod`
  so CI can never drift from `go.mod` again.

## Error handling

All new failure paths fail closed and emit structured `slog.Warn` logs following the
existing style (`"auth rejected: ..."`, `"ssh handshake failed"`, etc.). No new error
types are exported.

## Testing

- `checkStrictModes`: table-driven, split by privilege requirements:
  - **Always run (mode bits only, ordinary CI):** pass (`0600` key in `0700` dir);
    reject group-writable file, world-writable dir, group-writable home.
  - **Ownership cases, skipped unless `os.Geteuid() == 0`:** root-owned file passes;
    wrong-owner file rejected. These need `chown` to another uid/root, which ordinary
    CI cannot do — run opportunistically as root.
- Handshake deadline: recording `net.Conn` wrapper around the conn passed to `serveConn`.
  - **Failure path:** fake/stalling conn → assert `SetDeadline` was called before the
    handshake attempt and the conn was closed on deadline expiry.
  - **Success path:** `net.Pipe` plus a real in-process SSH client handshake
    (`ssh.NewClientConn` with `InsecureSkipVerify`, test host key signer, authorized test
    key) → assert the deadline is cleared after `ssh.NewServerConn` returns successfully.
    If this proves flaky during planning, the pre-approved fallback is a small unexported
    handshake function seam. (Fixes the current no-coverage gap on `serveConn`.)
- Rate limiter: insert > `maxEntries` distinct keys; assert size cap holds, oldest evicted,
  recently-seen entries survive.
- `go test ./...` green, including existing `auth_test`, `ratelimit_test`, `server_test`,
  `e2e_test`. E2e uses `AuthorizedKeysPath` into `t.TempDir()` (current-user-owned,
  `0700`) → passes strict checks.

## Explicitly out of scope

- `OriginPatterns` operator config (defer until browser clients exist)
- `StrictModes` disable toggle
- `HandshakeTimeout` / `MaxRateEntries` `Config` fields
- `/etc/shells` validation
- LRU via `container/list`
