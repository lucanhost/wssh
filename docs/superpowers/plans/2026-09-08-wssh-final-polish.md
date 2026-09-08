# wssh Final Polish Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make wssh release-ready: fix the broken README, add standard project files (CHANGELOG, CONTRIBUTING, RELEASING), add a tag-triggered GitHub Actions release workflow, and document every package and exported symbol with godoc comments.

**Architecture:** Documentation-only batch. Tasks 1–4 touch `.md`/`.yml` files; Tasks 5–6 touch `.go` files with strictly additive doc comments (no code movement, no signature changes); Task 7 verifies all gates. No task depends on another's output except Task 7.

**Tech Stack:** Go 1.26.8 (`go.mod`), Makefile (`build`/`test`/`ci`/`clean`), GitHub Actions (`actions/checkout@v4`, `actions/setup-go@v5`, `softprops/action-gh-release@v2`), godoc conventions.

**Spec:** `docs/superpowers/specs/2026-09-07-wssh-design.md` (design doc, approved; latest amendments record `go 1.26.0` language version — actual `go.mod` declares `go 1.26.8`; use `1.26` as the stated floor in docs).

## Convention Change (record for future batches)

This batch changes the repo convention from "no comments in Go code" to
"**all exported symbols documented with godoc comments; internal comments
minimal**". Future batches must document any newly added exported symbols.

## Global Constraints

- **Convention change:** This batch changes the repo convention from "no comments in Go code" to "all exported symbols documented with godoc; internal comments minimal."
- NO behavior, logic, or test changes. Go file changes are strictly additive doc comments.
- NO new dependencies.
- Existing CI workflow (`.github/workflows/ci.yml`) is NOT modified.
- Release workflow triggers on tags only — NOT branches or PRs.
- First release version is `v0.1.0` (pre-v1, unstable).
- **Go version:** MUST read `go.mod` and use the actual declared version in all docs. `go.mod` declares `go 1.26.8` → docs state "Go 1.26+". Do NOT hardcode 1.21.
- Package doc comments appear ONCE per package (primary file only).
- Doc comments use standard godoc format: `// Package name is ...`, `// Name is ...` / `// Name does ...`, blank `//` lines between paragraphs, `// # Section Name` headings, tab-indented code examples after `//`.
- All code fences in markdown files use raw triple backticks — NO escaping.
- Repo conventions: conventional commits (docs:/ci:/chore:); every task ends in a commit.
- All tests pass with `-race -count=1`; no test behavior changes.

## Known Follow-ups (out of scope here)

- `go.mod` module path is `wssh` (not `github.com/lucanhost/wssh`). The README's `go install github.com/lucanhost/wssh/...` instructions and the release repo URL assume the module path is renamed at/around release. Renaming would rewrite every import in every `.go` file and is therefore excluded from this doc-only batch; track as a follow-up before publishing the first release tag.
- `internal/e2e` contains only test files; `go doc` reports "no source-code package" for it. It is exempt from the package-doc requirement (no non-test package exists there).

## File Map

| File | Action | Task |
|------|--------|------|
| `README.md` | Modify (rewrite) | 1 |
| `.github/workflows/release.yml` | Create | 2 |
| `CHANGELOG.md` | Create | 3 |
| `CONTRIBUTING.md` | Create | 3 |
| `RELEASING.md` | Create | 4 |
| `cmd/wsshd/main.go` | Modify (package doc only) | 5 |
| `cmd/wssh/main.go` | Modify (package doc only) | 5 |
| `internal/transport/transport.go` | Modify (package doc + Accept/Dial docs) | 5, 6 |
| `internal/server/server.go` | Modify (package doc + symbol docs) | 5, 6 |
| `internal/client/client.go` | Modify (package doc + symbol docs) | 5, 6 |
| `internal/config/config.go` | Modify (package doc + symbol docs) | 5, 6 |
| `internal/termval/termval.go` | Modify (package doc + symbol doc) | 5, 6 |
| `internal/transport/ratelimit.go` | Modify (symbol docs) | 6 |
| `internal/server/keys.go` | Modify (symbol doc) | 6 |
| `internal/server/session.go` | Modify (symbol doc) | 6 |
| `internal/client/hostkey.go` | Modify (symbol docs) | 6 |
| `internal/client/target.go` | Modify (symbol docs) | 6 |
| `internal/client/signers.go` | Modify (symbol doc) | 6 |
| `internal/client/note.go` | Modify (symbol doc) | 6 |

---

### Task 1: Fix README.md — escaped backticks + missing sections [docs]

**Files:**
- Modify: `README.md` (full rewrite)

**Background:** The current README's TOML code fence uses escaped backticks (`\`\`\`toml` … `\`\`\``), which GitHub renders as literal backslash-backtick text. Rewrite fixes the fence to raw triple backticks and adds Installation, Quick Start, wsshd/wssh flag tables, Security, and Building sections. The two Limitations bullets present in the current README but absent from the template (`trusted_proxies` precedence, WebSocket origin policy) are preserved verbatim as bullets 5–6 — the instruction is to preserve ALL existing Limitations content in current wording.

- [ ] **Step 1: Replace `README.md` with the full content below**

````markdown
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
````

- [ ] **Step 2: Verify no escaped fences remain**

Run: `grep -n '\\\\`' README.md; echo "exit=$?"`
Expected: no matches (`exit=1`).

Run: `grep -c '^```' README.md`
Expected: an even count ≥ 10 (every fence opened is closed).

- [ ] **Step 3: Verify Go version matches go.mod**

Run: `grep "Requires Go" README.md && grep ^go go.mod`
Expected: `Requires Go 1.26+.` and `go 1.26.8`.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README with install, quick start, and security sections"
```

---

### Task 2: Add GitHub Actions release workflow [ci]

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Produces: on pushing a tag `v*`, cross-platform binaries named
  `wsshd-<VERSION>-<GOOS>-<GOARCH>` / `wssh-<VERSION>-<GOOS>-<GOARCH>` plus
  `checksums-sha256.txt` attached to a GitHub Release. First release target:
  `v0.1.0`. Platforms: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64
  (no Windows: PTY + syscall.Credential + /etc/passwd are Unix-only).
- Does NOT touch: `.github/workflows/ci.yml` (existing CI, unchanged).

- [ ] **Step 1: Create `.github/workflows/release.yml`**

```yaml
name: release
on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Build binaries
        run: |
          VERSION=${GITHUB_REF_NAME}
          LDFLAGS="-s -w"
          PLATFORMS=(
            "linux/amd64"
            "linux/arm64"
            "darwin/amd64"
            "darwin/arm64"
          )
          mkdir -p dist
          for platform in "${PLATFORMS[@]}"; do
            GOOS="${platform%/*}"
            GOARCH="${platform#*/}"
            for bin in wsshd wssh; do
              output="dist/${bin}-${VERSION}-${GOOS}-${GOARCH}"
              GOOS="${GOOS}" GOARCH="${GOARCH}" CGO_ENABLED=0 go build -trimpath \
                -buildvcs=true -ldflags="${LDFLAGS}" -o "${output}" "./cmd/${bin}"
            done
          done

      - name: Generate checksums
        run: |
          cd dist
          sha256sum * > checksums-sha256.txt

      - name: Create release
        uses: softprops/action-gh-release@v2
        with:
          generate_release_notes: true
          files: |
            dist/*
          draft: false
          prerelease: ${{ contains(github.ref_name, '-') }}
```

- [ ] **Step 2: Verify trigger and structure**

Run: `grep -n -A3 '^on:' .github/workflows/release.yml && grep -c 'pull_request\|branches' .github/workflows/release.yml; echo "exit=$?"`
Expected: `on:` block shows only `push: tags: - 'v*'`; grep count is `0` (no branch or PR triggers, exit=1).

Run: `grep -n "go-version-file" .github/workflows/release.yml`
Expected: `go-version-file: go.mod` (no version drift).

- [ ] **Step 3: Validate YAML parses**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/release.yml')); print('valid yaml')"`
Expected: `valid yaml`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add tag-triggered binary release workflow"
```

---

### Task 3: Add CHANGELOG.md + CONTRIBUTING.md [docs]

**Files:**
- Create: `CHANGELOG.md`
- Create: `CONTRIBUTING.md`

- [ ] **Step 1: Create `CHANGELOG.md`**

```markdown
# Changelog

See [GitHub Releases](https://github.com/lucanhost/wssh/releases) for
auto-generated release notes from commit history.

## [Unreleased]

- Initial release pending
```

- [ ] **Step 2: Create `CONTRIBUTING.md`**

````markdown
# Contributing

## Development

Requires Go 1.26+.

```bash
git clone https://github.com/lucanhost/wssh.git
cd wssh
make ci  # vet + test + vulncheck
```

## Code style

- Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`)
- All exported symbols documented with godoc comments
- Internal comments minimal — only for non-obvious logic
- All tests pass with `go test ./... -race -count=1`

## Pull requests

- Squash to a single commit per logical change
- Update tests for any behavior change
- Keep PRs focused (one concern per PR)
````

- [ ] **Step 3: Verify Go version matches go.mod**

Run: `grep "Requires Go" CONTRIBUTING.md && grep ^go go.mod`
Expected: `Requires Go 1.26+.` and `go 1.26.8`.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md CONTRIBUTING.md
git commit -m "docs: add CHANGELOG and CONTRIBUTING guides"
```

---

### Task 4: Add RELEASING.md [docs]

**Files:**
- Create: `RELEASING.md`

- [ ] **Step 1: Create `RELEASING.md`**

````markdown
# Releasing wssh

## Versioning

wssh uses [Semantic Versioning](https://semver.org/). The project is pre-v1
(unstable API); breaking changes may occur in any `v0.x` release.

## Creating a release

1. Ensure `main` is green (CI passing).
2. Tag the release:

   ```bash
   git tag -a v0.1.0 -m "v0.1.0: initial release"
   git push origin v0.1.0
   ```

3. The `release` workflow builds cross-platform binaries and publishes a
   GitHub release automatically.
4. Verify the release at https://github.com/lucanhost/wssh/releases.

## Pre-release

Use a hyphenated suffix: `v0.2.0-rc.1`. The release workflow marks these as
pre-release automatically.
````

- [ ] **Step 2: Verify content**

Run: `grep -n "v0.1.0\|pre-release" RELEASING.md`
Expected: both the `v0.1.0` tag example and the pre-release section appear.

- [ ] **Step 3: Commit**

```bash
git add RELEASING.md
git commit -m "docs: add RELEASING guide"
```

---

### Task 5: Add package-level godoc comments [docs — Go files]

**Files (all Modify — insert doc comment block immediately before the `package` line):**
- `cmd/wsshd/main.go`
- `cmd/wssh/main.go`
- `internal/transport/transport.go` (primary file for package `transport`)
- `internal/server/server.go` (primary file for package `server`)
- `internal/client/client.go` (primary file for package `client`)
- `internal/config/config.go` (primary file for package `config`)
- `internal/termval/termval.go` (primary file for package `termval`)

**Constraint:** Each package doc appears exactly ONCE — never in a second file of the same package. `internal/e2e` is test-only and exempt (`go doc` reports "no source-code package" for it).

**Interfaces:**
- Consumes: nothing (comments only).
- Produces: package docs visible via `go doc <pkg>`; consumed by Task 7 verification.

- [ ] **Step 1: `cmd/wsshd/main.go` — insert before `package main`**

```go
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
```

- [ ] **Step 2: `cmd/wssh/main.go` — insert before `package main`**

```go
// Command wssh is an SSH-over-WebSocket client.
//
// It connects to a wsshd server via WebSocket and provides either an
// interactive shell or one-shot command execution.
//
// # Usage
//
//	wssh [flags] [ws://|wss://]user@host[:port][/path] [command...]
//
// If command is present, runs in exec mode (one-shot). Otherwise, opens an
// interactive shell with raw terminal mode and SIGWINCH resize support.
//
// # Host Key Verification
//
// By default, wssh verifies host keys against ~/.ssh/known_hosts and fails
// closed on changed keys (MITM detection). Use --accept-new-host-key to
// trust unknown hosts on first use.
//
// # Example
//
//	wssh user@example.com
//	wssh user@example.com -- ls -la
//	wssh wss://user@example.com:443/ws -- ping -c3 8.8.8.8
package main
```

- [ ] **Step 3: `internal/transport/transport.go` — insert before `package transport`**

```go
// Package transport provides WebSocket-to-net.Conn bridging for SSH over
// WebSocket.
//
// The core mechanism wraps a WebSocket connection into a net.Conn interface,
// allowing golang.org/x/crypto/ssh to run unmodified over WebSocket binary
// frames.
//
// # Binary Frames
//
// All WebSocket messages use websocket.MessageBinary. Text frames would
// corrupt the SSH protocol stream.
//
// # Keepalive
//
// Both Accept and Dial start a background goroutine that sends WebSocket
// ping frames every 15 seconds (5 second timeout). This survives idle-killing
// proxies and firewalls. The goroutine exits on ping failure or connection
// close.
package transport
```

- [ ] **Step 4: `internal/server/server.go` — insert before `package server`**

```go
// Package server implements an SSH-over-WebSocket daemon.
//
// It accepts WebSocket upgrades, wraps them into net.Conn, and runs a full
// SSH server (golang.org/x/crypto/ssh) over the WebSocket binary stream.
//
// # Authentication
//
// Public-key authentication only. The PublicKeyCallback reads
// ~/.ssh/authorized_keys for the target OS user and matches against the
// presented key.
//
// # Sessions
//
// Each authenticated connection can open multiple session channels. Each
// channel supports pty-req, window-change, shell, and exec requests.
// PTY sessions spawn with Setsid+Setctty to create a controlling terminal.
//
// # Privilege Drop
//
// In root mode (geteuid() == 0), sessions drop privileges to the
// authenticated user's UID/GID via syscall.Credential before spawning the
// shell. Non-root mode can only serve the current user.
//
// # Graceful Shutdown
//
// Wait blocks until all active sessions close. WaitTimeout adds a deadline.
package server
```

- [ ] **Step 5: `internal/client/client.go` — insert before `package client`**

```go
// Package client implements an SSH-over-WebSocket client.
//
// It dials a WebSocket URL, establishes an SSH connection over it, and
// provides either an interactive shell or one-shot command execution.
//
// # Target Parsing
//
// Targets use the format [ws://|wss://]user@host[:port][/path].
//
// # Host Key Verification
//
// The HostKeyCallback wraps golang.org/x/crypto/ssh/knownhosts and adds
// trust-on-first-use (TOFU) support with interactive prompts.
//
// # Modes
//
//   - Interactive shell (RunShell): raw terminal mode, SIGWINCH resize,
//     exit code 130 on Ctrl+C.
//   - Exec (RunCommand): one-shot command, exit code from remote exit-status.
package client
```

- [ ] **Step 6: `internal/config/config.go` — insert before `package config`**

```go
// Package config implements wsshd configuration loading and merging.
//
// Configuration starts from Defaults, is overlaid by an optional TOML file
// (Load), and then by explicitly set CLI flags, producing a final Config via
// Merge. Overlay uses pointer fields so "unset" is distinguishable from a
// zero value: rate = 0 in the TOML file disables rate limiting rather than
// falling back to the default.
package config
```

- [ ] **Step 7: `internal/termval/termval.go` — insert before `package termval`**

```go
// Package termval validates terminal type (TERM) values.
//
// Both wsshd and wssh use it to sanitize the TERM string exchanged in SSH
// pty-req requests before placing it in a child process environment or
// sending it in a pty request, falling back to "xterm-256color" when invalid.
package termval
```

- [ ] **Step 8: Verify package docs appear and appear once per package**

Run:
```bash
for p in $(go list ./... | grep -v /e2e); do echo "== $p"; go doc "$p" | head -1; done
```
Expected: each package prints its doc summary line (e.g. `Package transport provides WebSocket-to-net.Conn bridging...`) instead of a bare `package X // import ...` line. `cmd/wsshd` and `cmd/wssh` print `Command wsshd is an SSH-over-WebSocket daemon.` / `Command wssh is an SSH-over-WebSocket client.`.

Run: `gofmt -l . && go build ./... && go vet ./...`
Expected: no output, all pass.

- [ ] **Step 9: Commit**

```bash
git add cmd/wsshd/main.go cmd/wssh/main.go internal/transport/transport.go internal/server/server.go internal/client/client.go internal/config/config.go internal/termval/termval.go
git commit -m "docs: add package-level godoc comments"
```

---

### Task 6: Add exported symbol godoc comments [docs — Go files]

**Files (all Modify — insert doc comment on the line(s) immediately before each declaration):**
- `internal/transport/transport.go` — `Accept`, `Dial`
- `internal/transport/ratelimit.go` — `RateLimiter`, `NewRateLimiter`, `Allow`, `Close`
- `internal/server/server.go` — `Config` (+ all 9 exported fields), `Server`, `New`, `WebSocketHandler`, `Root`, `Wait`, `WaitTimeout`, `Close`
- `internal/server/keys.go` — `LoadOrGenerateHostKey`
- `internal/server/session.go` — `ErrMalformedCredential`
- `internal/client/client.go` — `Connect`, `ExitError` (+ `Code` field), `ExitCode`, `RunCommand`, `RunShell`
- `internal/client/hostkey.go` — `HostKeyOptions` (+ all 4 fields), `HostKeyCallback`, `tcpAddr`
- `internal/client/target.go` — `Target` (+ all 5 fields), `ParseTarget`, `WebSocketURL`, `SSHAddr`
- `internal/client/signers.go` — `LoadSigners`
- `internal/client/note.go` — `PlaintextNote`
- `internal/config/config.go` — `Overlay` (+ all 7 fields), `Config` (+ all 7 fields), `Defaults`, `Load`, `Merge`, `Validate`
- `internal/termval/termval.go` — `Valid`

**Constraint:** Doc comments only. Do NOT move, rename, or reformat any declaration. Do NOT document unexported symbols unless noted (`tcpAddr` is explicitly requested despite being unexported).

**Interfaces:**
- Consumes: package docs from Task 5 already present in the same files.
- Produces: fully documented API surface, verified by Task 7.

- [ ] **Step 1: `internal/transport/transport.go` — add before `func Accept` and `func Dial`**

```go
// Accept upgrades the HTTP request to a WebSocket connection and returns it
// wrapped in a net.Conn suitable for serving SSH over. Messages are
// exchanged as binary frames only, frames larger than 1 MiB are rejected,
// and a keepalive goroutine pings the peer every 15 seconds; closing the
// returned conn stops the keepalive. WebSocket compression is disabled.
func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error)
```

```go
// Dial connects to the WebSocket endpoint at rawURL and returns the
// connection wrapped in a net.Conn suitable for driving SSH over. Messages
// are exchanged as binary frames only, frames larger than 1 MiB are
// rejected, and a keepalive goroutine pings the peer every 15 seconds;
// closing the returned conn stops the keepalive. WebSocket compression is
// disabled.
func Dial(ctx context.Context, rawURL string) (net.Conn, error)
```

- [ ] **Step 2: `internal/transport/ratelimit.go` — add docs to RateLimiter, NewRateLimiter, Allow, Close**

```go
// RateLimiter is a per-key (client IP) token-bucket rate limiter with idle
// eviction and a bounded entry count.
//
// Each key gets its own limiter created on first use. Entries idle longer
// than the TTL are dropped by a background sweep goroutine; when the entry
// map reaches its maximum size, stale entries are evicted and, if none are
// stale, the least-recently-seen entry is dropped, so spoofed sources cannot
// grow the map without limit.
type RateLimiter struct {
```

```go
// NewRateLimiter returns a RateLimiter admitting ratePerSec requests per
// second per key with the given burst, and starts a background goroutine
// that sweeps every idleTTL, dropping entries idle longer than idleTTL.
// A ratePerSec of 0 or less disables limiting: Allow always returns true.
// Call Close to stop the sweep goroutine.
func NewRateLimiter(ratePerSec float64, burst int, idleTTL time.Duration) *RateLimiter
```

```go
// Allow reports whether a request from ip may proceed, recording the access
// time for eviction purposes. It always returns true when limiting is
// disabled.
func (rl *RateLimiter) Allow(ip string) bool
```

```go
// Close stops the background eviction goroutine. The limiter must not be
// used after Close.
func (rl *RateLimiter) Close()
```

- [ ] **Step 3: `internal/server/server.go` — add docs to Config, all its fields, Server, New, WebSocketHandler, Root, Wait, WaitTimeout, Close**

```go
// Config configures a Server. Zero values for optional fields are replaced
// with defaults by New.
type Config struct {
	// Signer is the SSH host key signer; required.
	Signer ssh.Signer
	// Logger receives connection and session logs; nil discards all output.
	Logger *slog.Logger
	// Rate is the permitted WebSocket upgrade rate per client IP, in
	// requests per second; 0 disables rate limiting.
	Rate float64
	// Burst is the token-bucket burst size above Rate; 0 means 5.
	Burst int
	// AuthorizedKeysPath, when non-nil, overrides the location of a user's
	// authorized_keys file; the default is $HOME/.ssh/authorized_keys.
	AuthorizedKeysPath func(*user.User) string
	// MaxSessionsPerConn caps session channels per SSH connection; 0 means 10.
	MaxSessionsPerConn int
	// MaxChildren caps concurrently running child processes; 0 means 256.
	MaxChildren int
	// MaxHandshakes caps concurrent in-flight SSH handshakes; excess
	// upgrades receive HTTP 503; 0 means 64.
	MaxHandshakes int
	// TrustedProxies lists CIDRs (or bare IPs) whose forwarding headers are
	// trusted when extracting the real client IP; invalid entries are logged
	// and ignored. Empty means the client IP is always taken from RemoteAddr.
	TrustedProxies []string
}
```

```go
// Server is an SSH-over-WebSocket daemon. It upgrades HTTP requests to
// WebSocket connections, runs the SSH server handshake over them, and serves
// session channels (shell/exec), dropping privileges to the authenticated
// user when running as root.
type Server struct {
```

```go
// New creates a Server from cfg, applying defaults for omitted fields:
// Burst 5, MaxSessionsPerConn 10, MaxChildren 256, MaxHandshakes 64, and a
// logger that discards output. Root mode is enabled when the process runs
// with euid 0. TrustedProxies entries may be CIDRs or bare IPs (bare IPv4
// becomes /32, bare IPv6 becomes /128). A rate limiter is created only when
// cfg.Rate is greater than 0.
func New(cfg Config) *Server
```

```go
// WebSocketHandler returns an http.Handler that upgrades WebSocket requests
// and serves SSH over them. It rate-limits upgrades per client IP (HTTP 429
// when exceeded; the IP honors TrustedProxies), admits at most
// MaxHandshakes concurrent SSH handshakes (HTTP 503 beyond that), and serves
// each accepted connection in its own goroutine.
func (s *Server) WebSocketHandler() http.Handler
```

```go
// Root reports whether the server runs in root mode (euid 0), where it
// authenticates any OS user and drops privileges to the authenticated user
// before spawning processes.
func (s *Server) Root() bool
```

```go
// Wait blocks until every connection accepted by the server has finished.
func (s *Server) Wait()
```

```go
// WaitTimeout blocks until every connection has finished or the timeout
// expires, whichever comes first. A timeout of 0 or less waits indefinitely.
// It reports whether the drain completed.
func (s *Server) WaitTimeout(timeout time.Duration) bool
```

```go
// Close releases server resources, stopping the rate limiter's background
// eviction goroutine if one was created.
func (s *Server) Close()
```

- [ ] **Step 4: `internal/server/keys.go` — add doc before `func LoadOrGenerateHostKey`**

```go
// LoadOrGenerateHostKey returns an ssh.Signer for the private key at path.
// When the file does not exist, a new ed25519 key is generated and written
// as PEM with mode 0600 (parent directories created with mode 0755). An
// existing file that cannot be read or parsed is an error; it is never
// silently replaced.
func LoadOrGenerateHostKey(path string) (ssh.Signer, error)
```

- [ ] **Step 5: `internal/server/session.go` — add doc before `var ErrMalformedCredential`**

```go
// ErrMalformedCredential is returned when the authenticated user's uid or
// gid cannot be parsed as unsigned 32-bit integers. The session fails
// closed — it is never started under the daemon's own credentials.
var ErrMalformedCredential = errors.New("malformed uid or gid in user record")
```

- [ ] **Step 6: `internal/client/client.go` — add docs to Connect, ExitError + Code, ExitCode, RunCommand, RunShell**

```go
// Connect dials the target's WebSocket URL, performs the SSH handshake with
// the given signers and host key callback, and returns the established
// client. Both the WebSocket dial and the SSH handshake are bounded by a
// 10-second timeout. On SSH handshake failure the underlying connection is
// closed before returning the error.
func Connect(ctx context.Context, t *Target, signers []ssh.Signer, hostKeyCb ssh.HostKeyCallback) (*ssh.Client, error)
```

```go
// ExitError reports the remote command's exit status.
type ExitError struct {
	// Code is the exit status reported by the remote SSH server.
	Code int
}
```

```go
// ExitCode maps a session error to a process exit code: 0 for nil, the
// remote exit status for an *ExitError (directly or wrapped), and 255 for
// any other failure.
func ExitCode(err error) int
```

```go
// RunCommand runs command on the remote host in exec mode — no PTY, no raw
// terminal — writing output to stdout and stderr, and returns an *ExitError
// carrying the remote exit status.
func RunCommand(c *ssh.Client, command string, stdout, stderr io.Writer) error
```

```go
// RunShell starts an interactive remote shell: it puts the local terminal
// into raw mode, requests a PTY sized to the current window, forwards
// stdin/stdout/stderr, and resizes the remote PTY on SIGWINCH. SIGINT and
// SIGTERM restore the terminal, close the session, and exit the process
// with code 130. Stdin must be a terminal, or an error is returned.
func RunShell(c *ssh.Client) error
```

- [ ] **Step 7: `internal/client/hostkey.go` — add docs to HostKeyOptions, its fields, HostKeyCallback, tcpAddr**

```go
// HostKeyOptions configures host key verification.
type HostKeyOptions struct {
	// KnownHostsPath is the known_hosts file checked before connecting.
	KnownHostsPath string
	// AcceptNew enables trust-on-first-use: unknown hosts are appended to
	// the known_hosts file without prompting.
	AcceptNew bool
	// In is the prompt input stream; nil means os.Stdin.
	In io.Reader
	// Out is the prompt output stream; nil means os.Stderr.
	Out io.Writer
}
```

```go
// HostKeyCallback returns an ssh.HostKeyCallback implementing four
// verification paths against KnownHostsPath:
//
//   - known host, matching key: accepted;
//   - known host, changed key: hard failure (possible MITM); never accepted;
//   - unknown host with AcceptNew: key appended to the known_hosts file and
//     accepted;
//   - unknown host without AcceptNew: prints an OpenSSH-style fingerprint
//     prompt to Out, reads the answer from In, and appends the key only on
//     "yes" (EOF or any other answer aborts the connection).
func HostKeyCallback(opts HostKeyOptions) ssh.HostKeyCallback
```

```go
// tcpAddr is a trivial net.Addr wrapping a bare "host:port" string. The
// knownhosts callback calls net.SplitHostPort on remote.String() and fails
// when it does not parse, so the callback fabricates this address from the
// hostname it already holds rather than relying on the WebSocket-backed
// connection's address.
type tcpAddr string
```

- [ ] **Step 8: `internal/client/target.go` — add docs to Target, its fields, ParseTarget, WebSocketURL, SSHAddr**

```go
// Target is a parsed connection target.
type Target struct {
	// Scheme is "ws" or "wss".
	Scheme string
	// User is the remote OS username used for SSH authentication.
	User string
	// Host is the hostname or IP address without brackets.
	Host string
	// Port is the TCP port; 80 for ws:// and 443 for wss:// by default.
	Port int
	// Path is the WebSocket endpoint path; defaults to /ws.
	Path string
}
```

```go
// ParseTarget parses a connection target of the form
// [ws://|wss://]user@host[:port][/path]. A missing scheme defaults to
// ws://, the port defaults to 80 for ws:// and 443 for wss://, and a
// missing path defaults to /ws. The username is required; the scheme must
// be ws or wss; the port must be 1-65535. For example, "alice@server"
// yields ws://alice@server:80/ws and "wss://bob@srv:8443" yields
// wss://bob@srv:8443/ws.
func ParseTarget(s string) (*Target, error)
```

```go
// WebSocketURL returns the full WebSocket URL to dial, for example
// wss://example.com:443/ws.
func (t *Target) WebSocketURL() string
```

```go
// SSHAddr returns the host:port address used by the SSH layer and for
// known_hosts matching.
func (t *Target) SSHAddr() string
```

- [ ] **Step 9: `internal/client/signers.go` — add doc before `func LoadSigners`**

```go
// LoadSigners parses the private keys at paths for SSH authentication.
// When paths is empty it falls back to ~/.ssh/id_ed25519 and ~/.ssh/id_rsa;
// missing default keys are skipped silently, while unreadable or
// unparseable keys (default or explicit) are skipped with a warning written
// to warn. Paths beginning with ~/ expand to the home directory. An error
// is returned when no usable key remains.
func LoadSigners(paths []string, warn io.Writer) ([]ssh.Signer, error)
```

- [ ] **Step 10: `internal/client/note.go` — add doc before `func PlaintextNote`**

```go
// PlaintextNote returns a one-line warning about plaintext ws:// targets
// (SSH crypto still applies; wss:// is recommended on untrusted networks)
// and an empty string for wss:// targets.
func PlaintextNote(t *Target) string
```

- [ ] **Step 11: `internal/config/config.go` — add docs to Overlay, its fields, Config, its fields, Defaults, Load, Merge, Validate**

```go
// Overlay is a partially-specified configuration: unset fields are left
// untouched by Merge. Pointer fields make zero values distinguishable from
// absence — for example, rate = 0 in the TOML file disables rate limiting
// rather than restoring the default.
type Overlay struct {
	// Addr overrides the HTTP listen address.
	Addr *string `toml:"addr"`
	// Path overrides the WebSocket endpoint path.
	Path *string `toml:"path"`
	// HostKey overrides the SSH host key file path.
	HostKey *string `toml:"hostkey"`
	// Cert overrides the TLS certificate file.
	Cert *string `toml:"cert"`
	// Key overrides the TLS private key file.
	Key *string `toml:"key"`
	// Rate overrides the per-IP upgrade rate; 0 disables rate limiting.
	Rate *float64 `toml:"rate"`
	// TrustedProxies overrides the trusted proxy CIDR list; nil leaves the
	// previous value in place.
	TrustedProxies []string `toml:"trusted_proxies"`
}
```

```go
// Config is the fully-resolved daemon configuration.
type Config struct {
	// Addr is the HTTP listen address.
	Addr string
	// Path is the WebSocket endpoint path.
	Path string
	// HostKey is the SSH host key file path.
	HostKey string
	// Cert is the TLS certificate file; empty disables TLS.
	Cert string
	// Key is the TLS private key file; empty disables TLS.
	Key string
	// Rate is the per-IP WebSocket upgrade rate; 0 disables rate limiting.
	Rate float64
	// TrustedProxies lists CIDRs (or bare IPs) trusted to send client-IP
	// forwarding headers.
	TrustedProxies []string
}
```

```go
// Defaults returns the built-in configuration: addr ":8080", path "/ws",
// host key "/etc/wssh/host_key", rate 1, TLS disabled, no trusted proxies.
func Defaults() Config
```

```go
// Load reads and parses the TOML config file at path. A missing or
// malformed file is an error.
func Load(path string) (*Overlay, error)
```

```go
// Merge layers overlays over base in order: each overlay's set fields
// replace the accumulated value and unset fields are skipped. Nil overlays
// are ignored.
func Merge(base Config, overlays ...*Overlay) Config
```

```go
// Validate reports whether the configuration is self-consistent: cert and
// key must be provided together.
func (c Config) Validate() error
```

- [ ] **Step 12: `internal/termval/termval.go` — add doc before `func Valid`**

```go
// Valid reports whether s is an acceptable TERM value: 1-64 characters from
// [A-Za-z0-9._-]. Callers fall back to "xterm-256color" when it returns
// false.
func Valid(s string) bool
```

- [ ] **Step 13: Verify gates**

Run: `gofmt -l . && go vet ./... && go build ./...`
Expected: no output, exit 0.

Run: `go test ./... -race -count=1`
Expected: all packages `ok` (no test changes, no new failures).

- [ ] **Step 14: Commit**

```bash
git add internal/transport/transport.go internal/transport/ratelimit.go internal/server/server.go internal/server/keys.go internal/server/session.go internal/client/client.go internal/client/hostkey.go internal/client/target.go internal/client/signers.go internal/client/note.go internal/config/config.go internal/termval/termval.go
git commit -m "docs: document all exported symbols"
```

---

### Task 7: Verify everything [verification]

**Files:**
- None created. Fix-up edits allowed if verification finds gaps (commit as `docs: fix godoc/doc gaps found in verification`).

- [ ] **Step 1: Format, vet, build, test**

```bash
gofmt -l .            # must print nothing
go vet ./...          # must be clean
go build ./...        # must compile
go test ./... -race -count=1   # must pass
```
Expected: gofmt empty; vet/build silent; all tests `ok`.

- [ ] **Step 2: Every package documented (appears once per package)**

```bash
for p in $(go list ./... | grep -v /e2e); do go doc "$p" | head -2; done
```
Expected: every package prints its package doc text (`go doc` shows doc comments above the `package X // import ...` line). `internal/e2e` is excluded (test-only; `go doc` reports "no source-code package" — acceptable).

Then confirm no package doc is duplicated across files:

```bash
grep -rn "^// Package " --include="*.go" . | sort
```
Expected: exactly 7 matches — one per package: `cmd/wsshd`, `cmd/wssh`, `internal/transport`, `internal/server`, `internal/client`, `internal/config`, `internal/termval` (each package name appears exactly once).

- [ ] **Step 3: Every exported symbol documented**

```bash
go list ./... | grep -v /e2e | while read -r p; do
  d=$(go doc -all "$p")
  # declarations and their docs: print exported decl lines lacking a preceding comment
  echo "$d" | awk -v pkg="$p" '
    /^func [A-Z]|^type [A-Z]|^var [A-Z]|^func \([a-zA-Z0-9_ ]*\*?[A-Z][A-Za-z0-9_]*\) [A-Z]/ {print pkg": "$0}'
done
```
Expected: every listed exported declaration is immediately preceded in `go doc -all` output by its doc comment text (spot-check each: no exported symbol sits between two blank-comment boundaries). Complementary check — dump the full API and inspect:

```bash
go doc -all wssh/internal/client | less
```
Confirm: `Connect`, `ExitError`, `ExitCode`, `RunCommand`, `RunShell`, `HostKeyCallback`, `HostKeyOptions`, `LoadSigners`, `PlaintextNote`, `Target`, `ParseTarget`, `WebSocketURL`, `SSHAddr` all show docs. Repeat for `wssh/internal/server` (`Config`, `Server`, `New`, `WebSocketHandler`, `Root`, `Wait`, `WaitTimeout`, `Close`, `LoadOrGenerateHostKey`, `ErrMalformedCredential`), `wssh/internal/transport` (`Accept`, `Dial`, `RateLimiter`, `NewRateLimiter`, `Allow`, `Close`), `wssh/internal/config` (`Overlay`, `Config`, `Defaults`, `Load`, `Merge`, `Validate`), `wssh/internal/termval` (`Valid`).

- [ ] **Step 4: README fences render (no escaped backticks)**

```bash
grep -n '\\`' README.md; echo "escaped-fence-grep-exit=$?"
grep -c '^```' README.md
```
Expected: first grep finds nothing (exit 1); fence count even.

- [ ] **Step 5: Release workflow tag-only trigger**

```bash
grep -n "pull_request\|branches" .github/workflows/release.yml; echo "pr-branch-grep-exit=$?"
grep -n -A2 "tags:" .github/workflows/release.yml
```
Expected: no branch/PR triggers (exit 1); `tags: - 'v*'` present.

- [ ] **Step 6: Go version consistent across docs**

```bash
grep ^go go.mod
grep -rn "Go 1\." README.md CONTRIBUTING.md
```
Expected: `go 1.26.8`; docs state `Go 1.26+` (no `1.21` anywhere).

- [ ] **Step 7: Full CI gate (equivalent to `make ci`)**

```bash
make ci
```
Expected: vet + test + govulncheck all pass.

- [ ] **Step 8: Commit any fix-ups (only if Steps 1–7 found gaps)**

```bash
git add -A
git commit -m "docs: fix godoc/doc gaps found in verification"
```

---

## Self-Review Checklist (completed during planning)

- [x] All markdown code fences in target file contents use raw triple backticks (verified: Task 1 replaces the escaped `\`\`\`toml` fence; Tasks 3–4 content uses raw fences).
- [x] Release workflow triggers on tags only (`on: push: tags: ['v*']`); no `branches`/`pull_request` keys; `permissions: contents: write` present; `go-version-file: go.mod` (no version drift); `fetch-depth: 0` for release notes; prerelease auto-detects hyphenated tags.
- [x] Go version matches `go.mod` (`go 1.26.8` → "Go 1.26+" in README and CONTRIBUTING; no 1.21 references).
- [x] All exported symbols have docs: full inventory enumerated in Task 6 (transport: Accept, Dial, RateLimiter, NewRateLimiter, Allow, Close; server: Config+9 fields, Server, New, WebSocketHandler, Root, Wait, WaitTimeout, Close, LoadOrGenerateHostKey, ErrMalformedCredential; client: Connect, ExitError+Code, ExitCode, RunCommand, RunShell, HostKeyOptions+4 fields, HostKeyCallback, Target+5 fields, ParseTarget, WebSocketURL, SSHAddr, LoadSigners, PlaintextNote; config: Overlay+7 fields, Config+7 fields, Defaults, Load, Merge, Validate; termval: Valid). Plan adapted the prompt sketches to actual code: no `ShutdownTimeout` field exists; `LoadSigners`/`Target`/`ParseTarget`/`WebSocketURL`/`SSHAddr`/`PlaintextNote` live in `signers.go`/`target.go`/`note.go`, not `client.go`; `Accept`/`Dial` are exported and documented; `tcpAddr` documented despite unexported (explicitly requested, non-obvious knownhosts `net.SplitHostPort(remote.String())` workaround).
- [x] Package docs appear once per package (7 packages; primary files pinned in Task 5; `internal/e2e` exempt as test-only).
- [x] No placeholders: every file's full content and every doc comment written in full.
- [x] Type consistency: doc comments reference actual signatures verified against source (e.g. `NewRateLimiter(ratePerSec float64, burst int, idleTTL time.Duration)`, `WaitTimeout(timeout time.Duration) bool`, `HostKeyCallback(opts HostKeyOptions) ssh.HostKeyCallback`).
- [x] Ordering & file conflicts: Tasks 1–4 (`.md`/`.yml`) never touch `.go`; Tasks 5–6 (`.go`) never touch `.md`/`.yml`; Task 7 runs last.
