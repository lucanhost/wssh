# wssh Version Support + Module Path Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename the module path from `wssh` to `github.com/lucanhost/wssh` so `go install github.com/lucanhost/wssh/cmd/...@latest` works, and add build-time version stamping (`-version` flag on both binaries, `-X main.version` in the release workflow, README docs).

**Architecture:** go.mod declares the module path; every import of `wssh/internal/...` must follow. `var version = "dev"` in both `cmd/*/main.go` package mains is replaced at build time via `-ldflags "-X main.version=..."`. The release workflow sets `VERSION=${GITHUB_REF_NAME}` and passes it through LDFLAGS. The `-version` flag short-circuits after `flag.Parse()` before any other logic.

**Tech Stack:** Go 1.26.8, `cmd/wsshd` + `cmd/wssh` package-main binaries, GitHub Actions `release.yml`, README markdown. No new dependencies.

**Spec pointer:** `docs/superpowers/specs/2026-09-07-wssh-design.md` (binaries & flags section). Batch 6 plan: `docs/superpowers/plans/2026-09-08-wssh-final-polish.md`.

## Global Constraints

- Module path rename: `wssh` → `github.com/lucanhost/wssh`. All imports updated.
- Version variable: `var version = "dev"` in both cmd mains, stamped via `-ldflags="-X main.version=${VERSION}"` in release builds.
- `-version` flag: prints `<binary> <version>` and exits 0.
- No behavior changes beyond the version flag. All existing tests must pass unchanged.
- No new dependencies.
- Repo conventions: conventional commits (feat:/fix:/chore:); every task ends in a commit.
- All tests pass with `-race -count=1`.

---

### Task 1: Rename module path to github.com/lucanhost/wssh [release blocker]

`go.mod` declares `module wssh`; the README documents
`go install github.com/lucanhost/wssh/cmd/wsshd@latest`, which 404s against a
module named `wssh`. Rename the module so `go install` works.

**Files:**
- Modify: `go.mod:1`
- Modify (import lines only): `cmd/wsshd/main.go:43-44`, `cmd/wssh/main.go:34`, `internal/e2e/e2e_test.go:24-25`, `internal/client/client.go:35-36`, `internal/client/client_test.go:22`, `internal/server/server.go:42`, `internal/server/server_test.go:21`, `internal/server/session.go:17`
- Verify (no change expected): `README.md` (the `go install` URLs already say `github.com/lucanhost/wssh/cmd/...`)

**Interfaces:**
- Produces: module importable as `github.com/lucanhost/wssh`; internal packages reachable as `github.com/lucanhost/wssh/internal/...`.

- [ ] **Step 1: Update go.mod**

Replace the first line:

```go
module wssh
```

with:

```go
module github.com/lucanhost/wssh
```

- [ ] **Step 2: Update all internal imports**

Full-module replacement of the import path prefix in every `.go` file:

```bash
grep -rl 'wssh/internal/' --include='*.go' . | xargs sed -i 's|wssh/internal/|github.com/lucanhost/wssh/internal/|g'
```

Expected result — 11 import lines across 8 files updated:

| File | Lines |
|------|-------|
| `cmd/wsshd/main.go` | `"github.com/lucanhost/wssh/internal/config"`, `"github.com/lucanhost/wssh/internal/server"` |
| `cmd/wssh/main.go` | `"github.com/lucanhost/wssh/internal/client"` |
| `internal/e2e/e2e_test.go` | `"github.com/lucanhost/wssh/internal/client"`, `"github.com/lucanhost/wssh/internal/server"` |
| `internal/client/client.go` | `"github.com/lucanhost/wssh/internal/termval"`, `"github.com/lucanhost/wssh/internal/transport"` |
| `internal/client/client_test.go` | `"github.com/lucanhost/wssh/internal/server"` |
| `internal/server/server.go` | `"github.com/lucanhost/wssh/internal/transport"` |
| `internal/server/server_test.go` | `"github.com/lucanhost/wssh/internal/transport"` |
| `internal/server/session.go` | `"github.com/lucanhost/wssh/internal/termval"` |

Verify no stragglers (must print nothing):

```bash
grep -rn 'wssh/internal/' --include='*.go' .
```

- [ ] **Step 3: Verify build + tests**

```bash
go build ./...
go test ./... -race -count=1
```

Expected: build clean; all packages report `ok` with zero failures.

- [ ] **Step 4: Verify `go mod tidy` is a no-op**

```bash
go mod tidy
git diff --exit-code go.mod go.sum
```

Expected: `git diff` exits 0 — no changes to `go.mod` or `go.sum`.

- [ ] **Step 5: Commit**

```bash
git add go.mod $(grep -rl 'wssh/internal/' --include='*.go' .)
git commit -m "fix: rename module path to github.com/lucanhost/wssh"
```

(After the sed in Step 2, `grep -rl 'wssh/internal/'` finds no files — stage the
8 files explicitly instead: `git add go.mod cmd/wsshd/main.go cmd/wssh/main.go internal/e2e/e2e_test.go internal/client/client.go internal/client/client_test.go internal/server/server.go internal/server/server_test.go internal/server/session.go`.)

---

### Task 2: Add version variables to both cmd mains [feature]

Add a `version` package variable stamped at build time and a `-version` flag to
both `cmd/wsshd/main.go` and `cmd/wssh/main.go`.

**Files:**
- Modify: `cmd/wsshd/main.go` (import `fmt`; add `version` var; add `showVersion` flag + early exit after `flag.Parse()`)
- Modify: `cmd/wssh/main.go` (add `version` var; add `showVersion` flag + early exit after `flag.Parse()`)

**Interfaces:**
- Consumes: nothing new (both mains already use `flag`, `os`; `wssh/main.go` already imports `fmt`).
- Produces: `var version = "dev"` in each package main, overridable at build time via `-ldflags "-X main.version=..."`; `-version` flag on each binary printing `wsshd <version>` / `wssh <version>` and exiting 0.

- [ ] **Step 1: Add version variable + flag to `cmd/wsshd/main.go`**

Add `"fmt"` to the import block (`cmd/wsshd/main.go:30-45`):

```go
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
	"strings"
	"syscall"
	"time"

	"github.com/lucanhost/wssh/internal/config"
	"github.com/lucanhost/wssh/internal/server"
)
```

Add the version variable between the closing `)` of the import block and
`func main()`:

```go
// version is stamped at build time via -ldflags="-X main.version=..."
var version = "dev"
```

Add the flag to the flag-declaration var block inside `main()` (after
`configPath`):

```go
		showVersion    = flag.Bool("version", false, "print version and exit")
```

Insert the early exit immediately after `flag.Parse()` (line 58):

```go
	flag.Parse()
	if *showVersion {
		fmt.Printf("wsshd %s\n", version)
		os.Exit(0)
	}
```

- [ ] **Step 2: Add version variable + flag to `cmd/wssh/main.go`**

Add the version variable between the import block and `type multiFlag`:

```go
// version is stamped at build time via -ldflags="-X main.version=..."
var version = "dev"
```

Add the flag after the `acceptNew` declaration inside `main()`:

```go
	showVersion := flag.Bool("version", false, "print version and exit")
```

Insert the early exit immediately after `flag.Parse()` (line 59), before the
`args := flag.Args()` block:

```go
	flag.Parse()
	if *showVersion {
		fmt.Printf("wssh %s\n", version)
		os.Exit(0)
	}
```

No new imports needed — `wssh/main.go` already imports `flag`, `fmt`, `os`.

- [ ] **Step 3: Verify build + tests**

```bash
go build ./...
go test ./... -race -count=1
```

Expected: build clean; all packages `ok`.

- [ ] **Step 4: Verify `-version` behavior of both binaries**

```bash
go build -o /tmp/wsshd ./cmd/wsshd
go build -o /tmp/wssh ./cmd/wssh
/tmp/wsshd -version   # Expected: wsshd dev
/tmp/wssh -version    # Expected: wssh dev
/tmp/wsshd -version; echo "exit=$?"   # exit=0
```

Stamped build check:

```bash
go build -ldflags="-X main.version=v0.1.0-test" -o /tmp/wsshd-stamped ./cmd/wsshd
go build -ldflags="-X main.version=v0.1.0-test" -o /tmp/wssh-stamped ./cmd/wssh
/tmp/wsshd-stamped -version   # Expected: wsshd v0.1.0-test
/tmp/wssh-stamped -version    # Expected: wssh v0.1.0-test
```

- [ ] **Step 5: Commit**

```bash
git add cmd/wsshd/main.go cmd/wssh/main.go
git commit -m "feat: add -version flag to wsshd and wssh"
```

---

### Task 3: Wire version stamping into release workflow [CI]

The release workflow currently has `LDFLAGS="-s -w"` (the `-X main.version`
was dropped as a no-op in commit `db933b2` because the variable didn't exist).
Wire it back in with the tag name.

**Files:**
- Modify: `.github/workflows/release.yml:22-41` (Build binaries step)

**Interfaces:**
- Consumes: `var version` in both package mains (Task 2).
- Produces: release binaries at `dist/${bin}-${VERSION}-${GOOS}-${GOARCH}` with version stamped; expected `... -version` output `wsshd v0.1.0` / `wssh v0.1.0` for tag `v0.1.0`.

- [ ] **Step 1: Update the Build binaries step**

Replace the `Build binaries` step body (lines 23-41) with:

```yaml
      - name: Build binaries
        run: |
          VERSION=${GITHUB_REF_NAME}
          LDFLAGS="-s -w -X main.version=${VERSION}"
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
```

Keep the `GOOS="${GOOS}" GOARCH="${GOARCH}"` env prefix on the `go build` line
(commit `db933b2` fixed cross-compilation by exporting these env vars per
iteration — the shell assignments alone do not export them).

- [ ] **Step 2: Verify stamped binaries locally**

Replicate the workflow build for one platform and check the version output:

```bash
VERSION=v0.1.0
LDFLAGS="-s -w -X main.version=${VERSION}"
mkdir -p /tmp/wssh-dist
for bin in wsshd wssh; do
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -buildvcs=true \
    -ldflags="${LDFLAGS}" -o "/tmp/wssh-dist/${bin}-${VERSION}-linux-amd64" "./cmd/${bin}"
done
/tmp/wssh-dist/wsshd-v0.1.0-linux-amd64 -version   # Expected: wsshd v0.1.0
/tmp/wssh-dist/wssh-v0.1.0-linux-amd64 -version    # Expected: wssh v0.1.0
```

Also confirm both cross-compilation targets still build (workflow builds
darwin/arm64; spot-check one):

```bash
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -buildvcs=true \
  -ldflags="-s -w -X main.version=v0.1.0" -o /tmp/wssh-darwin-arm64 ./cmd/wsshd
```

Expected: builds succeed; `file /tmp/wssh-darwin-arm64` reports a Mach-O arm64 binary.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: stamp version via -ldflags in release builds"
```

---

### Task 4: Update README with version flag documentation [docs]

Add `-version` to both flag tables and show version checking in Quick Start.

**Files:**
- Modify: `README.md:45-62` (Quick Start block), `README.md:101-112` (wsshd flags table), `README.md:114-120` (wssh flags table)

**Interfaces:**
- Consumes: `-version` flags from Task 2.
- Produces: README documenting `-version` for both binaries.

- [ ] **Step 1: Update the wsshd flags table**

In the `### wsshd flags` table (`README.md:103-112`), add a row after
`-config`:

```markdown
| `-version` | `false` | Print version and exit |
```

Resulting table:

```markdown
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
| `-version` | `false` | Print version and exit |
```

- [ ] **Step 2: Update the wssh flags table**

In the `### wssh flags` table (`README.md:116-120`), add a row after
`--accept-new-host-key`:

```markdown
| `-version` | `false` | Print version and exit |
```

Resulting table:

```markdown
| Flag | Default | Description |
|------|---------|-------------|
| `-i` | `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` | Private key path (repeatable) |
| `--known-hosts` | `~/.ssh/known_hosts` | Known hosts file |
| `--accept-new-host-key` | `false` | Trust-on-first-use for unknown hosts |
| `-version` | `false` | Print version and exit |
```

- [ ] **Step 3: Update Quick Start with version checking**

In the `## Quick Start` block (`README.md:46-62`), insert the version-check
lines at the top of the bash block, before the existing `# Start the server`
comment. Keep all existing commands unchanged:

```bash
# Check versions
./bin/wsshd -version
./bin/wssh -version

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

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: document -version flag in README"
```

---

## Self-Review

- [ ] **Module path:** All 11 `wssh/internal/` import lines across 8 `.go` files (cmd/wsshd, cmd/wssh, e2e, client, client_test, server, server_test, session) renamed to `github.com/lucanhost/wssh/internal/` in Task 1 Step 2 — verified by the grep in Step 2 and `go build ./...` in Step 3. README `go install` URLs already correct — no change needed.
- [ ] **Version variable:** `var version = "dev"` added to both `cmd/wsshd/main.go` and `cmd/wssh/main.go` (Task 2 Steps 1-2), stamped via `-ldflags "-X main.version=..."` — verified in Task 2 Step 4 and Task 3 Step 2.
- [ ] **`-version` flag in both mains:** `flag.Bool("version", ...)` + early exit after `flag.Parse()` printing `wsshd <version>` / `wssh <version>`, exit 0 — Task 2, verified by `/tmp/wsshd -version; echo exit=$?`.
- [ ] **Release workflow LDFLAGS:** include `-X main.version=${VERSION}` while preserving the `GOOS=... GOARCH=...` env-prefixed `go build` (no regression of `db933b2`) — Task 3 Step 1.
- [ ] **README flag tables:** both tables get a `-version` row; Quick Start shows version checking — Task 4.
- [ ] **No behavior change beyond version flag:** no other logic touched; full `go test ./... -race -count=1` gates every task.
- [ ] **Placeholder scan:** all steps contain exact content; no TBD/TODO.