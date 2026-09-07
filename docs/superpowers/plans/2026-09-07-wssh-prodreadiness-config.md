# wssh Production-Readiness + Config-File Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Third and final remediation batch for wssh: pin `MaxAuthTries`, real-client-IP rate limiting behind trusted proxies, known_hosts symlink hardening, IPv6 support guarantees, plaintext `ws://` advisory, hardened build + CI with govulncheck, and TOML config-file support for `wsshd`.

**Architecture:** All logic lives in `internal/` packages; `cmd/wsshd` and `cmd/wssh` stay thin. Task 2 adds client-IP extraction inside `internal/server` (rate limiter untouched — it still keys on the string returned by `clientIP`). Task 7 adds a new `internal/config` package that does NOT import `internal/server`; `cmd/wsshd/main.go` does the wiring (flags → CLI overlay, TOML file → file overlay, `config.Merge` resolves).

**Tech Stack:** Go (module `wssh`, go.mod declares `go 1.26.0`), `golang.org/x/crypto/ssh`, `github.com/coder/websocket`, `github.com/BurntSushi/toml` (the ONE new dependency), `golang.org/x/vuln/cmd/govulncheck` (tool, not dependency), Make, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-07-wssh-design.md` (deviation addendum appended to that file when this plan was written — see "Deviations" below).

## Global Constraints

- Go floor: go.mod declares `go 1.26.0` (satisfies the spec's "Go 1.21+" floor).
- Module dependencies go 5 → 6: adds `github.com/BurntSushi/toml` ONLY (Task 7). No other new module deps. `govulncheck` is a tool (`go install`), NOT a go.mod dependency.
- Adds EXACTLY TWO new flags: `-trusted-proxies` (Task 2) and `-config` (Task 7). No other flags added, renamed, or have changed defaults.
- Do not regress behavior from the security-hardening or post-hardening batches. Untrusted peers MUST NOT be able to influence their rate-limit key. Omitting `-config` MUST be byte-identical to current behavior.
- Repo conventions: no comments in Go code (Makefile/YAML/TOML examples/README may comment); conventional commits (feat:/fix:/test:/docs:/chore:/ci:); every task ends in a commit (Task 1 is verify-only — see its note).
- All tests must pass with `-race`; new tests follow existing style (table-driven where natural, `t.Helper()`, no new key-generation paths).
- `internal/config` must NOT import `internal/server`.
- `slog` for all logging; no key material or secrets in logs.
- `burst` stays fixed at 5 (not configurable).
- No comments in Go code — the code blocks below contain none; keep it that way.

## Deviations From the Prompt (verified against repo at commit 8524897)

1. **Task 1 is already satisfied at HEAD.** `MaxAuthTries: 3` is set (`internal/server/server.go:67`) and the pinning test `TestMaxAuthTriesIsThree` already exists (`internal/server/server_test.go:149`, added in commit `77b03b2 feat(server): lower MaxAuthTries from 6 to 3`). Task 1 below is therefore a **verify-only** task: confirm both facts, run the test, commit nothing. The conditional code is included in case the verifier finds either missing.
2. **go.mod declares `go 1.26.0`, not 1.21.** The CI YAML below pins `go-version: '1.21'` exactly as specified; GitHub's `actions/setup-go` installs Go 1.21 and `GOTOOLCHAIN=auto` (default since 1.21) transparently downloads the 1.26 toolchain demanded by go.mod, so the workflow works. If the operator prefers, `go-version-file: go.mod` is a drop-in alternative — not applied here to keep the specified YAML verbatim.
3. **known_hosts entries always carry an explicit `:port` (including 80/443).** The spec's line "port omitted for 80/443" does not describe wssh: `Target.SSHAddr()` always emits `host:port`, the callback hostname is that exact string, and `appendKnownHost` writes it verbatim. The round-trip test (Task 4) is the acceptance criterion and **passes empirically** for IPv6 (`[2001:db8::1]:8080`, `[2001:db8::2]:80`) and IPv4 (`203.0.113.5:8080`) — verified against `golang.org/x/crypto@v0.56.0` `knownhosts` semantics before this plan was written. Task 4 therefore changes NO production code; it only pins behavior with tests.
4. **`BurntSushi/toml` pinned to v1.5.0** (verified installable, zero transitive deps — `go mod graph` shows only the direct require edge).

## Execution Ordering (SDD controller MUST honor)

- **Task 3 before Task 4:** both modify `internal/client/hostkey.go` (Task 3) / `hostkey_test.go` (both).
- **Task 2 before Task 7:** Task 2 adds the `-trusted-proxies` flag and `Config.TrustedProxies`; Task 7's config-file rewire must enumerate ALL flags present in `cmd/wsshd/main.go` at implementation time (including `-trusted-proxies`) and route them through config resolution. Do NOT assume a fixed flag list.
- `cmd/wsshd/main.go` is modified by Tasks 2, 4 (verify-only), and 7 — execute in order 2 → 4 → 7.
- Tasks 1 and 2 both touch the `server` package but on disjoint files (Task 1 appends to `server_test.go` only if missing; Task 2 creates `clientip.go`/`clientip_test.go` and modifies `server.go`).
- Every other task touches a disjoint file set.
- Linear order 1 → 2 → 3 → 4 → 5 → 6 → 7 satisfies all constraints.

## Accepted-Risk Ledger

- **Task 3 residual TOCTOU (accepted):** `appendKnownHost` does `os.Lstat` (symlink check) and then `os.OpenFile` — a local attacker can swap the path to a symlink between the two calls. Fully closing this requires openat/fstatat with `O_NOFOLLOW` (out of scope for this batch). The Lstat check closes the trivial persistent-symlink attack; the race window is recorded as accepted risk.
- **Task 2 residual (accepted, by design):** if an operator lists a trusted proxy CIDR that also contains end-user addresses, those users can spoof their rate-limit key via forwarding headers. Mitigation is operational: only list proxy CIDRs. `X-Forwarded-For` handling walks right-to-left and returns the first (rightmost) untrusted entry, which is the correct de-facto algorithm.
- **IPv6 limitations (documented, out of scope):** link-local zone IDs (`fe80::1%eth0`) unsupported; rate limiting stays per-address (no `/64` subnet grouping). Both noted as future items in the spec addendum.

## Repo State Snapshot (verified at 8524897)

- `internal/server/server.go`: `Config` struct (line 18), `Server` struct (line 28), `New` (line 40, sets `MaxAuthTries: 3` at line 67), `WebSocketHandler` (line 83, does `ip, _, err := net.SplitHostPort(r.RemoteAddr)` at line 85).
- `internal/server/server_test.go`: `TestMaxAuthTriesIsThree` at line 149; helpers `testSigner(t)` (in `auth_test.go:19`, returns `(ssh.Signer, string)`) and `discardLogger()` (`auth_test.go:32`).
- `internal/client/hostkey.go`: `appendKnownHost` at line 84 (O_APPEND|O_CREATE|O_WRONLY, no symlink check).
- `internal/client/hostkey_test.go`: package `client`; helpers `testKey`, `tcpAddr`, `writeKnownHosts`, `keyLine`; imports do NOT yet include `errors`.
- `internal/client/target.go`: `ParseTarget`, `WebSocketURL`, `SSHAddr` (all use `net.JoinHostPort`).
- `cmd/wsshd/main.go`: flags addr/path/hostkey/cert/key/rate; RemoteAddr advisory log at line 79-81.
- `cmd/wssh/main.go`: parses target at line 43.
- `go.mod`: 5 direct deps (coder/websocket, x/crypto, x/term, x/time, creack/pty) + x/sys indirect; `go 1.26.0`.
- No `Makefile`, no `.github/` directory. `README.md` exists with a "## Limitations" section.

---

### Task 1: Pin MaxAuthTries == 3 with a regression test [verify + test]

**Files:**
- Verify: `internal/server/server.go:67` (`MaxAuthTries: 3` inside `ssh.ServerConfig` literal in `New`)
- Verify: `internal/server/server_test.go:149` (`TestMaxAuthTriesIsThree`)
- Conditional modify: `internal/server/server_test.go` (append test ONLY if missing)
- Conditional modify: `internal/server/server.go` (set value ONLY if not 3)

**Interfaces:**
- Consumes: `New(Config{Signer: ...}) *Server` (existing); `testSigner(t testing.TB) (ssh.Signer, string)` (existing helper in `auth_test.go`); unexported `Server.sshConfig` field (same package).
- Produces: nothing new — a pinned guarantee. Later tasks rely on `New` keeping `MaxAuthTries: 3`.

**Repo-state note:** Both the value and the test ALREADY EXIST at HEAD (commit `77b03b2`). Expected outcome of this task: verification only, **no commit**. Only if a verification step fails do you apply the conditional fix and commit.

- [ ] **Step 1: Verify the value in server.go**

Run: `grep -n "MaxAuthTries" internal/server/server.go`
Expected output:
```
67:		MaxAuthTries:      3,
```
If the value is anything other than `3`, edit it to `3` before continuing.

- [ ] **Step 2: Verify the pinning test exists**

Run: `grep -n "TestMaxAuthTriesIsThree" internal/server/server_test.go`
Expected output:
```
149:func TestMaxAuthTriesIsThree(t *testing.T) {
```
If it is missing, append this exact test to `internal/server/server_test.go` (reuses the existing `testSigner` helper — do not invent a new key-generation path):

```go
func TestMaxAuthTriesIsThree(t *testing.T) {
	signer, _ := testSigner(t)
	s := New(Config{Signer: signer})
	if got := s.sshConfig.MaxAuthTries; got != 3 {
		t.Fatalf("MaxAuthTries = %d, want 3", got)
	}
}
```

- [ ] **Step 3: Run the pinning test**

Run: `go test ./internal/server/ -race -run TestMaxAuthTriesIsThree -v`
Expected output:
```
=== RUN   TestMaxAuthTriesIsThree
--- PASS: TestMaxAuthTriesIsThree (0.00s)
PASS
ok  	wssh/internal/server	<CACHE/TIME>
```

- [ ] **Step 4: Commit (only if Step 1 or Step 2 required a change)**

If nothing changed (expected): record "Task 1 verified, already pinned at HEAD" in the task log and skip the commit — there is nothing to commit and an empty commit violates repo hygiene.

If a change WAS required:
```bash
git add internal/server/server.go internal/server/server_test.go
git commit -m "test(server): pin MaxAuthTries to 3 with regression test"
```

---

### Task 2: Real client IP behind reverse proxies / CDNs [security + ops]

**Files:**
- Create: `internal/server/clientip.go`
- Create: `internal/server/clientip_test.go`
- Modify: `internal/server/server.go` (Config struct, Server struct, New, WebSocketHandler, imports)
- Modify: `cmd/wsshd/main.go` (new flag, proxy list parse, server.Config wiring, startup log)
- Modify: `README.md` (Limitations bullet about RemoteAddr)

**Interfaces:**
- Consumes: `transport.RateLimiter.Allow(ip string) bool` (unchanged); `testSigner(t)` helper; `New(Config) *Server`.
- Produces (later tasks rely on these):
  - `Config.TrustedProxies []string` — new field on `server.Config`; each entry a CIDR or bare IP.
  - `Server.trustedProxies []*net.IPNet` — parsed storage.
  - `func (s *Server) clientIP(r *http.Request) string` — method on `*Server`.
  - `func hostFromAddr(addr string) string`, `func (s *Server) peerTrusted(ip net.IP) bool`, `func xffClientIP(xff string, s *Server) net.IP` — unexported helpers.
  - CLI flag `-trusted-proxies` (string, default `""`) — Task 7's overlay must expose it as `trusted_proxies`.
- The `RateLimiter` itself is NOT changed — it keys on the string `clientIP` returns.

- [ ] **Step 1: Write the failing test**

Create `internal/server/clientip_test.go`:

```go
package server

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		headers        map[string]string
		want           string
	}{
		{
			name:       "no trusted proxies ignores XFF",
			remoteAddr: "203.0.113.7:1234",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.1"},
			want:       "203.0.113.7",
		},
		{
			name:           "untrusted peer ignores XFF",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "203.0.113.7:1234",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.1"},
			want:           "203.0.113.7",
		},
		{
			name:           "trusted peer CF-Connecting-IP",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:443",
			headers:        map[string]string{"CF-Connecting-IP": "198.51.100.9"},
			want:           "198.51.100.9",
		},
		{
			name:           "trusted peer X-Real-IP without CF header",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:443",
			headers:        map[string]string{"X-Real-IP": "198.51.100.10"},
			want:           "198.51.100.10",
		},
		{
			name:           "trusted peer XFF rightmost untrusted wins",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:443",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.20, 10.0.0.9"},
			want:           "198.51.100.20",
		},
		{
			name:           "trusted peer XFF all trusted falls back to leftmost",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:443",
			headers:        map[string]string{"X-Forwarded-For": "10.0.0.9, 10.0.0.8"},
			want:           "10.0.0.9",
		},
		{
			name:           "bare IP trusted proxy",
			trustedProxies: []string{"127.0.0.1"},
			remoteAddr:     "127.0.0.1:9999",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.1"},
			want:           "198.51.100.1",
		},
		{
			name:           "malformed trusted proxy entry skipped",
			trustedProxies: []string{"banana", "10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:443",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.1"},
			want:           "198.51.100.1",
		},
		{
			name:           "IPv6 trusted peer with IPv6 XFF entry",
			trustedProxies: []string{"2001:db8::/32"},
			remoteAddr:     "[2001:db8::5]:443",
			headers:        map[string]string{"X-Forwarded-For": "2606:4700::99"},
			want:           "2606:4700::99",
		},
		{
			name:           "IPv6 untrusted peer keeps bracket-stripped host",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "[2001:db8::5]:443",
			want:           "2001:db8::5",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, _ := testSigner(t)
			s := New(Config{Signer: signer, TrustedProxies: tc.trustedProxies})
			r := &http.Request{RemoteAddr: tc.remoteAddr, Header: http.Header{}}
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := s.clientIP(r); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHostFromAddr(t *testing.T) {
	if got := hostFromAddr("192.0.2.1:8080"); got != "192.0.2.1" {
		t.Fatalf("hostFromAddr = %q, want 192.0.2.1", got)
	}
	if got := hostFromAddr("[2001:db8::1]:80"); got != "2001:db8::1" {
		t.Fatalf("hostFromAddr = %q, want 2001:db8::1", got)
	}
	if got := hostFromAddr("noport"); got != "noport" {
		t.Fatalf("hostFromAddr = %q, want noport", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -race -run 'TestClientIP|TestHostFromAddr' -v`
Expected: FAIL — build error `s.clientIP undefined (type *Server has no field or method clientIP)` (and `Config has no field TrustedProxies`).

- [ ] **Step 3: Create clientip.go**

Create `internal/server/clientip.go`:

```go
package server

import (
	"net"
	"net/http"
	"strings"
)

func (s *Server) clientIP(r *http.Request) string {
	peer := hostFromAddr(r.RemoteAddr)
	if len(s.trustedProxies) == 0 {
		return peer
	}
	ip := net.ParseIP(peer)
	if ip == nil || !s.peerTrusted(ip) {
		return peer
	}
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		if pip := net.ParseIP(strings.TrimSpace(v)); pip != nil {
			return pip.String()
		}
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		if pip := net.ParseIP(strings.TrimSpace(v)); pip != nil {
			return pip.String()
		}
	}
	if pip := xffClientIP(r.Header.Get("X-Forwarded-For"), s); pip != nil {
		return pip.String()
	}
	return peer
}

func hostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func (s *Server) peerTrusted(ip net.IP) bool {
	for _, cidr := range s.trustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func xffClientIP(xff string, s *Server) net.IP {
	if xff == "" {
		return nil
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		pip := net.ParseIP(strings.TrimSpace(parts[i]))
		if pip == nil {
			continue
		}
		if !s.peerTrusted(pip) {
			return pip
		}
	}
	for _, p := range parts {
		if pip := net.ParseIP(strings.TrimSpace(p)); pip != nil {
			return pip
		}
	}
	return nil
}
```

- [ ] **Step 4: Wire server.go**

Four edits to `internal/server/server.go`:

Edit 1 — add `strings` to the import block (keep alphabetical order):
```go
import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/user"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"wssh/internal/transport"
)
```

Edit 2 — add `TrustedProxies` to `Config`:
```go
type Config struct {
	Signer             ssh.Signer
	Logger             *slog.Logger
	Rate               float64
	Burst              int
	AuthorizedKeysPath func(*user.User) string
	MaxSessionsPerConn int
	MaxChildren        int
	TrustedProxies     []string
}
```

Edit 3 — add `trustedProxies` to `Server` and parse entries in `New` (insert the field after `limiter`; insert the loop right after the `s := &Server{...}` literal, before the `if cfg.Rate > 0` block):
```go
type Server struct {
	sshConfig          ssh.ServerConfig
	logger             *slog.Logger
	root               bool
	currentUsername    string
	authorizedKeysPath func(*user.User) string
	limiter            *transport.RateLimiter
	trustedProxies     []*net.IPNet
	wg                 sync.WaitGroup
	maxSessionsPerConn int
	childrenSem        chan struct{}
}
```
```go
	for _, entry := range cfg.TrustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			if ip.To4() != nil {
				entry += "/32"
			} else {
				entry += "/128"
			}
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			s.logger.Warn("ignoring invalid trusted proxy entry", "entry", entry, "err", err)
			continue
		}
		s.trustedProxies = append(s.trustedProxies, cidr)
	}
```

Edit 4 — in `WebSocketHandler`, replace:
```go
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
```
with:
```go
		ip := s.clientIP(r)
```
(The `net` import stays — `serveConn` still takes `net.Conn`.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/server/ -race -count=1`
Expected: `ok wssh/internal/server` — all existing tests (loopback exec, exit status, auth failure, rate limit, MaxAuthTries, session caps, children sem) still pass; e2e behavior unchanged because tests construct `New` without `TrustedProxies` → `clientIP` returns the RemoteAddr host exactly as before.

- [ ] **Step 6: Wire cmd/wsshd/main.go**

Edit 1 — replace the flag `var` block with (adds `-trusted-proxies`):
```go
	var (
		addr           = flag.String("addr", ":8080", "HTTP listen address")
		path           = flag.String("path", "/ws", "WebSocket endpoint path")
		hostKey        = flag.String("hostkey", "/etc/wssh/host_key", "SSH host key path (ed25519/RSA; auto-generated when missing)")
		cert           = flag.String("cert", "", "TLS certificate file (enables HTTPS/WSS)")
		key            = flag.String("key", "", "TLS private key file")
		rate           = flag.Float64("rate", 1, "upgrade requests per second per IP (burst 5); 0 disables")
		trustedProxies = flag.String("trusted-proxies", "", "comma-separated CIDRs/bare IPs trusted to send forwarding headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)")
	)
```

Edit 2 — after `flag.Parse()` (before the cert/key check), add:
```go
	var proxyList []string
	for _, p := range strings.Split(*trustedProxies, ",") {
		if p = strings.TrimSpace(p); p != "" {
			proxyList = append(proxyList, p)
		}
	}
```

Edit 3 — pass to the server:
```go
	srv := server.New(server.Config{
		Signer:         signer,
		Logger:         logger,
		Rate:           *rate,
		Burst:          5,
		TrustedProxies: proxyList,
	})
```

Edit 4 — replace the startup advisory:
```go
	if *rate > 0 {
		logger.Info("rate limiting keys on RemoteAddr; if fronted by a TLS proxy, enforce rate limits at the proxy")
	}
```
with:
```go
	if len(proxyList) > 0 {
		logger.Info("trusting client IP from forwarding headers; trusted proxies: " + strings.Join(proxyList, ","))
	} else if *rate > 0 {
		logger.Info("rate limiting keys on RemoteAddr; if fronted by a TLS proxy, enforce rate limits at the proxy")
	}
```

- [ ] **Step 7: Update README Limitations bullet**

In `README.md`, replace:
```markdown
- Per-IP HTTP-level rate limiting on WebSocket upgrade requests keys on `RemoteAddr`.
  If wsshd is fronted by a TLS-terminating proxy (e.g. nginx, Cloudflare), all
  clients share the proxy's IP and rate limiting is ineffective — enforce limits
  at the proxy layer instead.
```
with:
```markdown
- Per-IP HTTP-level rate limiting on WebSocket upgrade requests keys on the real
  client IP when the direct peer is in `-trusted-proxies` (forwarding headers:
  `CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`); otherwise it keys on
  `RemoteAddr`. If wsshd is fronted by a proxy that is not listed, all clients
  share the proxy's IP — add the proxy's CIDRs to `-trusted-proxies` or enforce
  limits at the proxy layer.
```

- [ ] **Step 8: Format, vet, build, full suite**

Run: `gofmt -l . && go vet ./... && go build ./...`
Expected: no output (clean).

Run: `go test ./... -race -count=1`
Expected: `ok` for every package (`internal/client`, `internal/e2e`, `internal/server`, `internal/termval`, `internal/transport`, plus cmd packages if any).

- [ ] **Step 9: Commit**

```bash
git add internal/server/clientip.go internal/server/clientip_test.go internal/server/server.go cmd/wsshd/main.go README.md
git commit -m "feat(server): rate limit on real client IP behind trusted proxies"
```

---

### Task 3: known_hosts append symlink hardening [security]

**Files:**
- Modify: `internal/client/hostkey.go:84-95` (replace `appendKnownHost`)
- Test: `internal/client/hostkey_test.go` (append one test)

**Interfaces:**
- Consumes: `testKey(t)` helper (existing, returns `(ssh.Signer, ssh.PublicKey)`); `os`, `filepath` already imported in the test file.
- Produces: `func appendKnownHost(path, hostname string, key ssh.PublicKey) error` — same signature, new symlink refusal. Callers (`HostKeyCallback` TOFU path at hostkey.go:62 and :75) unchanged.

- [ ] **Step 1: Write the failing test**

Append to `internal/client/hostkey_test.go`:

```go
func TestAppendKnownHostRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kh := filepath.Join(dir, "known_hosts")
	if err := os.Symlink(target, kh); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	_, key := testKey(t)
	if err := appendKnownHost(kh, "srv:8080", key); err == nil {
		t.Fatal("append through symlink accepted")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "original\n" {
		t.Fatalf("symlink target was modified: %q", data)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/ -race -run TestAppendKnownHostRefusesSymlink -v`
Expected: FAIL with `append through symlink accepted` (current implementation happily appends through the symlink).

- [ ] **Step 3: Replace appendKnownHost**

In `internal/client/hostkey.go`, replace the whole function (lines 84-95):
```go
func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	entry := fmt.Sprintf("%s %s\n", hostname, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("wssh: cannot append to %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(entry); err != nil {
		return err
	}
	return nil
}
```
with:
```go
func appendKnownHost(path, hostname string, key ssh.PublicKey) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("wssh: refusing to append to symlink %s", path)
	}
	entry := fmt.Sprintf("%s %s\n", hostname, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("wssh: cannot append to %s: %w", path, err)
	}
	defer f.Close()
	_, err = f.WriteString(entry)
	return err
}
```
No import changes (`fmt`, `os`, `strings` already imported). The residual Lstat→open TOCTOU is recorded as accepted risk in this plan's ledger.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/client/ -race -count=1`
Expected: `ok wssh/internal/client` — the new symlink test passes AND the existing append tests (`TestHostKeyUnknownAcceptNewAppends`, `TestHostKeyUnknownPromptYes`, concurrency test) still pass, proving regular files are unaffected.

- [ ] **Step 5: Commit**

```bash
git add internal/client/hostkey.go internal/client/hostkey_test.go
git commit -m "fix(client): refuse known_hosts append through symlink"
```

---

### Task 4: IPv6 support [client + known_hosts]

**Files:**
- Test: `internal/client/target_test.go` (append two test funcs)
- Test: `internal/client/hostkey_test.go` (add `errors` import; append one test func)
- Verify-only: `cmd/wsshd/main.go` (no change expected — see Step 4)

**Interfaces:**
- Consumes: `ParseTarget(s string) (*Target, error)`, `(*Target).WebSocketURL() string`, `(*Target).SSHAddr() string`, `appendKnownHost(path, hostname string, key ssh.PublicKey) error` (post-Task 3), `tcpAddr` type from hostkey_test.go, `testKey(t)`.
- Produces: no production changes. The tests PIN the IPv6 guarantees: target parsing, bracketed address forms, and the known_hosts append→`knownhosts.New` round-trip. **Round-trip was empirically verified by the plan author against `golang.org/x/crypto@v0.56.0`** (scratch test passed for `[2001:db8::1]:8080`, `[2001:db8::2]:80`, `203.0.113.5:8080`; changed keys rejected with `*knownhosts.KeyError`). If a test unexpectedly fails, fix minimally per Step 3's diagnosis rule — do NOT hand-roll the known_hosts format beyond what the round-trip demands.

- [ ] **Step 1: Append IPv6 target-parsing tests**

Append to `internal/client/target_test.go`:

```go
func TestParseTargetIPv6(t *testing.T) {
	cases := []struct {
		in   string
		want Target
	}{
		{in: "user@[::1]:8080", want: Target{Scheme: "ws", User: "user", Host: "::1", Port: 8080, Path: "/ws"}},
		{in: "wss://user@[2001:db8::1]/ws", want: Target{Scheme: "wss", User: "user", Host: "2001:db8::1", Port: 443, Path: "/ws"}},
		{in: "user@[::1]", want: Target{Scheme: "ws", User: "user", Host: "::1", Port: 80, Path: "/ws"}},
	}
	for _, tc := range cases {
		got, err := ParseTarget(tc.in)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", tc.in, err)
			continue
		}
		if *got != tc.want {
			t.Errorf("ParseTarget(%q) = %+v, want %+v", tc.in, *got, tc.want)
		}
	}
}

func TestTargetIPv6AddressForms(t *testing.T) {
	tg, err := ParseTarget("user@[::1]:8080")
	if err != nil {
		t.Fatal(err)
	}
	if got := tg.WebSocketURL(); got != "ws://[::1]:8080/ws" {
		t.Fatalf("WebSocketURL = %q, want %q", got, "ws://[::1]:8080/ws")
	}
	if got := tg.SSHAddr(); got != "[::1]:8080" {
		t.Fatalf("SSHAddr = %q, want %q", got, "[::1]:8080")
	}
	tg, err = ParseTarget("wss://user@[2001:db8::1]/ws")
	if err != nil {
		t.Fatal(err)
	}
	if got := tg.WebSocketURL(); got != "wss://[2001:db8::1]:443/ws" {
		t.Fatalf("WebSocketURL = %q, want %q", got, "wss://[2001:db8::1]:443/ws")
	}
	if got := tg.SSHAddr(); got != "[2001:db8::1]:443" {
		t.Fatalf("SSHAddr = %q, want %q", got, "[2001:db8::1]:443")
	}
}
```

(`net.JoinHostPort` brackets IPv6 hosts; `url.Parse` strips brackets in `Hostname()`. Both already work — these tests pin it.)

- [ ] **Step 2: Append known_hosts IPv6 round-trip test**

First add `errors` to the import block of `internal/client/hostkey_test.go`:
```go
import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)
```

Then append:
```go
func TestKnownHostsRoundTripIPv6AndIPv4(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, key := testKey(t)
	_, other := testKey(t)

	hostnames := []string{
		net.JoinHostPort("2001:db8::1", "8080"),
		net.JoinHostPort("2001:db8::2", "80"),
		net.JoinHostPort("203.0.113.5", "8080"),
	}
	for _, hostname := range hostnames {
		if err := appendKnownHost(kh, hostname, key); err != nil {
			t.Fatalf("append %q: %v", hostname, err)
		}
	}
	khcb, err := knownhosts.New(kh)
	if err != nil {
		t.Fatalf("knownhosts.New: %v", err)
	}
	for _, hostname := range hostnames {
		if err := khcb(hostname, tcpAddr(hostname), key); err != nil {
			t.Fatalf("entry %q rejected: %v", hostname, err)
		}
		err := khcb(hostname, tcpAddr(hostname), other)
		if err == nil {
			t.Fatalf("changed key accepted for %q", hostname)
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			t.Fatalf("changed key for %q: want *knownhosts.KeyError, got %T: %v", hostname, err, err)
		}
	}
}
```

Acceptance semantics: the entry written by `appendKnownHost` (hostname verbatim — `[2001:db8::1]:8080` for IPv6, bracketed by `net.JoinHostPort` in `SSHAddr`) must be ACCEPTED by a `knownhosts.New` callback for the same address and REJECT a changed key. Entries keep the explicit `:port` even for 80/443 because `SSHAddr()` always carries the port; the round-trip is the acceptance criterion (see Deviations #3).

- [ ] **Step 3: Run the new tests**

Run: `go test ./internal/client/ -race -run 'IPv6' -v`
Expected: PASS for `TestParseTargetIPv6`, `TestTargetIPv6AddressForms`, `TestKnownHostsRoundTripIPv6AndIPv4` — these pin existing correct behavior, so they should pass immediately (verified by the plan author).

If the round-trip test FAILS: diagnose with `go test -run TestKnownHostsRoundTripIPv6AndIPv4 -v` output comparing the written file contents against the callback hostname. The ONLY acceptable fix is in `appendKnownHost`'s `hostname` handling, and only if the round-trip demands it. Do not change `Target` parsing or `SSHAddr`.

- [ ] **Step 4: Verify server dual-stack (no code change expected)**

`cmd/wsshd/main.go` uses `net.Listen("tcp", resolvedAddr)` — on a wildcard address like `:8080` this is dual-stack (IPv4+IPv6) with no change. The rate limiter's key comes from `clientIP`, whose IPv6 peer handling (`hostFromAddr` strips `[...]`, `net.ParseIP` parses) is already covered by Task 2's `TestClientIP` cases "IPv6 trusted peer with IPv6 XFF entry" and "IPv6 untrusted peer keeps bracket-stripped host". No listener change and no new server test required — record this verification in the task log.

- [ ] **Step 5: Full suite**

Run: `go test ./... -race -count=1`
Expected: all packages `ok`.

- [ ] **Step 6: Commit**

```bash
git add internal/client/target_test.go internal/client/hostkey_test.go
git commit -m "test(client): cover IPv6 targets and known_hosts round-trip"
```

---

### Task 5: Plaintext ws:// advisory on the client [UX / safety]

**Files:**
- Create: `internal/client/note.go`
- Create: `internal/client/note_test.go`
- Modify: `cmd/wssh/main.go` (3-line insertion after target parse; `target.go` untouched)

**Interfaces:**
- Consumes: `client.Target` (field `Scheme string`); `client.ParseTarget`.
- Produces: `func PlaintextNote(t *Target) string` — returns the advisory line for `ws` scheme, `""` otherwise. No new flags, no suppression flag.

- [ ] **Step 1: Write the failing test**

Create `internal/client/note_test.go`:

```go
package client

import "testing"

func TestPlaintextNote(t *testing.T) {
	cases := []struct {
		scheme string
		want   string
	}{
		{"ws", "wssh: note: plaintext ws:// transport; SSH crypto still applies, but prefer wss:// on untrusted networks"},
		{"wss", ""},
	}
	for _, tc := range cases {
		got := PlaintextNote(&Target{Scheme: tc.scheme})
		if got != tc.want {
			t.Errorf("PlaintextNote(scheme=%q) = %q, want %q", tc.scheme, got, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/client/ -race -run TestPlaintextNote -v`
Expected: FAIL — `undefined: PlaintextNote`.

- [ ] **Step 3: Create note.go**

Create `internal/client/note.go`:

```go
package client

func PlaintextNote(t *Target) string {
	if t.Scheme == "ws" {
		return "wssh: note: plaintext ws:// transport; SSH crypto still applies, but prefer wss:// on untrusted networks"
	}
	return ""
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/client/ -race -run TestPlaintextNote -v`
Expected: PASS.

- [ ] **Step 5: Wire into cmd/wssh/main.go**

In `cmd/wssh/main.go`, after the target-parse error block:
```go
	target, err := client.ParseTarget(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "wssh: %v\n", err)
		os.Exit(2)
	}
```
insert (before `command := strings.Join(args[1:], " ")`):
```go
	if note := client.PlaintextNote(target); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}
```
(`fmt` and `os` already imported.)

- [ ] **Step 6: Build, vet, full suite**

Run: `gofmt -l . && go vet ./... && go build ./... && go test ./... -race -count=1`
Expected: clean; all packages `ok`.

- [ ] **Step 7: Commit**

```bash
git add internal/client/note.go internal/client/note_test.go cmd/wssh/main.go
git commit -m "feat(client): warn on plaintext ws:// transport"
```

---

### Task 6: Supply chain — hardened build + CI with govulncheck [build tooling]

**Files:**
- Create: `Makefile`
- Create: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `make build|test|vet|vuln|ci|clean` targets; CI workflow running vet + race tests + build + govulncheck on push/PR. This task is build tooling — verification is via commands, not unit tests.

- [ ] **Step 1: Create the Makefile**

Create `Makefile` (recipes MUST be tab-indented — verify with `cat -A Makefile | grep '^ '` returning nothing):

```makefile
SERVER := bin/wsshd
CLIENT := bin/wssh
GOBUILD := CGO_ENABLED=0 go build -trimpath -buildvcs=true -ldflags="-s -w"

.PHONY: all build test vet vuln ci clean

all: build

build:
	$(GOBUILD) -o $(SERVER) ./cmd/wsshd
	$(GOBUILD) -o $(CLIENT) ./cmd/wssh

test:
	go test ./... -race -count=1

vet:
	go vet ./...

vuln:
	govulncheck ./...

ci: vet test vuln

clean:
	rm -rf bin
```

- [ ] **Step 2: Create the CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - run: go vet ./...
      - run: go test ./... -race -count=1
      - run: go build ./...
      - run: go install golang.org/x/vuln/cmd/govulncheck@latest
      - run: govulncheck ./...
```

Note (see Deviations #2): go.mod demands `go 1.26.0`; setup-go's 1.21 + `GOTOOLCHAIN=auto` downloads the 1.26 toolchain automatically, so this workflow works as written.

- [ ] **Step 3: Verify build outputs**

Run: `make build && ls -la bin/`
Expected: `bin/wsshd` and `bin/wssh` exist.

Run: `file bin/wsshd`
Expected output contains `statically linked` (CGO_ENABLED=0), e.g.:
```
bin/wsshd: ELF 64-bit LSB executable, x86-64, ... statically linked, ...
```

- [ ] **Step 4: Verify vet + test targets**

Run: `make vet`
Expected: no output (clean).

Run: `make test`
Expected: `ok` for every package.

- [ ] **Step 5: Verify govulncheck target**

Run: `go install golang.org/x/vuln/cmd/govulncheck@latest && make vuln`
Expected: govulncheck scans all packages and exits 0 — `No vulnerabilities found.` (or an equivalent clean summary). govulncheck is installed via `go install` — it is NOT a go.mod dependency and must not appear in go.mod/go.sum as a module require.

- [ ] **Step 6: Verify the full CI target locally**

Run: `make ci`
Expected: vet → test → vuln all clean, exit 0.

- [ ] **Step 7: Clean artifacts and commit**

Run: `make clean`
Expected: `bin/` removed.

```bash
git add Makefile .github/workflows/ci.yml
git commit -m "ci: add Makefile and govulncheck CI workflow"
```

---

### Task 7: wsshd config-file support (TOML) [feature — depends on Task 2]

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Modify: `cmd/wsshd/main.go` (full rewire — complete replacement file below)
- Modify: `README.md` (Configuration section)
- Modify: `go.mod` / `go.sum` (via `go get github.com/BurntSushi/toml@v1.5.0`)

**Interfaces:**
- Consumes: ALL flags present in `cmd/wsshd/main.go` at implementation time — after Task 2 these are: `addr`, `path`, `hostkey`, `cert`, `key`, `rate`, `trusted-proxies` (plus the new `config` flag itself, which is NOT part of the overlay). Task 2's `server.Config.TrustedProxies []string`.
- Produces (in package `config`; must NOT import `internal/server`):
  - `type Overlay struct` — TOML-tagged, POINTER fields for scalars: `Addr *string` (`toml:"addr"`), `Path *string` (`toml:"path"`), `HostKey *string` (`toml:"hostkey"`), `Cert *string` (`toml:"cert"`), `Key *string` (`toml:"key"`), `Rate *float64` (`toml:"rate"`), `TrustedProxies []string` (`toml:"trusted_proxies"`; slice — nil = absent).
  - `type Config struct` — resolved runtime settings (typed, non-pointer): `Addr, Path, HostKey, Cert, Key string; Rate float64; TrustedProxies []string`.
  - `func Defaults() Config` — mirrors current flag defaults: `:8080`, `/ws`, `/etc/wssh/host_key`, `""`, `""`, `1`, nil.
  - `func Load(path string) (*Overlay, error)` — distinguishes file-not-found from parse error.
  - `func Merge(base Config, overlays ...*Overlay) Config` — nil overlays skipped; per field, later non-nil wins (left-to-right).
  - `func (c Config) Validate() error` — cert/key both-or-neither.
- Zero-value rule: `rate = 0` means DISABLE rate limiting and must survive merging — hence the `*float64` pointer.

- [ ] **Step 1: Add the dependency**

Run: `go get github.com/BurntSushi/toml@v1.5.0`
Expected output:
```
go: added github.com/BurntSushi/toml v1.5.0
```
(v1.5.0 has zero transitive dependencies — `go mod graph` shows only the direct edge. Direct module count goes 5 → 6.)

- [ ] **Step 2: Write the failing tests**

Create `internal/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeTOML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wsshd.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValidTOML(t *testing.T) {
	path := writeTOML(t, `
addr = ":9090"
path = "/ssh"
hostkey = "/tmp/host_key"
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
rate = 0
trusted_proxies = ["10.0.0.0/8", "192.168.0.0/16"]
`)
	o, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if o.Addr == nil || *o.Addr != ":9090" {
		t.Fatalf("addr = %v, want :9090", o.Addr)
	}
	if o.Path == nil || *o.Path != "/ssh" {
		t.Fatalf("path = %v, want /ssh", o.Path)
	}
	if o.HostKey == nil || *o.HostKey != "/tmp/host_key" {
		t.Fatalf("hostkey = %v, want /tmp/host_key", o.HostKey)
	}
	if o.Cert == nil || *o.Cert != "/tmp/cert.pem" {
		t.Fatalf("cert = %v, want /tmp/cert.pem", o.Cert)
	}
	if o.Key == nil || *o.Key != "/tmp/key.pem" {
		t.Fatalf("key = %v, want /tmp/key.pem", o.Key)
	}
	if o.Rate == nil || *o.Rate != 0 {
		t.Fatalf("rate = %v, want pointer to 0", o.Rate)
	}
	want := []string{"10.0.0.0/8", "192.168.0.0/16"}
	if !slices.Equal(o.TrustedProxies, want) {
		t.Fatalf("trusted_proxies = %v, want %v", o.TrustedProxies, want)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err == nil {
		t.Fatal("missing file: want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing file error = %v, want 'not found'", err)
	}
}

func TestLoadMalformedTOML(t *testing.T) {
	path := writeTOML(t, "addr = [unclosed")
	if _, err := Load(path); err == nil {
		t.Fatal("malformed TOML: want error")
	}
}

func TestMergeRateZeroIsDisableNotAbsent(t *testing.T) {
	zero := 0.0
	got := Merge(Defaults(), &Overlay{Rate: &zero})
	if got.Rate != 0 {
		t.Fatalf("Rate = %v, want 0 (rate=0 must disable, not fall back to default)", got.Rate)
	}
}

func TestMergePrecedence(t *testing.T) {
	fileAddr, cliAddr := ":1111", ":2222"
	got := Merge(Defaults(), &Overlay{Addr: &fileAddr}, &Overlay{Addr: &cliAddr})
	if got.Addr != ":2222" {
		t.Fatalf("CLI overlay should win: Addr = %q, want :2222", got.Addr)
	}
	got = Merge(Defaults(), &Overlay{Addr: &fileAddr}, nil)
	if got.Addr != ":1111" {
		t.Fatalf("file overlay should beat default: Addr = %q, want :1111", got.Addr)
	}
	got = Merge(Defaults(), nil, nil)
	if got.Addr != ":8080" {
		t.Fatalf("absent should keep default: Addr = %q, want :8080", got.Addr)
	}
}

func TestMergeTrustedProxies(t *testing.T) {
	tp := []string{"fd00::/8"}
	got := Merge(Defaults(), &Overlay{TrustedProxies: tp})
	if !slices.Equal(got.TrustedProxies, tp) {
		t.Fatalf("TrustedProxies = %v, want %v", got.TrustedProxies, tp)
	}
	if got := Merge(Defaults(), nil); got.TrustedProxies != nil {
		t.Fatalf("absent TrustedProxies = %v, want nil", got.TrustedProxies)
	}
}

func TestValidateCertKeyPairing(t *testing.T) {
	if err := (Config{Cert: "/c", Key: "/k"}).Validate(); err != nil {
		t.Fatalf("cert+key should validate: %v", err)
	}
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("neither should validate: %v", err)
	}
	if err := (Config{Cert: "/c"}).Validate(); err == nil {
		t.Fatal("cert without key should fail validation")
	}
	if err := (Config{Key: "/k"}).Validate(); err == nil {
		t.Fatal("key without cert should fail validation")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/config/ -v`
Expected: FAIL — build errors (`undefined: Load`, `undefined: Merge`, `undefined: Defaults`, `undefined: Overlay`).

- [ ] **Step 4: Create internal/config/config.go**

Create `internal/config/config.go`:

```go
package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Overlay struct {
	Addr           *string  `toml:"addr"`
	Path           *string  `toml:"path"`
	HostKey        *string  `toml:"hostkey"`
	Cert           *string  `toml:"cert"`
	Key            *string  `toml:"key"`
	Rate           *float64 `toml:"rate"`
	TrustedProxies []string `toml:"trusted_proxies"`
}

type Config struct {
	Addr           string
	Path           string
	HostKey        string
	Cert           string
	Key            string
	Rate           float64
	TrustedProxies []string
}

func Defaults() Config {
	return Config{
		Addr:    ":8080",
		Path:    "/ws",
		HostKey: "/etc/wssh/host_key",
		Rate:    1,
	}
}

func Load(path string) (*Overlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
		return nil, fmt.Errorf("cannot read config file %s: %w", path, err)
	}
	var o Overlay
	if err := toml.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("cannot parse config file %s: %w", path, err)
	}
	return &o, nil
}

func Merge(base Config, overlays ...*Overlay) Config {
	c := base
	for _, o := range overlays {
		if o == nil {
			continue
		}
		if o.Addr != nil {
			c.Addr = *o.Addr
		}
		if o.Path != nil {
			c.Path = *o.Path
		}
		if o.HostKey != nil {
			c.HostKey = *o.HostKey
		}
		if o.Cert != nil {
			c.Cert = *o.Cert
		}
		if o.Key != nil {
			c.Key = *o.Key
		}
		if o.Rate != nil {
			c.Rate = *o.Rate
		}
		if o.TrustedProxies != nil {
			c.TrustedProxies = o.TrustedProxies
		}
	}
	return c
}

func (c Config) Validate() error {
	if (c.Cert == "") != (c.Key == "") {
		return errors.New("-cert and -key must be given together")
	}
	return nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/ -race -count=1 -v`
Expected: PASS for all seven test funcs.

- [ ] **Step 6: Rewire cmd/wsshd/main.go**

Replace the ENTIRE content of `cmd/wsshd/main.go` with (this enumerates the actual flag set post-Task 2 — if any flag was added between planning and execution, add its overlay case here too):

```go
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

	"wssh/internal/config"
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
		configPath     = flag.String("config", "", "TOML config file path")
	)
	flag.Parse()
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
	hs := &http.Server{Addr: resolved.Addr, Handler: mux}

	ln, err := net.Listen("tcp", resolved.Addr)
	if err != nil {
		logger.Error("listen", "err", err)
		os.Exit(1)
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
```

Behavior preserved: cert/key both-or-neither fatal (exit 2, same message via `Validate`), host-key fatal (exit 1), listen fatal (exit 1), TLS setup, `LoadOrGenerateHostKey`, `srv.WaitTimeout(30s)` drain, Task 2's `clientIP` wiring via `server.Config.TrustedProxies`. `flag.Visit` only reports flags the user explicitly set, so `-rate 0` on the CLI lands as a non-nil `*float64` pointing at 0 (disable), while an unset `-rate` leaves the overlay field nil (default 1 applies).

- [ ] **Step 7: Format, vet, build**

Run: `gofmt -l . && go vet ./... && go build ./...`
Expected: no output.

- [ ] **Step 8: Smoke-test the three config modes**

Missing file → fatal:
```bash
go build -o /tmp/wsshd-smoke ./cmd/wsshd && /tmp/wsshd-smoke -config /nonexistent.toml; echo "exit=$?"
```
Expected: log line `config path=/nonexistent.toml err="config file not found: /nonexistent.toml"` and `exit=1`.

Valid file → resolved values + config-file log:
```bash
printf 'addr = ":18099"\npath = "/ssh"\nhostkey = "/tmp/wssh-smoke-key"\nrate = 0\n' > /tmp/wssh-smoke.toml
/tmp/wsshd-smoke -config /tmp/wssh-smoke.toml & sleep 0.5; kill %1
```
Expected log lines: `wsshd listening addr=:18099 path=/ssh tls=plain ... hostkey=/tmp/wssh-smoke-key`, then `using config file path=/tmp/wssh-smoke.toml`, and NO RemoteAddr advisory (rate=0 disables limiting).

No `-config` → byte-identical legacy behavior:
```bash
/tmp/wsshd-smoke -addr :18098 -hostkey /tmp/wssh-smoke-key2 & sleep 0.5; kill %1
```
Expected: same startup log fields as before this batch (`addr`, `path`, `tls`, `mode`, `hostkey`) plus the RemoteAddr advisory; no `using config file` line.

CLI-beats-file precedence smoke:
```bash
/tmp/wsshd-smoke -config /tmp/wssh-smoke.toml -addr :18097 & sleep 0.5; kill %1
```
Expected: `wsshd listening addr=:18097 ...` (CLI flag wins over file's `:18099`).

- [ ] **Step 9: Full suite**

Run: `go test ./... -race -count=1`
Expected: all packages `ok` (e2e and server tests do not use `-config`; behavior unchanged).

- [ ] **Step 10: Document the schema in README**

Append to `README.md`:

````markdown
## Configuration (wsshd)

`wsshd` reads an optional TOML config file via `-config PATH`. Precedence:
explicit CLI flag > config file > built-in default. Omitting `-config` keeps
pure flag behavior. A missing or malformed file passed via `-config` is a fatal
startup error.

```toml
# /etc/wssh/wsshd.toml
addr    = ":8080"
path    = "/ws"
hostkey = "/etc/wssh/host_key"
# cert  = "/etc/wssh/cert.pem"
# key   = "/etc/wssh/key.pem"
rate    = 1.0
# trusted_proxies = ["10.0.0.0/8"]
```

- `rate = 0` disables rate limiting (it is NOT treated as "unset").
- `cert` and `key` must be set together, whether via file or flags.
````

- [ ] **Step 11: Verify dependency count and tidy**

Run: `go mod tidy && grep -c '^	[a-z]' go.mod || true; go list -m all | grep -v indirect | wc -l`
Expected: direct module lines in go.mod = 6 (`coder/websocket`, `x/crypto`, `x/term`, `x/time`, `creack/pty`, `BurntSushi/toml`) plus the module line itself. `govulncheck` must NOT appear.

- [ ] **Step 12: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go cmd/wsshd/main.go README.md go.mod go.sum
git commit -m "feat(wsshd): add TOML config file with CLI overrides"
```

---

## Self-Review (performed while writing this plan)

**1. Spec coverage** — every scope item maps to a task:
- MaxAuthTries pin → Task 1 (verify-only; already at HEAD).
- `-trusted-proxies` + real-client-IP extraction, header precedence CF → X-Real-IP → XFF, parse-failure warn+skip, startup log swap, README bullet → Task 2.
- known_hosts symlink refusal + TOCTOU ledger entry → Task 3.
- IPv6 target parsing / bracketed URL+SSH addr / known_hosts round-trip / dual-stack note → Task 4 (tests only; round-trip pre-verified).
- Plaintext `ws://` advisory, no suppression flag → Task 5.
- Makefile + CI + govulncheck, static-binary verification → Task 6.
- TOML config, pointer-field `rate = 0`, `flag.Visit` CLI overlay, `Merge` precedence, `Validate`, README schema, dep 5→6 → Task 7.
- Spec deviation addendum (a)–(d) → appended to the spec file when this plan was saved.
- Out-of-scope list respected: no `/healthz`, no client config file, no env expansion/include/hot-reload/auto-discovery, burst fixed at 5, no RFC 7239, no zone IDs, no bundled Cloudflare ranges, no X-Forwarded-Proto, no transport.Dial changes, no auth/PTY/session changes.

**2. Placeholder scan** — no "TBD"/"TODO"/"add error handling"/"similar to Task N" anywhere; every code step contains complete code; every run step has expected output.

**3. Type/signature consistency** —
- `clientIP` (Task 2) is `func (s *Server) clientIP(r *http.Request) string`; call site in `WebSocketHandler` uses `ip := s.clientIP(r)` and feeds `s.limiter.Allow(ip)` — matches.
- `Config.TrustedProxies []string` (Task 2) ↔ `server.Config{TrustedProxies: proxyList}` (Task 2 main) ↔ `TrustedProxies: resolved.TrustedProxies` (Task 7 main) ↔ `Overlay.TrustedProxies []string` with `toml:"trusted_proxies"` (Task 7) — all `[]string`.
- `Merge(base Config, overlays ...*Overlay) Config` (Task 7 def) ↔ call site `config.Merge(config.Defaults(), fileOverlay, cliOverlay)` where `fileOverlay *config.Overlay` (nil-safe) and `cliOverlay *config.Overlay` — matches.
- `rate = 0`: `Overlay.Rate *float64`; `TestMergeRateZeroIsDisableNotAbsent` pins 0 ≠ absent; `flag.Visit` branch copies `*rate` into a fresh `float64` — no aliasing of flag storage.
- Ordering: Task 3 (hostkey.go) precedes Task 4 (hostkey_test.go round-trip uses hardened `appendKnownHost`); Task 2 (adds `-trusted-proxies`) precedes Task 7 (overlay enumerates it); main.go order 2 → 4 (verify-only) → 7.
- Task 4's `TestTargetIPv6AddressForms` expects `wss://[2001:db8::1]:443/ws` — `net.JoinHostPort` always emits the port; verified.
- Task 4's hostkey_test.go import block adds `errors`; `net`, `knownhosts`, `tcpAddr`, `testKey` already present.
