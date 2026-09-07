# wssh Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the four verified security/stability fixes from the 2026-09-08 audit (StrictModes, handshake deadline, rate-limiter cap, HTTP server timeouts) plus housekeeping (LICENSE, CI go version).

**Architecture:** All fixes are localized, dependency-free changes to existing files. StrictModes adds a stat-chain gate before reading `authorized_keys`; the handshake deadline wraps the existing `serveConn`; the rate limiter gets an eviction path on its existing insert; the HTTP server gains header/idle timeouts. Spec: `docs/superpowers/specs/2026-09-08-security-hardening-design.md`.

**Tech Stack:** Go 1.26.8 (`go.mod`), `golang.org/x/crypto/ssh`, `github.com/coder/websocket`, stdlib `syscall` (Unix-only — repo already relies on Unix semantics).

## Global Constraints

- No new module dependencies (`go.mod` require blocks unchanged).
- Unix-only code is acceptable: `syscall.Stat_t` — consistent with existing `SysProcAttr` usage.
- All new failure paths fail closed and log via existing `slog` patterns (`s.authReject`-style Warn messages).
- Existing test conventions: tests live beside source (`auth_test.go`, `server_test.go`, `ratelimit_test.go`), use `t.TempDir()`, `testSigner(t)`, `discardLogger()`, `newAuthServer(t, keys)`.
- Spec-mandated behavior: `0644` keys / `0755` dirs remain legal; owner uid must be the user or `0`; handshake grace 60s; limiter cap 10000; `ReadHeaderTimeout` 10s, `IdleTimeout` 120s; deliberately **no** `ReadTimeout`/`WriteTimeout` (hijacked WS conns inherit them and live sessions die).
- `handshakeTimeout` is an unexported **var** (not const) so tests can shorten it — a deliberate, spec-noted deviation for testability.
- Verify with: `go vet ./... && go test ./... -race -count=1 && go build ./...` (CI parity: `.github/workflows/ci.yml`).

---

### Task 1: StrictModes permission checks on `authorized_keys`

**Files:**
- Modify: `internal/server/auth.go` (imports; `loadAuthorizedKeys`; new `checkStrictModes`)
- Test: `internal/server/auth_test.go`

**Interfaces:**
- Consumes: `*user.User` (fields `Uid`, `Gid`, `Username`, `HomeDir`), existing `loadAuthorizedKeys(u *user.User) ([]ssh.PublicKey, error)`.
- Produces: `checkStrictModes(u *user.User, path string) error` — unexported, package `server`. Called only from `loadAuthorizedKeys` and tests.

- [ ] **Step 1: Write the failing tests**

Append to `internal/server/auth_test.go` (existing imports already cover `os`, `os/user`, `path/filepath`, `testing`):

```go
func TestCheckStrictModes(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("user.Current: %v", err)
	}
	home := t.TempDir() // 0700, owned by current user
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "authorized_keys")

	cases := []struct {
		name     string
		fileMode os.FileMode
		dirMode  os.FileMode
		wantErr  bool
	}{
		{"key 0600 dir 0700", 0o600, 0o700, false},
		{"key 0644 dir 0755 (OpenSSH-legal)", 0o644, 0o755, false},
		{"group-writable key", 0o664, 0o700, true},
		{"world-writable key", 0o606, 0o700, true},
		{"group-writable .ssh", 0o600, 0o770, true},
		{"world-writable .ssh", 0o600, 0o707, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA test\n"), tc.fileMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(keyPath, tc.fileMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(sshDir, tc.dirMode); err != nil {
				t.Fatal(err)
			}
			u := &user.User{Uid: me.Uid, Gid: me.Gid, Username: me.Username, HomeDir: home}
			err := checkStrictModes(u, keyPath)
			if tc.wantErr && err == nil {
				t.Fatal("checkStrictModes accepted insecure permissions")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkStrictModes rejected secure permissions: %v", err)
			}
		})
	}
}

func TestCheckStrictModesGroupWritableHome(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("user.Current: %v", err)
	}
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, 0o772); err != nil {
		t.Fatal(err)
	}
	u := &user.User{Uid: me.Uid, Gid: me.Gid, Username: me.Username, HomeDir: home}
	if err := checkStrictModes(u, keyPath); err == nil {
		t.Fatal("group-writable home accepted")
	}
}

func TestCheckStrictModesOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership checks require root")
	}
	me, err := user.Current()
	if err != nil {
		t.Skipf("user.Current: %v", err)
	}
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &user.User{Uid: me.Uid, Gid: me.Gid, Username: me.Username, HomeDir: home}

	if err := os.Chown(keyPath, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := checkStrictModes(u, keyPath); err != nil {
		t.Fatalf("root-owned key rejected: %v", err)
	}

	if err := os.Chown(keyPath, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := checkStrictModes(u, keyPath); err == nil {
		t.Fatal("foreign-owned key accepted")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/ -run TestCheckStrictModes -v`
Expected: FAIL — `undefined: checkStrictModes`

- [ ] **Step 3: Implement `checkStrictModes` and wire into `loadAuthorizedKeys`**

In `internal/server/auth.go`, extend the import block to:

```go
import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)
```

Add the gate call at the top of `loadAuthorizedKeys`, directly after the path is resolved (before `os.Open`):

```go
func (s *Server) loadAuthorizedKeys(u *user.User) ([]ssh.PublicKey, error) {
	path := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	if s.authorizedKeysPath != nil {
		path = s.authorizedKeysPath(u)
	}
	if err := checkStrictModes(u, path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	// ... remainder unchanged
```

Add the new function at the end of `internal/server/auth.go`:

```go
// checkStrictModes enforces the same invariants as OpenSSH StrictModes: the
// authorized_keys file, its .ssh directory, and the user's home directory must
// be owned by the user (or root) and must not be group- or world-writable.
// Any violation is an authentication error (fail closed).
func checkStrictModes(u *user.User, path string) error {
	if u.HomeDir == "" {
		return errors.New("user has no home directory")
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid uid %q for user %q", u.Uid, u.Username)
	}
	uid := uint32(uid64)
	for _, dir := range []string{u.HomeDir, filepath.Dir(path), path} {
		fi, err := os.Stat(dir)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("permission checks unsupported on this platform (%s)", dir)
		}
		if st.Uid != uid && st.Uid != 0 {
			return fmt.Errorf("%s: owned by uid %d, want %d or root", dir, st.Uid, uid)
		}
		if perm := fi.Mode().Perm(); perm&0o022 != 0 {
			return fmt.Errorf("%s: permissions %04o allow group/other writes", dir, perm)
		}
	}
	return nil
}
```

Note: `publicKeyCallback` (auth.go:45-49) already logs and rejects on `loadAuthorizedKeys` error — no change needed there; rejection messages will now carry the StrictModes reason via `"err"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ -run TestCheckStrictModes -v && go test ./internal/server/ -count=1`
Expected: all `TestCheckStrictModes*` subtests PASS; all existing server tests still PASS (they use `t.TempDir()` with 0700/0600, current-user-owned — legal under StrictModes).

- [ ] **Step 5: Commit**

```bash
git add internal/server/auth.go internal/server/auth_test.go
git commit -m "feat: enforce StrictModes permission checks on authorized_keys"
```

---

### Task 2: Handshake deadline (Slowloris defense)

**Files:**
- Modify: `internal/server/server.go:122-131` (`serveConn`; new package-level `handshakeTimeout` var)
- Test: `internal/server/server_test.go` (new imports `net`, `sync`; new types `dummyAddr`, `stallConn`, `recordingConn`; new tests)

**Interfaces:**
- Consumes: `newAuthServer(t, keys)` from `auth_test.go` (same package); `testSigner(t)`; `user.Current()`.
- Produces: `handshakeTimeout time.Duration` — package-level var in `server`, default `60 * time.Second`, overridden by tests. `serveConn` behavior change: deadline set before `ssh.NewServerConn`, cleared (`SetDeadline(time.Time{})`) after success.

- [ ] **Step 1: Write the failing tests**

Add to the import block of `internal/server/server_test.go`: `"net"` and `"sync"`.

Append to `internal/server/server_test.go`:

```go
type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

// stallConn accepts writes, then blocks reads until the deadline set by
// serveConn expires — simulating a Slowloris client that never completes
// the SSH handshake.
type stallConn struct {
	mu        sync.Mutex
	deadline  time.Time
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *stallConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	var timer <-chan time.Time
	if !d.IsZero() {
		timer = time.After(time.Until(d))
	}
	select {
	case <-timer:
		return 0, os.ErrDeadlineExceeded
	case <-c.closed:
		return 0, net.ErrClosed
	}
}

func (c *stallConn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
		return len(b), nil
	}
}

func (c *stallConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *stallConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *stallConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *stallConn) SetDeadline(t time.Time) error      { c.mu.Lock(); c.deadline = t; c.mu.Unlock(); return nil }
func (c *stallConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *stallConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

// recordingConn records SetDeadline calls while delegating to a real conn.
type recordingConn struct {
	net.Conn
	mu       sync.Mutex
	deadline []time.Time
}

func (c *recordingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = append(c.deadline, t)
	c.mu.Unlock()
	return c.Conn.SetDeadline(t)
}

func TestServeConnHandshakeDeadline(t *testing.T) {
	s := newAuthServer(t, "")
	old := handshakeTimeout
	handshakeTimeout = 50 * time.Millisecond
	t.Cleanup(func() { handshakeTimeout = old })

	sc := &stallConn{closed: make(chan struct{})}
	s.wg.Add(1)
	done := make(chan struct{})
	go func() {
		s.serveConn(sc, "test:1")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveConn did not return after handshake deadline")
	}
	sc.mu.Lock()
	d := sc.deadline
	sc.mu.Unlock()
	if d.IsZero() {
		t.Fatal("handshake deadline was not set before ssh.NewServerConn")
	}
}

func TestServeConnClearsDeadlineAfterHandshake(t *testing.T) {
	signer, line := testSigner(t)
	s := newAuthServer(t, line)
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current: %v", err)
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	rc := &recordingConn{Conn: c1}
	s.wg.Add(1)
	go s.serveConn(rc, "test:22")

	cfg := &ssh.ClientConfig{
		User:            u.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	_ = c2.SetDeadline(time.Now().Add(10 * time.Second))
	conn, chans, reqs, err := ssh.NewClientConn(c2, "test:22", cfg)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	_ = chans // test opens no channels; closing the client ends serveConn

	cleared := func() bool {
		rc.mu.Lock()
		defer rc.mu.Unlock()
		return len(rc.deadline) > 0 && rc.deadline[len(rc.deadline)-1].IsZero()
	}
	ok := false
	for i := 0; i < 100; i++ {
		if cleared() {
			ok = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = c2.SetDeadline(time.Time{})
	if !ok {
		t.Fatal("deadline not cleared after successful handshake")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/ -run 'TestServeConn(HandshakeDeadline|ClearsDeadline)' -v`
Expected: FAIL — `undefined: handshakeTimeout`

- [ ] **Step 3: Implement the deadline in `serveConn`**

In `internal/server/server.go`, add above `serveConn` (near the `Config`/`Server` type definitions):

```go
// handshakeTimeout bounds the time allowed for the SSH handshake (version
// exchange, key exchange, and authentication), mirroring OpenSSH's
// LoginGraceTime. It is a variable so tests can shorten it.
var handshakeTimeout = 60 * time.Second
```

Replace the top of `serveConn` (server.go:122-129) with:

```go
func (s *Server) serveConn(netConn net.Conn, remoteAddr string) {
	defer s.wg.Done()
	defer netConn.Close()
	if err := netConn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		s.logger.Warn("ssh handshake deadline not set", "remote", remoteAddr, "err", err)
	}
	sconn, chans, reqs, err := ssh.NewServerConn(netConn, &s.sshConfig)
	if err != nil {
		s.logger.Warn("ssh handshake failed", "remote", remoteAddr, "err", err)
		return
	}
	_ = netConn.SetDeadline(time.Time{}) // handshake done; allow long-lived sessions
	s.logger.Info("connection authenticated", "user", sconn.User(), "remote", remoteAddr)
	// ... remainder unchanged
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ -run 'TestServeConn(HandshakeDeadline|ClearsDeadline)' -v && go test ./internal/server/ ./internal/e2e/ -count=1`
Expected: new tests PASS; existing server + e2e suites PASS (real WS handshakes complete in milliseconds, well under 60s; deadline clear leaves keepalive unaffected).

- [ ] **Step 5: Commit**

```bash
git add internal/server/server.go internal/server/server_test.go
git commit -m "feat: add handshake deadline to prevent slowloris"
```

---

### Task 3: Rate limiter entry cap

**Files:**
- Modify: `internal/transport/ratelimit.go` (new `maxEntries` const; `Allow`; new `evictLocked`)
- Test: `internal/transport/ratelimit_test.go` (add `fmt` import)

**Interfaces:**
- Consumes: existing `RateLimiter` struct (`mu`, `entries`, `rate`, `burst`, `ttl`), `rlEntry`.
- Produces: `const maxEntries = 10000`; method `evictLocked()` (caller holds `rl.mu`). No exported API changes — `NewRateLimiter` signature unchanged.

- [ ] **Step 1: Write the failing test**

Add `"fmt"` to the import block of `internal/transport/ratelimit_test.go`, then append:

```go
func TestRateLimiterCapsEntries(t *testing.T) {
	rl := NewRateLimiter(1000, 1000, time.Hour)
	defer rl.Close()
	for i := 0; i < maxEntries; i++ {
		if !rl.Allow(fmt.Sprintf("ip-%d", i)) {
			t.Fatalf("ip-%d denied before cap", i)
		}
	}
	rl.mu.Lock()
	n := len(rl.entries)
	rl.mu.Unlock()
	if n != maxEntries {
		t.Fatalf("entries = %d, want %d", n, maxEntries)
	}
	if !rl.Allow("ip-overflow") {
		t.Fatal("new IP denied at capacity")
	}
	rl.mu.Lock()
	n = len(rl.entries)
	_, oldestGone := rl.entries["ip-0"]
	rl.mu.Unlock()
	if n > maxEntries {
		t.Fatalf("map grew past cap: %d entries", n)
	}
	if !oldestGone {
		t.Fatal("oldest entry not evicted at capacity")
	}
	if !rl.Allow("ip-1") {
		t.Fatal("recently-seen entry denied after eviction")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/transport/ -run TestRateLimiterCapsEntries -v`
Expected: FAIL — `undefined: maxEntries`

- [ ] **Step 3: Implement the cap and eviction**

In `internal/transport/ratelimit.go`, add below the imports:

```go
// maxEntries bounds the per-IP entry map so spoofed or distributed sources
// cannot grow it without limit between sweeps.
const maxEntries = 10000
```

Replace `Allow` and add `evictLocked`:

```go
func (rl *RateLimiter) Allow(ip string) bool {
	if rl.rate <= 0 {
		return true
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[ip]
	if !ok {
		if len(rl.entries) >= maxEntries {
			rl.evictLocked()
		}
		e = &rlEntry{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.entries[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}

// evictLocked makes room for one new entry: it first drops entries idle past
// the TTL; if none are stale, it drops the least-recently-seen entry.
// Caller must hold rl.mu.
func (rl *RateLimiter) evictLocked() {
	cutoff := time.Now().Add(-rl.ttl)
	for ip, e := range rl.entries {
		if e.lastSeen.Before(cutoff) {
			delete(rl.entries, ip)
		}
	}
	if len(rl.entries) < maxEntries {
		return
	}
	var oldestIP string
	var oldest time.Time
	for ip, e := range rl.entries {
		if oldestIP == "" || e.lastSeen.Before(oldest) {
			oldestIP, oldest = ip, e.lastSeen
		}
	}
	delete(rl.entries, oldestIP)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/transport/ -count=1 -race`
Expected: all tests PASS (new cap test + existing burst/disabled/idle-eviction tests).

- [ ] **Step 5: Commit**

```bash
git add internal/transport/ratelimit.go internal/transport/ratelimit_test.go
git commit -m "feat: cap rate limiter entries to bound memory"
```

---

### Task 4: HTTP server timeouts

**Files:**
- Modify: `cmd/wsshd/main.go:92` (single statement; `time` already imported)

**Interfaces:**
- Consumes: nothing new.
- Produces: `http.Server` with `ReadHeaderTimeout: 10s` and `IdleTimeout: 120s`. No `ReadTimeout`/`WriteTimeout` — spec-mandated: `websocket.Accept` hijacks the conn and hijacked conns inherit `net/http` deadlines, which would kill live SSH-over-WS sessions.

- [ ] **Step 1: Apply the change**

Replace main.go line 92:

```go
	hs := &http.Server{Addr: resolved.Addr, Handler: mux}
```

with:

```go
	hs := &http.Server{
		Addr:              resolved.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
```

- [ ] **Step 2: Verify build, vet, and existing tests**

Run: `go build ./... && go vet ./... && go test ./... -count=1`
Expected: all clean. (No unit test — config-only change in `main`; covered by build + vet + full suite.)

- [ ] **Step 3: Commit**

```bash
git add cmd/wsshd/main.go
git commit -m "fix: add http.Server header/idle timeouts"
```

---

### Task 5: LICENSE + CI go version + full verification

**Files:**
- Create: `LICENSE` (MIT)
- Modify: `.github/workflows/ci.yml:10`

**Interfaces:**
- Consumes: `go.mod` (`go 1.26.8`).
- Produces: `go-version-file: go.mod` in CI so the toolchain can never drift from `go.mod`; MIT license text with copyright `lucanhost`.

- [ ] **Step 1: Create LICENSE**

Create `LICENSE` with the standard MIT text:

```text
MIT License

Copyright (c) 2026 lucanhost

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

- [ ] **Step 2: Pin CI to go.mod**

In `.github/workflows/ci.yml`, replace:

```yaml
        with:
          go-version: '1.21'
```

with:

```yaml
        with:
          go-version-file: go.mod
```

- [ ] **Step 3: Full verification (CI parity, run locally)**

Run: `go vet ./... && go test ./... -race -count=1 && go build ./...`
Expected: all clean — every package builds, vet silent, full suite green including e2e. Additionally confirm the StrictModes ownership tests skip cleanly as non-root: `go test ./internal/server/ -run TestCheckStrictModesOwnership -v` → `SKIP: ownership checks require root` (unless running as root, then PASS).

- [ ] **Step 4: Commit**

```bash
git add LICENSE .github/workflows/ci.yml
git commit -m "chore: add MIT license, pin CI go version to go.mod"
```
