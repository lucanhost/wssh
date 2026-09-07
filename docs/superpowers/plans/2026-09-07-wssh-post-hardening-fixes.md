# wssh Post-Hardening Fix Batch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remediate the seven findings from the 2026-09-07 post-hardening code review (three real/latent bugs, four cleanup items) and close the test-coverage gaps (TLS e2e, fuzz targets) against the live codebase at commit `81faf35`, without breaking any existing test, flag, or behavior.

**Architecture:** Targeted edits to the existing `internal/transport`, `internal/server`, `internal/client`, and `cmd/wsshd` packages. Each fix is a self-contained task with a TDD cycle (failing test first where a behavioral test is possible; code-order / coverage tests where the fix is structural). Two fixes are structural with no observable-behavior change (tasks 4, 5), and one is a build-time map completion (task 7); those use direct implementation + full-suite verification rather than a forced red-green cycle. No new dependencies, no flag-surface changes.

**Tech Stack:** Go (go.mod currently `go 1.26.0`; floor is 1.21), `golang.org/x/crypto/ssh`, `github.com/coder/websocket` v1.8.15, `github.com/creack/pty`, `golang.org/x/term`, `golang.org/x/time`. All tests run with `-race`.

**Spec pointer:** `docs/superpowers/specs/2026-09-07-wssh-design.md` (approved design). Reference audit: `AUDIT.md` §7 (coder/websocket v1.8.15 API realities). Prior hardening plan: `docs/superpowers/plans/2026-09-07-wssh-security-hardening.md` (this batch closes out review findings on top of that work).

## Global Constraints

- Go floor 1.21 (go.mod currently declares `go 1.26.0` — do not touch go.mod; all code below is 1.21-compatible).
- Exactly the 5 pinned dependencies (`x/crypto`, `coder/websocket`, `creack/pty`, `x/term`, `x/time` + indirect `x/sys`) — NO new deps.
- coder/websocket v1.8.15 API realities (AUDIT.md §7): `NetConn(ctx, c, msgType)` ctx bounds conn lifetime (use `context.Background()` for established conns); `Dial` returns `(*Conn, *http.Response, error)` — 3 values; no `KeepAlivePingOptions`; `ssh.KeysEqual` is gone — use `bytes.Equal(k.Marshal(), pubKey.Marshal())`.
- Repo conventions: no code comments (only exception: the one comment added in Task 2); conventional commits (`fix:` / `test:` / `feat:` / `chore:`); every task ends in a commit.
- All tests must pass with `-race`; new tests follow existing style (table-driven where applicable; server tests use real loopback SSH-over-WS via existing helpers `newTestServer`/`dialTestSSH`/`currentUser`/`testSigner`/`syncBuffer`).
- CLI flag surface is FROZEN this batch — no new flags, no renamed flags, no changed defaults.
- slog for all logging; no key material or secrets in logs.
- Platform: this repo is Linux-oriented (`/etc/passwd`, `pty`, `syscall.SIG*`). All code below compiles on Linux (the test platform). Task 7 adds signals that only exist on Linux/Unix; cross-platform builds are NOT a goal this batch — do not add build tags.
- Baseline: 43 tests pass with `-race`; `go vet` and `go build` clean. Verify baseline before starting: `go test -race ./... && go vet ./...`.

---

### Task 1: Raise authorized_keys scanner buffer limit  [Medium — real bug]

**Files:**
- Modify: `internal/server/auth.go:78-91` (scanner creation in `loadAuthorizedKeys`)
- Test: `internal/server/auth_test.go` (append new test)

**Interfaces:**
- Consumes: `testSigner(t *testing.T) (ssh.Signer, string)` from `auth_test.go:18`, `newAuthServer(t, authorizedKeys string) *Server` from `auth_test.go:44`, `user.Current()`.
- Produces: unchanged signatures. `loadAuthorizedKeys(u *user.User) ([]ssh.PublicKey, error)` now tolerates authorized_keys lines up to 1 MB. The scanner buffer is 256 KB initial / 1 MB max.

Context: `bufio.NewScanner` defaults to a 64 KB max token. SSH certificates and `sk-ssh-ed25519@openssh.com` keys with many principals exceed this. On overflow, `scanner.Err()` returns `bufio.ErrTooLong` after a partial parse — `loadAuthorizedKeys` returns partial keys **and** an error, silently locking out legitimate users.

- [ ] **Step 1: Write the failing test**

Append to `internal/server/auth_test.go`:

```go
func TestLoadAuthorizedKeysLongLine(t *testing.T) {
	signer, line := testSigner(t)
	// Pad the comment field well past the 64 KB bufio.Scanner default limit
	// (100 KB line). A certificate/sk-key with many principals behaves the same.
	long := line + " " + strings.Repeat("x", 100*1024)
	s := newAuthServer(t, long+"\n")
	u, _ := user.Current()
	keys, err := s.loadAuthorizedKeys(u)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys with 100KB line: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
	if !bytes.Equal(keys[0].Marshal(), signer.PublicKey().Marshal()) {
		t.Fatal("parsed key does not match generated key")
	}
}
```

`strings` is already imported in `auth_test.go`. `bytes` is NOT — add `"bytes"` to the import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -race ./internal/server/ -run TestLoadAuthorizedKeysLongLine -v -count=1`
Expected: FAIL — `loadAuthorizedKeys with 100KB line: bufio.Scanner: token too long`, then the test aborts via `t.Fatalf`.

- [ ] **Step 3: Write minimal implementation**

In `internal/server/auth.go`, inside `loadAuthorizedKeys`, right after `scanner := bufio.NewScanner(f)`:

```go
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -race ./internal/server/ -run TestLoadAuthorizedKeysLongLine -v -count=1`
Expected: PASS — `1 key parsed, key matches`.

Run full server suite: `go test -race ./internal/server/ -count=1`
Expected: `ok wssh/internal/server`.

- [ ] **Step 5: Commit**

```bash
git add internal/server/auth.go internal/server/auth_test.go
git commit -m "fix(server): raise authorized_keys scanner buffer to 1MB

SSH certificates and sk-ed25519 keys with many principals exceed the
64KB bufio.Scanner default, causing ErrTooLong after a partial parse
that silently rejected valid users. Raise the line limit to 1MB."
```

---

### Task 2: Set websocket read limit before NetConn wrap  [Low — race window]

**Files:**
- Modify: `internal/transport/transport.go:17-41` (`Accept`, `Dial`)
- Test: `internal/transport/transport_test.go` (existing `TestReadLimitRejectsOversizedMessage` is the behavior guard; no new test needed — the ordering is verified by code review per the review finding)

**Interfaces:**
- Consumes: `websocket.Accept`, `websocket.Dial`, `websocket.NetConn` (v1.8.15 3-value `Dial`).
- Produces: unchanged `func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error)` and `func Dial(ctx context.Context, rawURL string) (net.Conn, error)`. Behavioral change: `SetReadLimit(1<<20)` now runs immediately after the handshake, before `NetConn` wraps — closing the window in which a malicious peer could push an oversized frame before the limit is enforced.

Context: `Accept`/`Dial` currently call `c.SetReadLimit(1 << 20)` AFTER `websocket.NetConn()` is constructed. Between handshake and `SetReadLimit`, the peer can already send. Moving `SetReadLimit` directly after `websocket.Accept`/`Dial` (both operate on the same `*websocket.Conn`; `NetConn` is only a wrapper) closes the race window.

- [ ] **Step 1: Reorder `SetReadLimit` in `Accept` and `Dial`**

Edit `internal/transport/transport.go`. In `Accept`, change:

```go
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	go keepalive(context.Background(), c)
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	c.SetReadLimit(1 << 20)
	return nc, nil
```

to:

```go
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	// SetReadLimit before NetConn to close race window
	c.SetReadLimit(1 << 20)
	go keepalive(context.Background(), c)
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	return nc, nil
```

In `Dial`, change:

```go
	c, _, err := websocket.Dial(ctx, rawURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	go keepalive(context.Background(), c)
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	c.SetReadLimit(1 << 20)
	return nc, nil
```

to:

```go
	c, _, err := websocket.Dial(ctx, rawURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	// SetReadLimit before NetConn to close race window
	c.SetReadLimit(1 << 20)
	go keepalive(context.Background(), c)
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	return nc, nil
```

- [ ] **Step 2: Run the existing behavior guard**

Run: `go test -race ./internal/transport/ -run TestReadLimitRejectsOversizedMessage -v -count=1`
Expected: PASS — the 1 MiB+1 read is rejected with `websocket.ErrMessageTooBig` on both directions.

- [ ] **Step 3: Run full transport suite**

Run: `go test -race ./internal/transport/ -count=1`
Expected: `ok wssh/internal/transport`.

- [ ] **Step 4: Commit**

```bash
git add internal/transport/transport.go
git commit -m "fix(transport): enforce read limit before NetConn wrap

SetReadLimit ran after NetConn() constructed its wrapper, leaving a
window between handshake and limit enforcement in which a peer could
push an oversized frame. Move SetReadLimit directly after
Accept/Dial to close the race window."
```

---

### Task 3: Stop keepalive goroutine on connection close  [Low — memory growth]

**Files:**
- Modify: `internal/transport/transport.go` (whole file: `Accept`, `Dial`, `keepalive`; add `connWithDone` type)
- Test: `internal/transport/transport_test.go` (append tests)

**Interfaces:**
- Consumes: `websocket.NetConn(context.Background(), c, websocket.MessageBinary) net.Conn` from Task 2 order.
- Produces:
  - `type connWithDone struct { net.Conn; done chan struct{}; once sync.Once }` with method `func (c *connWithDone) Close() error`.
  - `func keepalive(ctx context.Context, c *websocket.Conn, done <-chan struct{})` — signature changed: now takes a read-only `done` channel; returns when `ctx.Done()`, `done` closes, or `c.Ping` fails.
  - `Accept`/`Dial` now return `net.Conn` whose concrete type is `*connWithDone`. The unexported `done` field is visible to tests (same package `transport`).

Context: `keepalive` currently only exits when `c.Ping()` fails (next 15 s tick). If the consumer abandons the conn (or the remote dies half-open), the goroutine pings forever. Fix: `connWithDone` wraps the `net.Conn`; its `Close()` closes a `done` channel (via `sync.Once`, so double-close is safe) before closing the underlying conn. `keepalive` selects on `done`.

- [ ] **Step 1: Write the failing test**

Append to `internal/transport/transport_test.go`. The test is deterministic: it asserts the returned `net.Conn` is a `*connWithDone` whose `done` channel closes on `Close()` — no `runtime.NumGoroutine` flakiness. The keepalive-goroutine-exits-on-done behavior is guaranteed by the select in `keepalive`; the test observes the wiring that makes it fire.

```go
func TestKeepaliveExitsOnClose(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nc, err := Accept(w, r)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer nc.Close()
		io.Copy(io.Discard, nc)
	}))
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nc, err := Dial(ctx, wsURL)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	wd, ok := nc.(*connWithDone)
	if !ok {
		nc.Close()
		t.Fatalf("Dial returned %T, want *connWithDone", nc)
	}
	nc.Close()

	select {
	case <-wd.done:
	case <-time.After(1 * time.Second):
		t.Fatal("done channel not closed after net.Conn.Close(); keepalive goroutine will leak")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -race ./internal/transport/ -run TestKeepaliveExitsOnClose -v -count=1`
Expected: FAIL — compile error: `undefined: connWithDone` (or, after a stub, a type-assert failure / done-not-closed timeout).

- [ ] **Step 3: Write minimal implementation**

Rewrite `internal/transport/transport.go`:

```go
package transport

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	keepaliveInterval = 15 * time.Second
	keepaliveTimeout  = 5 * time.Second
)

func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	// SetReadLimit before NetConn to close race window
	c.SetReadLimit(1 << 20)
	done := make(chan struct{})
	go keepalive(context.Background(), c, done)
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	return &connWithDone{Conn: nc, done: done}, nil
}

func Dial(ctx context.Context, rawURL string) (net.Conn, error) {
	c, _, err := websocket.Dial(ctx, rawURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	// SetReadLimit before NetConn to close race window
	c.SetReadLimit(1 << 20)
	done := make(chan struct{})
	go keepalive(context.Background(), c, done)
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	return &connWithDone{Conn: nc, done: done}, nil
}

type connWithDone struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (c *connWithDone) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

func keepalive(ctx context.Context, c *websocket.Conn, done <-chan struct{}) {
	ticker := time.NewTicker(keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			pingCtx, cancel := context.WithTimeout(ctx, keepaliveTimeout)
			if err := c.Ping(pingCtx); err != nil {
				cancel()
				return
			}
			cancel()
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -race ./internal/transport/ -run TestKeepaliveExitsOnClose -v -count=1`
Expected: PASS — `done` closes within 1 s of `Close()`.

- [ ] **Step 5: Run full transport suite + downstream packages (type change touches every consumer)**

Run: `go test -race ./internal/transport/ ./internal/server/ ./internal/e2e/ ./internal/client/ -count=1`
Expected: `ok` for all four packages. If `internal/server` or `internal/e2e` fail, the `*connWithDone` wrapper is not behaving as a drop-in `net.Conn` — re-check that only `Close` is overridden and the embedding is correct.

- [ ] **Step 6: Commit**

```bash
git add internal/transport/transport.go internal/transport/transport_test.go
git commit -m "fix(transport): stop keepalive goroutine when conn closes

keepalive only exited when Ping failed, so an abandoned or half-open
connection leaked the goroutine forever. Wrap returned conns in
connWithDone whose Close signals a done channel that keepalive selects
on, exiting promptly and safely on double-Close via sync.Once."
```

---

### Task 4: Remove dead Config.ShutdownTimeout field  [Trivial]

**Files:**
- Modify: `internal/server/server.go:18-27` (Config struct), `:39` (Server struct), `:55-57` (default assignment in `New`), `:65` (struct literal), `:154-170` (`WaitTimeout`)
- Test: `internal/server/shutdown_test.go` (modify helper + test that referenced the field)

**Interfaces:**
- Consumes: `Config` struct (all other fields unchanged), `Wait()`/`WaitTimeout`.
- Produces: `Config` loses `ShutdownTimeout time.Duration`. `Server` loses `shutdownTimeout` field. `func (s *Server) WaitTimeout(timeout time.Duration) bool` keeps its signature but the `timeout <= 0` fallback no longer reads a stored default — it now blocks indefinitely (same as `Wait()`) when called with a non-positive timeout. Callers `cmd/wsshd/main.go` and `shutdown_test.go` always pass a positive timeout, so their behavior is unchanged.

Context: `Config.ShutdownTimeout` was added in the hardening batch but is dead: `cmd/wsshd/main.go:94-95` uses a local `const shutdownTimeout = 30 * time.Second` and never passes the config value. No test exercises the `timeout <= 0` → default path. Removing the field + the `shutdownTimeout` struct field + the default-assignment block simplifies the API.

- [ ] **Step 1: Remove the field and its wiring from `server.go`**

Edit `internal/server/server.go`:

1. Remove from the `Config` struct:

```go
	ShutdownTimeout    time.Duration
```

2. Remove from the `Server` struct:

```go
	shutdownTimeout    time.Duration
```

3. Remove from `New`:

```go
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
```

4. Remove from the `&Server{...}` literal in `New`:

```go
		shutdownTimeout:    cfg.ShutdownTimeout,
```

5. Rewrite `WaitTimeout` so a non-positive timeout means "block until drained" (same as `Wait()`), removing the `s.shutdownTimeout` read:

```go
func (s *Server) WaitTimeout(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	if timeout <= 0 {
		<-done
		return true
	}
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		s.logger.Warn("shutdown drain timed out", "timeout", timeout)
		return false
	}
}
```

- [ ] **Step 2: Update `shutdown_test.go` — remove the now-invalid field reference**

`newTestServerWithTimeout` (shutdown_test.go:76-97) set `ShutdownTimeout: timeout` in the `Config` literal. That field no longer exists. Fold its single caller back onto `newTestServer`:

Edit `internal/server/shutdown_test.go`:

1. In `TestWaitTimeoutReturnsFalseOnHungSession` (line 50), change:

```go
	shortSrv, shortWSURL := newTestServerWithTimeout(t, line, 0, 500*time.Millisecond)
```

to:

```go
	shortSrv, shortWSURL := newTestServer(t, line, 0)
```

2. Delete the now-unused `newTestServerWithTimeout` helper (lines 76-97).

Note: `TestWaitTimeoutReturnsFalseOnHungSession` passes an explicit `500 * time.Millisecond` to `WaitTimeout`, so the removed default was never load-bearing in this test — it still deterministically asserts `WaitTimeout` returns `false` while a `sleep 60` session is active.

- [ ] **Step 3: Verify compilation and behavior**

Run: `go test -race ./internal/server/ -run 'TestWait|TestShutdown' -v -count=1` (if `TestShutdown` doesn't exist, this still matches `TestWaitDrainsActiveSessions` and `TestWaitTimeoutReturnsFalseOnHungSession`)
Expected: PASS on both `TestWaitDrainsActiveSessions` and `TestWaitTimeoutReturnsFalseOnHungSession`.

Run: `go build ./...`
Expected: clean. `go vet ./...` clean.

- [ ] **Step 4: Commit**

```bash
git add internal/server/server.go internal/server/shutdown_test.go
git commit -m "chore(server): remove dead Config.ShutdownTimeout field

cmd/wsshd passes its own 30s const to WaitTimeout and never sets the
config field; no caller exercised the timeout<=0 default path.
Remove the field, struct slot and default assignment; WaitTimeout now
blocks indefinitely when given a non-positive timeout."
```

---

### Task 5: Gate proxy rate-limit warning on rate > 0  [Trivial]

**Files:**
- Modify: `cmd/wsshd/main.go:79`

**Interfaces:**
- Consumes: `*rate` flag (`flag.Float64`, default 1).
- Produces: unchanged behavior; a log line is now conditional. No function signatures change.

Context: `cmd/wsshd/main.go:79` logs the TLS-proxy rate-limiting advisory unconditionally. With `-rate 0` (rate limiting disabled) the message is misleading.

- [ ] **Step 1: Write minimal implementation**

In `cmd/wsshd/main.go`, replace:

```go
	logger.Info("rate limiting keys on RemoteAddr; if fronted by a TLS proxy, enforce rate limits at the proxy")
```

with:

```go
	if *rate > 0 {
		logger.Info("rate limiting keys on RemoteAddr; if fronted by a TLS proxy, enforce rate limits at the proxy")
	}
```

- [ ] **Step 2: Verify**

Run: `go build ./... && go vet ./...`
Expected: clean. (Logging-only change; no test.) Manual sanity check is optional: `go run ./cmd/wsshd -addr :0 -rate 0 -hostkey $(mktemp)` should not print the advisory.

- [ ] **Step 3: Commit**

```bash
git add cmd/wsshd/main.go
git commit -m "fix(wsshd): only log proxy rate-limit advisory when rate > 0"
```

---

### Task 6: Move bufio.Reader inside HostKeyCallback  [Low — latent bug]

**Files:**
- Modify: `internal/client/hostkey.go:34-76`
- Test: `internal/client/hostkey_test.go` (append test)

**Interfaces:**
- Consumes: `HostKeyOptions{KnownHostsPath string; AcceptNew bool; In io.Reader; Out io.Writer}`, `ssh.HostKeyCallback` type.
- Produces: unchanged `func HostKeyCallback(opts HostKeyOptions) ssh.HostKeyCallback`. The returned closure now creates a fresh `*bufio.Reader` per invocation instead of sharing one across invocations. For the CLI (single connection) this is behavior-neutral; it removes a data race if the callback is ever invoked concurrently in a library context.

Context: `hostkey.go:41` builds `reader := bufio.NewReader(in)` once, captured by the returned closure. If two goroutines invoke the callback concurrently (concurrent SSH clients sharing one callback), both call `reader.ReadString` on the same `*bufio.Reader` — a data race on its internal buffer. Moving construction inside the closure makes each invocation independent (the underlying `in` reader must itself be concurrency-safe, as `os.Stdin` is at the syscall level; a `bytes.Buffer` as `In` is a test-only concern).

- [ ] **Step 1: Write the failing test**

Append to `internal/client/hostkey_test.go`. The test invokes the same callback from 10 goroutines. Each invocation needs its own answer. `In` is shared, so the test uses a concurrency-safe reader: a `bytes.Reader`-backed `io.MultiReader` won't suffice for 10 distinct reads of "yes\n", so give each goroutine its own answer via a `chan string`-driven reader — but that races on the single shared `bufio.Reader` pre-fix, which is exactly what `-race` detects.

Simplest robust design: each goroutine supplies its own independent answer stream through a custom reader over a per-goroutine slice is impossible (In is fixed). Instead, use a concurrency-safe writer-side pump: `In` is an `io.PipeReader`; a pump goroutine writes one "yes\n" per callback invocation consumed. Reads from the pipe are safe; the shared `bufio.Reader` is what races. The pump writes 10 lines; each callback reads exactly one.

```go
func TestHostKeyCallbackConcurrent(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, nil, 0o600)
	_, key := testKey(t)

	pr, pw := io.Pipe()
	defer pr.Close()
	cb := HostKeyCallback(HostKeyOptions{KnownHostsPath: kh, In: pr, Out: io.Discard})

	const n = 10
	go func() {
		defer pw.Close()
		for i := 0; i < n; i++ {
			if _, err := io.WriteString(pw, "yes\n"); err != nil {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	errs := make(chan error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- cb("srv:8080", fakeAddr{}, key)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent callback: %v", err)
		}
	}
}
```

The `hostkey_test.go` import block needs `"io"` and `"sync"` added.

- [ ] **Step 2: Run test to verify it fails (data race)**

Run: `go test -race ./internal/client/ -run TestHostKeyCallbackConcurrent -v -count=1`
Expected: FAIL — `WARNING: DATA RACE` reported on the shared `bufio.Reader` (`ReadString` from concurrent goroutines), or the test errors because `bufio.Reader.ReadString` on a single reader mis-sequences answers.

- [ ] **Step 3: Write minimal implementation**

In `internal/client/hostkey.go`, inside `HostKeyCallback`, remove the line `reader := bufio.NewReader(in)` (currently line 41) and add the creation inside the returned closure as its first statement:

```go
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		reader := bufio.NewReader(in)
		if baseErr != nil {
			return baseErr
		}
		if base != nil {
			err := base(hostname, tcpAddr(hostname), key)
			if err == nil {
				return nil
			}
			var keyErr *knownhosts.KeyError
			if errors.As(err, &keyErr) && len(keyErr.Want) == 0 {
			} else {
				if errors.As(err, &keyErr) {
					return fmt.Errorf("wssh: host key for %s does not match the known_hosts entry (possible MITM); connection refused", hostname)
				}
				return fmt.Errorf("wssh: host key check failed: %w", err)
			}
		}
		if opts.AcceptNew {
			return appendKnownHost(opts.KnownHostsPath, hostname, key)
		}
		fmt.Fprintf(out, "The authenticity of host '%s' can't be established.\n", hostname)
		fmt.Fprintf(out, "%s key fingerprint is %s.\n", key.Type(), ssh.FingerprintSHA256(key))
		fmt.Fprintf(out, "Are you sure you want to continue connecting (yes/no)? ")
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return errors.New("wssh: host key verification aborted")
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		if answer != "yes" && answer != "y" {
			return errors.New("wssh: host key verification failed: user declined")
		}
		return appendKnownHost(opts.KnownHostsPath, hostname, key)
	}
```

- [ ] **Step 4: Run test to verify it passes (no race)**

Run: `go test -race ./internal/client/ -run TestHostKeyCallbackConcurrent -v -count=1`
Expected: PASS — no data race, no errors.

- [ ] **Step 5: Run full client suite**

Run: `go test -race ./internal/client/ -count=1`
Expected: `ok wssh/internal/client`.

- [ ] **Step 6: Commit**

```bash
git add internal/client/hostkey.go internal/client/hostkey_test.go
git commit -m "fix(client): create bufio.Reader per HostKeyCallback call

The callback shared one bufio.Reader across all invocations, racing if
ever used concurrently in a library context. Create the reader inside
the closure so each call is independent."
```

---

### Task 7: Complete signalNames map  [Cosmetic]

**Files:**
- Modify: `internal/server/session.go:51-63` (the `signalNames` var)
- Test: `internal/server/session_test.go` (append test)

**Interfaces:**
- Consumes: `syscall.Signal` constants (Linux).
- Produces: `signalNames map[syscall.Signal]string` gains 15 entries. Lookup site unchanged (`session.go:308`, `signalNames[waitStatus.Signal()]`). When a child is killed by a signal, the `exit-signal` channel request now carries the real name instead of a numeric fallback for the newly added signals.

Context: the map covers 11 signals; the `exit-signal` handler falls back to a decimal string for unmapped signals. Standard Linux signals `SIGCHLD`, `SIGCONT`, `SIGSTOP`, `SIGTSTP`, `SIGTTIN`, `SIGTTOU`, `SIGURG`, `SIGXCPU`, `SIGXFSZ`, `SIGVTALRM`, `SIGPROF`, `SIGWINCH`, `SIGIO`, `SIGPWR`, `SIGSYS` were missing. (`SIGSTOP`/`SIGCONT`/`SIGTSTP` etc. rarely terminate a child, but mapping them is free and makes the map exhaustive for the Linux platform this repo targets.)

- [ ] **Step 1: Write the failing test**

Append to `internal/server/session_test.go`. The current `session_test.go` imports `bytes`, `errors`, `io`, `sync`, `testing`, `time`, `golang.org/x/crypto/ssh`. Add `"syscall"` to the import block.

```go
func TestSignalNamesCoversStandardSignals(t *testing.T) {
	standard := map[syscall.Signal]string{
		syscall.SIGHUP:    "HUP",
		syscall.SIGINT:    "INT",
		syscall.SIGQUIT:   "QUIT",
		syscall.SIGILL:    "ILL",
		syscall.SIGABRT:   "ABRT",
		syscall.SIGFPE:    "FPE",
		syscall.SIGKILL:   "KILL",
		syscall.SIGSEGV:   "SEGV",
		syscall.SIGPIPE:   "PIPE",
		syscall.SIGALRM:   "ALRM",
		syscall.SIGTERM:   "TERM",
		syscall.SIGCHLD:   "CHLD",
		syscall.SIGCONT:   "CONT",
		syscall.SIGSTOP:   "STOP",
		syscall.SIGTSTP:   "TSTP",
		syscall.SIGTTIN:   "TTIN",
		syscall.SIGTTOU:   "TTOU",
		syscall.SIGURG:    "URG",
		syscall.SIGXCPU:   "XCPU",
		syscall.SIGXFSZ:   "XFSZ",
		syscall.SIGVTALRM: "VTALRM",
		syscall.SIGPROF:   "PROF",
		syscall.SIGWINCH:  "WINCH",
		syscall.SIGIO:     "IO",
		syscall.SIGPWR:    "PWR",
		syscall.SIGSYS:    "SYS",
	}
	for sig, want := range standard {
		if got := signalNames[sig]; got != want {
			t.Errorf("signalNames[%v] = %q, want %q", int(sig), got, want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -race ./internal/server/ -run TestSignalNamesCoversStandardSignals -v -count=1`
Expected: FAIL — `signalNames[17] = "" , want "CHLD"` (and one line per currently-missing signal).

- [ ] **Step 3: Write minimal implementation**

In `internal/server/session.go`, extend the map:

```go
var signalNames = map[syscall.Signal]string{
	syscall.SIGHUP:    "HUP",
	syscall.SIGINT:    "INT",
	syscall.SIGQUIT:   "QUIT",
	syscall.SIGILL:    "ILL",
	syscall.SIGABRT:   "ABRT",
	syscall.SIGFPE:    "FPE",
	syscall.SIGKILL:   "KILL",
	syscall.SIGSEGV:   "SEGV",
	syscall.SIGPIPE:   "PIPE",
	syscall.SIGALRM:   "ALRM",
	syscall.SIGTERM:   "TERM",
	syscall.SIGCHLD:   "CHLD",
	syscall.SIGCONT:   "CONT",
	syscall.SIGSTOP:   "STOP",
	syscall.SIGTSTP:   "TSTP",
	syscall.SIGTTIN:   "TTIN",
	syscall.SIGTTOU:   "TTOU",
	syscall.SIGURG:    "URG",
	syscall.SIGXCPU:   "XCPU",
	syscall.SIGXFSZ:   "XFSZ",
	syscall.SIGVTALRM: "VTALRM",
	syscall.SIGPROF:   "PROF",
	syscall.SIGWINCH:  "WINCH",
	syscall.SIGIO:     "IO",
	syscall.SIGPWR:    "PWR",
	syscall.SIGSYS:    "SYS",
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -race ./internal/server/ -run TestSignalNamesCoversStandardSignals -v -count=1`
Expected: PASS.

Run full server suite: `go test -race ./internal/server/ -count=1`
Expected: `ok wssh/internal/server`.

- [ ] **Step 5: Commit**

```bash
git add internal/server/session.go internal/server/session_test.go
git commit -m "feat(server): map all standard Linux exit signals

signalNames omitted 15 standard signals, so children killed by e.g.
SIGWINCH or SIGXCPU reported a numeric fallback in exit-signal.
Add the missing entries; test asserts full Linux coverage."
```

---

### Task 8: TLS end-to-end integration test  [Coverage gap]

**Files:**
- Test: `internal/e2e/e2e_test.go` (append helper + test)

**Interfaces:**
- Consumes: existing `startServer`-style keygen (host + client signers, `AuthorizedKeysPath` override), `server.New`, `server.WebSocketHandler`, `client.ParseTarget`, `client.RunCommand`, `websocket.Dial`/`websocket.NetConn` (v1.8.15), `crypto/tls`, `crypto/x509`.
- Produces: no production code changes. New test helper `startTLSServer(t, rate float64, burst int) (*client.Target, ssh.Signer, *x509.CertPool)` and `TestE2EExecOverTLS`.

Context: the `-cert`/`-key` (TLS/WSS) path has zero integration coverage. Production `wsshd` wraps its listener with `tls.NewListener` (cmd/wsshd/main.go:70). The in-process equivalent is `httptest.NewTLSServer`, which wraps the same handler mux in TLS and exposes its self-signed certificate. Because `transport.Dial` → `websocket.Dial` uses the default transport (system roots) and the CLI surface is frozen (no way to inject a custom TLS config through the real client), the client half of this test dials with `websocket.DialOptions{HTTPClient}` directly — the exact same v1.8.15 API `transport.Dial` uses internally — then runs the SSH handshake and `client.RunCommand`, proving SSH-over-WSS works end to end over a real TLS listener.

Do NOT spawn the real `wsshd` binary here: in non-root mode it reads the OS user's real `$HOME/.ssh/authorized_keys`, which would pollute a developer machine and is exactly why every existing test uses the `AuthorizedKeysPath` override. The override is not available on the real CLI (flags frozen).

- [ ] **Step 1: Write the failing (coverage) test — no code change, so it should pass once written**

Append to `internal/e2e/e2e_test.go`:

```go
func startTLSServer(t *testing.T, rate float64, burst int) (*client.Target, ssh.Signer, *x509.CertPool) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientSigner, err := ssh.NewSignerFromKey(clientPriv)
	if err != nil {
		t.Fatal(err)
	}
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(akPath, ssh.MarshalAuthorizedKey(clientSigner.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := server.New(server.Config{
		Signer:             hostSigner,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		Rate:               rate,
		Burst:              burst,
		AuthorizedKeysPath: func(*user.User) string { return akPath },
	})
	t.Cleanup(srv.Close)
	mux := http.NewServeMux()
	mux.Handle("/ws", srv.WebSocketHandler())
	up := httptest.NewTLSServer(mux)
	t.Cleanup(up.Close)

	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(up.Certificate())

	target, err := client.ParseTarget("wss://" + u.Username + "@" + strings.TrimPrefix(up.URL, "https://") + "/ws")
	if err != nil {
		t.Fatal(err)
	}
	return target, clientSigner, roots
}

func TestE2EExecOverTLS(t *testing.T) {
	target, signer, roots := startTLSServer(t, 0, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, target.WebSocketURL(), &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
		HTTPClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots},
		}},
	})
	if err != nil {
		t.Fatalf("wss dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	nc := websocket.NetConn(context.Background(), c, websocket.MessageBinary)
	defer nc.Close()

	cfg := &ssh.ClientConfig{
		User:            target.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, chans, reqs, err := ssh.NewClientConn(nc, target.SSHAddr(), cfg)
	if err != nil {
		t.Fatalf("ssh connect over TLS: %v", err)
	}
	defer conn.Close()
	cl := ssh.NewClient(conn, chans, reqs)
	defer cl.Close()

	var out bytes.Buffer
	if err := client.RunCommand(cl, "echo e2e-tls-ok", &out, io.Discard); err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.String() != "e2e-tls-ok\n" {
		t.Fatalf("output = %q", out.String())
	}
}
```

Add these imports to `internal/e2e/e2e_test.go` (current imports are `bytes`, `context`, `crypto/ed25519`, `crypto/rand`, `io`, `log/slog`, `net/http`, `net/http/httptest`, `os`, `os/user`, `path/filepath`, `strings`, `testing`, `time`, `golang.org/x/crypto/ssh`, `wssh/internal/client`, `wssh/internal/server`):

```go
	"crypto/tls"
	"crypto/x509"

	"github.com/coder/websocket"
```

- [ ] **Step 2: Run the test**

Run: `go test -race ./internal/e2e/ -run TestE2EExecOverTLS -v -count=1`
Expected: PASS — full SSH handshake + `echo e2e-tls-ok` executed over a real TLS WebSocket listener.

- [ ] **Step 3: Run full e2e suite**

Run: `go test -race ./internal/e2e/ -count=1`
Expected: `ok wssh/internal/e2e` (all pre-existing e2e tests still pass).

- [ ] **Step 4: Commit**

```bash
git add internal/e2e/e2e_test.go
git commit -m "test(e2e): cover SSH-over-WebSocket over TLS

The -cert/-key path had zero integration coverage. Serve the handler
behind httptest.NewTLSServer, trust its self-signed cert via a custom
root pool, and run the full SSH handshake + exec over wss."
```

---

### Task 9: Fuzz target for client.ParseTarget  [Coverage gap]

**Files:**
- Test: `internal/client/target_test.go` (append)

**Interfaces:**
- Consumes: `ParseTarget(s string) (*Target, error)`.
- Produces: `FuzzParseTarget(f *testing.F)`. Parsers must never panic on arbitrary input.

Context: `client.ParseTarget` parses user-supplied URLs. Fuzz it to guarantee no panic on malformed input (bad escapes, huge port numbers, unusual userinfo, IPv6 brackets).

- [ ] **Step 1: Write the fuzz target**

Append to `internal/client/target_test.go`:

```go
func FuzzParseTarget(f *testing.F) {
	for _, seed := range []string{
		"alice@server",
		"wss://bob@srv:8443/custom",
		"user@host:8080",
		"ws://",
		"@host",
		"user@",
		"user@host:99999",
		"user@host:0",
		"user@host:-1",
		"ftp://a@b",
		"ws://user@[::1]:8080/ws",
		"ws://user@host/%zz",
		"ws://us%2Fer@host",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseTarget(s)
	})
}
```

- [ ] **Step 2: Run seeds as a normal test**

Run: `go test -race ./internal/client/ -run FuzzParseTarget -count=1`
Expected: PASS — corpus seeds all execute without panic.

- [ ] **Step 3: Run a short fuzz campaign**

Run: `go test ./internal/client/ -run '^$' -fuzz '^FuzzParseTarget$' -fuzztime=30s`
Expected: no crash; fuzzer completes 30 s and reports no failing input. (A panic would print a crash report and a minimized reproducer.)

- [ ] **Step 4: Commit**

```bash
git add internal/client/target_test.go
git commit -m "test(client): add fuzz target for ParseTarget"
```

---

### Task 10: Fuzz target for server.loadAuthorizedKeys  [Coverage gap]

**Files:**
- Test: `internal/server/auth_test.go` (append)

**Interfaces:**
- Consumes: `loadAuthorizedKeys(u *user.User) ([]ssh.PublicKey, error)` (only reachable through a `*Server`), `discardLogger()` from `auth_test.go:31`.
- Produces: `FuzzLoadAuthorizedKeys(f *testing.F)`.

Context: `loadAuthorizedKeys` parses `authorized_keys` files. Fuzz it to guarantee no panic on arbitrary file bytes. Because it reads a file path from the `Server`'s configured `AuthorizedKeysPath`, each fuzz iteration writes the candidate bytes to a fresh temp file and calls through a minimal `Server` (signer not needed — `loadAuthorizedKeys` never touches `sshConfig`; `New` tolerates a nil signer as long as we never handshake, which this fuzz body does not).

- [ ] **Step 1: Write the fuzz target**

Append to `internal/server/auth_test.go`:

```go
func FuzzLoadAuthorizedKeys(f *testing.F) {
	_, line := fuzzKeyLine()
	for _, seed := range []string{
		"",
		"# comment only\n",
		line,
		line + " " + strings.Repeat("x", 100*1024) + "\n",
		"not a valid key\n",
		"\xff\xfe\x00garbage\n",
		strings.Repeat("A", 2*1024*1024),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, content string) {
		dir := t.TempDir()
		akPath := filepath.Join(dir, "authorized_keys")
		if err := os.WriteFile(akPath, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		s := New(Config{
			Logger:             discardLogger(),
			AuthorizedKeysPath: func(*user.User) string { return akPath },
		})
		u, err := user.Current()
		if err != nil {
			t.Skipf("user.Current: %v", err)
		}
		_, _ = s.loadAuthorizedKeys(u)
	})
}

func fuzzKeyLine() (ssh.Signer, string) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ""
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, ""
	}
	return signer, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}
```

`auth_test.go` already imports `crypto/ed25519`, `crypto/rand`, `os`, `os/user`, `path/filepath`, `strings`, `testing`, `golang.org/x/crypto/ssh`. No import changes needed.

Note: `f.Add` cannot take `[]byte` (the fuzz corpus element type must match the callback signature), so the callback signature is `func(t *testing.T, content string)` and seeds are `string`.

- [ ] **Step 2: Run seeds as a normal test**

Run: `go test -race ./internal/server/ -run FuzzLoadAuthorizedKeys -count=1`
Expected: PASS — seeds execute without panic (the 100 KB-line seed exercises the Task 1 scanner buffer path; the 2 MB-line seed exercises the >1 MB rejection path, which returns `ErrTooLong` — an error, not a panic, and the test body ignores the return).

- [ ] **Step 3: Run a short fuzz campaign**

Run: `go test ./internal/server/ -run '^$' -fuzz '^FuzzLoadAuthorizedKeys$' -fuzztime=30s`
Expected: no crash; fuzzer completes 30 s cleanly.

- [ ] **Step 4: Commit**

```bash
git add internal/server/auth_test.go
git commit -m "test(server): add fuzz target for loadAuthorizedKeys"
```

---

## Final Verification (after Task 10)

Run the full gate before declaring the batch done:

```bash
go test -race ./... -count=1
go vet ./...
go build ./...
```

Expected: all packages `ok`; vet and build clean. Confirm the commit log reads as one commit per task:

```bash
git log --oneline -12
```

---

## Self-Review Checklist

- **Spec coverage:** All 7 review findings mapped to Tasks 1-7; both coverage gaps (TLS e2e, fuzz) mapped to Tasks 8-10. Each task's commit is independently reverting-able. No task touches code outside its stated files.
- **Placeholder scan:** Every code step contains the actual, complete code; no "add error handling" or "similar to Task N" shorthand. Run commands include expected output.
- **Type/signature consistency:**
  - `keepalive` signature `(ctx, *websocket.Conn, <-chan struct{})` in Task 3 matches its two call sites (`Accept`, `Dial`) in the same Task's rewritten file; no other call sites exist.
  - `connWithDone` embeds `net.Conn` (Tasks 3 code) and therefore satisfies every consumer of `Accept`/`Dial` (`serveConn`, `client.Connect`, `dialTestSSH`) without further edits — verified by Task 3 Step 5's downstream test run.
  - `WaitTimeout(time.Duration) bool` signature unchanged across Task 4; only the `<= 0` branch semantics change, and no caller passes `<= 0`.
  - Task 2 and Task 3 both rewrite `Accept`/`Dial`; Task 3's final file includes Task 2's reorder, so executing Task 2 then Task 3 is clean (Task 3's full-file listing is authoritative).
  - Task 1's scanner fix and Task 10's fuzz seeds both touch the same `loadAuthorizedKeys`; the fuzz 100 KB seed only parses cleanly because Task 1 landed first. If tasks execute out of order, the fuzz seed still doesn't panic (error return is ignored) — no hard ordering dependency.
  - Task 6 test uses `io.Pipe`, `io.Discard`, `sync.WaitGroup`; Task 4 uses only `time` — all imports enumerated per test file.
- **Flag surface:** untouched (verified per-task; only Task 5 references `*rate` and only to gate a log line).
- **Deviations from the finding text, and why:**
  1. Task 3 test uses `done`-channel observation instead of `runtime.NumGoroutine()`. Rationale: goroutine-count polling is flaky under `-race` with parallel GC/runtime goroutines; asserting the `connWithDone.done` channel closes on `Close()` deterministically proves the leak-prevention wiring, and the select in `keepalive` makes goroutine exit immediate and unconditional once `done` closes.
  2. Task 4 removes the `ShutdownTimeout` field but MUST also edit `shutdown_test.go` — the finding said "no test change needed," but `newTestServerWithTimeout` sets `Config.ShutdownTimeout` in a composite literal, which will not compile once the field is gone. The fold-onto-`newTestServer` edit preserves the test's intent (it passes an explicit timeout to `WaitTimeout`).
  3. Task 8 does not spawn the real `wsshd` binary. Spawning it in non-root mode reads the real OS user's `~/.ssh/authorized_keys` (no `AuthorizedKeysPath` override on the CLI — flags frozen), which would write into a developer's real home directory. `httptest.NewTLSServer` exercises the identical production TLS-listener + handler + SSH path in-process with the established override pattern.
  4. Task 8's client half dials `websocket.Dial` directly rather than through `client.Connect`/`transport.Dial`, because those use the default HTTP transport (system cert roots) with no TLS-config injection point, and the CLI surface is frozen. The test uses the same v1.8.15 `DialOptions`/`NetConn` API the production dial path uses, so the transport-layer behavior under test is identical.
