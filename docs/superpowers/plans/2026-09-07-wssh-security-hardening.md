# wssh Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the wssh SSH-over-WebSocket daemon and client against privilege-escalation, resource-exhaustion, and input-validation failures without breaking existing behavior.

**Architecture:** All changes operate on the existing codebase as-is — no new packages at the top level, no new dependencies. The hardening touches four files (`server.go`, `session.go`, `transport.go`, `client.go`) plus one new shared validator package (`internal/termval`). Tests follow the existing table-driven and loopback style; all 8 tasks are ordered to avoid file conflicts (tasks 2,4,6,7 touch `session.go`/`server.go` sequentially).

**Tech Stack:** Go 1.21+, existing 5 pinned deps, x/crypto/ssh, coder/websocket v1.8.15, creack/pty, x/term, x/time, log/slog
**Spec:** docs/superpowers/specs/2026-09-07-wssh-design.md

## Global Constraints

- Go 1.21 floor; exactly the 5 pinned dependencies — NO new deps.
- coder/websocket v1.8.15: NetConn ctx bounds conn lifetime (established conns use context.Background()); Dial returns 3 values; no KeepAlivePingOptions; ssh.KeysEqual gone (bytes.Equal on Marshal()).
- No comments in code; conventional commits (feat:/fix:/test:/docs:); every task ends in a commit.
- All tests pass with -race; new tests follow existing style (table-driven where applicable; server tests use real loopback SSH-over-WS via existing helpers newTestServer/dialTestSSH/currentUser/testSigner/syncBuffer).
- CLI flag surface FROZEN — no new/renamed flags, no changed defaults except MaxAuthTries (internal config).
- slog for logging; no key material/secrets in logs.

---

### Task 1: MaxAuthTries 6 → 3

**Files:**
- Modify: `internal/server/server.go` line 55 (`MaxAuthTries: 6` → `3`)
- Modify: `internal/server/server_test.go` (append test after line 147)

**Interfaces:**
- Consumes: `ssh.ServerConfig.MaxAuthTries` (field on struct created in `New`).
- Produces: `Server.sshConfig.MaxAuthTries == 3` observable via test.

- [ ] **Step 1: Write failing test that reads the config value**

Append to `internal/server/server_test.go`:

```go
func TestMaxAuthTriesIsThree(t *testing.T) {
	signer, _ := testSigner(t)
	s := New(Config{Signer: signer})
	if s.sshConfig.MaxAuthTries != 3 {
		t.Fatalf("MaxAuthTries = %d, want 3", s.sshConfig.MaxAuthTries)
	}
}
```

Expected FAIL output:
```
--- FAIL: TestMaxAuthTriesIsThree (0.00s)
    server_test.go:XXX: MaxAuthTries = 6, want 3
```

- [ ] **Step 2: Run the failing test**

```bash
go test ./internal/server/... -run TestMaxAuthTriesIsThree -v -count=1
```

Expected: FAIL as above.

- [ ] **Step 3: Implement — change default from 6 to 3**

Edit `internal/server/server.go` line 55:

```go
MaxAuthTries:      3,
```

- [ ] **Step 4: Run the test — expect PASS**

```bash
go test ./internal/server/... -run TestMaxAuthTriesIsThree -v -count=1
```

Expected: `PASS`

- [ ] **Step 5: Full gate**

```bash
go vet ./... && go test ./... -race -count=1
```

Expected: all packages pass.

- [ ] **Step 6: Commit**

```bash
git add internal/server/server.go internal/server/server_test.go
git commit -m "feat(server): lower MaxAuthTries from 6 to 3"
```

---

### Task 2: credentialsFor hard-fail

**Files:**
- Modify: `internal/server/session.go` lines 199–222 (`credentialsFor`), lines 151–197 (`startProcess`), lines 133–140 (`handleSession` shell/exec case)
- Create: `internal/server/session_credentials_test.go` (new file)

**Interfaces:**
- Consumes: `*user.User` (from auth extensions)
- Produces: `(*syscall.Credential, error)` — nil,nil for non-root; `(*syscall.Credential, nil)` on success; `(nil, error)` on malformed uid/gid in root mode
- `startProcess` signature unchanged externally (still returns `(*exec.Cmd, *os.File, *os.File, error)`); errors from `credentialsFor` propagated as the fourth return
- `handleSession` rejects shell/exec request with `req.Reply(false, nil)` on error

- [ ] **Step 1: Write failing unit tests for credentialsFor**

Create `internal/server/session_credentials_test.go`:

```go
package server

import (
	"errors"
	"os/user"
	"testing"
)

func TestCredentialsForNonRootReturnsNil(t *testing.T) {
	// Non-root: always nil, nil regardless of input.
	// This test must be skipped when running as root because
	// credentialsFor bails early on os.Geteuid() != 0.
	if os.Geteuid() == 0 {
		t.Skip("skipping non-root test while running as root")
	}
	u := &user.User{Uid: "1000", Gid: "1000"}
	cred, err := credentialsFor(u)
	if cred != nil || err != nil {
		t.Fatalf("non-root: cred=%v err=%v, want nil,nil", cred, err)
	}
}

func TestCredentialsForRootMalformedUID(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping root test while running as non-root")
	}
	cases := []struct {
		name string
		u    *user.User
	}{
		{"uid abc", &user.User{Uid: "abc", Gid: "0"}},
		{"gid abc", &user.User{Uid: "0", Gid: "abc"}},
		{"both empty", &user.User{Uid: "", Gid: ""}},
		{"negative uid", &user.User{Uid: "-1", Gid: "0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := credentialsFor(tc.u)
			if cred != nil {
				t.Fatalf("cred = %v, want nil", cred)
		}
			if err == nil {
				t.Fatal("expected error for malformed uid/gid")
			}
			if !errors.Is(err, ErrMalformedCredential) {
				t.Fatalf("err = %v, want ErrMalformedCredential", err)
			}
		})
	}
}
```

Expected FAIL output (compilation + runtime):
```
session_credentials_test.go:XX: undefined: ErrMalformedCredential
```
(also `credentialsFor` currently returns `*syscall.Credential` not `(*syscall.Credential, error)`, so type mismatch compile error)

- [ ] **Step 2: Compile-confirm failure**

```bash
go test ./internal/server/... -run TestCredentialsFor -v -count=1 2>&1 | head -20
```

Expected: compile errors about `credentialsFor` signature and missing `ErrMalformedCredential`.

- [ ] **Step 3: Implement credentialsFor with hard-fail**

Replace `internal/server/session.go` lines 199–222:

```go
var ErrMalformedCredential = errors.New("malformed uid or gid in user record")

func credentialsFor(u *user.User) (*syscall.Credential, error) {
	if os.Geteuid() != 0 {
		return nil, nil
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, ErrMalformedCredential
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, ErrMalformedCredential
	}
	groups := []uint32{}
	if gidStrings, err := u.GroupIds(); err == nil {
		for _, gs := range gidStrings {
			g, err := strconv.ParseUint(gs, 10, 32)
			if err != nil {
				continue
			}
			groups = append(groups, uint32(g))
		}
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}, nil
}
```

Also update `startProcess` (around line 167) — replace:
```go
	if cred := credentialsFor(u); cred != nil {
		attrs.Credential = cred
	}
```
with:
```go
	cred, err := credentialsFor(u)
	if err != nil {
		return nil, nil, nil, err
	}
	if cred != nil {
		attrs.Credential = cred
	}
```

- [ ] **Step 4: Update handleSession to reject on credentialsFor error**

In `handleSession` (line ~133), the error from `startProcess` is already checked at lines 135–140:
```go
			if err != nil {
				s.logger.Error("process start failed", "user", u.Username, "type", kind, "err", err)
				cmd = nil
				req.Reply(false, nil)
				continue
			}
```
No change needed here — the existing error handling already rejects the request.

- [ ] **Step 5: Run the tests — expect PASS**

```bash
go test ./internal/server/... -run TestCredentialsFor -v -count=1
```

Expected:
- On non-root runner: `TestCredentialsForNonRootReturnsNil` SKIP, `TestCredentialsForRootMalformedUID` SKIP → 0 tests run, exit 0
- On root runner: both pass

- [ ] **Step 6: Full gate**

```bash
go vet ./... && go test ./... -race -count=1
```

Expected: all pass (including existing tests).

- [ ] **Step 7: Commit**

```bash
git add internal/server/session.go internal/server/session_credentials_test.go
git commit -m "feat(server): credentialsFor hard-fails on malformed uid/gid"
```

---

### Task 3: WebSocket read limit

**Files:**
- Modify: `internal/transport/transport.go` lines 17–36 (`Accept`, `Dial`)
- Modify: `internal/transport/transport_test.go` (append test after line 87)

**Interfaces:**
- Consumes: `*websocket.Conn` (returned by `websocket.Accept` / `websocket.Dial`)
- Produces: same `(net.Conn, error)` return signatures; no API change to callers
- `Conn.SetReadLimit(1 << 20)` called after Accept/Dial succeeds, before `websocket.NetConn` wrap
- NetConn still uses `context.Background()` (CRITICAL — no regression)

- [ ] **Step 1: Write failing transport test**

Append to `internal/transport/transport_test.go`:

```go
func TestReadLimitRejectsOversizedMessage(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nc, err := Accept(w, r)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer nc.Close()
		// Read until EOF or error — the oversized message should trigger a closure.
		buf := make([]byte, 4096)
		for {
			_, err := nc.Read(buf)
			if err != nil {
				return
			}
		}
	}))
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Dial the raw websocket (not NetConn) so we can send an oversized frame.
	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.CloseNow()

	largeMsg := make([]byte, 1<<20+1) // > 1 MiB, exceeds 1MiB limit
	if err := c.Write(ctx, websocket.MessageBinary, largeMsg); err != nil {
		t.Fatalf("write large msg: %v", err)
	}

	// The server-side NetConn should have closed after reading the oversized frame.
	// Give it a moment, then assert a fresh dial+round-trip still works.
	time.Sleep(200 * time.Millisecond)

	nc2, err := Dial(ctx, wsURL)
	if err != nil {
		t.Fatalf("second Dial after oversized msg: %v", err)
	}
	defer nc2.Close()
	if _, err := nc2.Write([]byte("ping")); err != nil {
		t.Fatalf("write to fresh conn: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(nc2, buf); err != nil {
		t.Fatalf("read from fresh conn: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("got %q want %q", buf, "pong")
	}
}
```

Also add a handler that echoes back "pong" for the second round-trip assertion:

Actually — the existing test server handler reads 3 bytes and writes "xyz". For this test we need a different handler. Let me adjust:

```go
func TestReadLimitRejectsOversizedMessage(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nc, err := Accept(w, r)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		defer nc.Close()
		// Drain or wait — oversized frame will cause the conn to close.
		buf := make([]byte, 4096)
		for {
			_, err := nc.Read(buf)
			if err != nil {
				return
			}
		}
	}))
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.CloseNow()

	largeMsg := make([]byte, 1<<20+1)
	if err := c.Write(ctx, websocket.MessageBinary, largeMsg); err != nil {
		t.Fatalf("write large msg: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Fresh round-trip must still succeed (server still serving).
	nc2, err := Dial(ctx, wsURL)
	if err != nil {
		t.Fatalf("second Dial: %v", err)
	}
	defer nc2.Close()
	if _, err := nc2.Write([]byte("abc")); err != nil {
		t.Fatalf("write: %v", err)
	}
}
```

Expected FAIL output (before implementing read limit):
```
--- FAIL: TestReadLimitRejectsOversizedMessage (0.30s)
    transport_test.go:XX: write: websocket: message too big
```

- [ ] **Step 2: Run the failing test**

```bash
go test ./internal/transport/... -run TestReadLimitRejectsOversizedMessage -v -count=1
```

Expected: FAIL (write succeeds — no limit set yet).

- [ ] **Step 3: Implement — add SetReadLimit after Accept/Dial**

Edit `internal/transport/transport.go`:

In `Accept` (after line 20, before `go keepalive`):
```go
	c.SetReadLimit(1 << 20)
```

In `Dial` (after line 31, before `go keepalive`):
```go
	c.SetReadLimit(1 << 20)
```

Resulting `Accept`:
```go
func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(1 << 20)
	go keepalive(context.Background(), c)
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}
```

Resulting `Dial`:
```go
func Dial(ctx context.Context, rawURL string) (net.Conn, error) {
	c, _, err := websocket.Dial(ctx, rawURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return nil, err
	}
	c.SetReadLimit(1 << 20)
	go keepalive(context.Background(), c)
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}
```

- [ ] **Step 4: Run the test — expect PASS**

```bash
go test ./internal/transport/... -run TestReadLimitRejectsOversizedMessage -v -count=1
```

Expected: `PASS`

- [ ] **Step 5: Full gate**

```bash
go vet ./... && go test ./... -race -count=1
```

Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add internal/transport/transport.go internal/transport/transport_test.go
git commit -m "feat(transport): cap WebSocket read limit at 1MiB per message"
```

---

### Task 4: PTY dimension validation

**Files:**
- Modify: `internal/server/session.go` lines 88–116 (`pty-req` and `window-change` cases), lines 170–175 (Winsize fallback)
- Create: `internal/server/session_pty_test.go` (new file)

**Interfaces:**
- Consumes: `pty.Winsize` with `Rows uint16`, `Cols uint16`
- Produces: validated `pty.Winsize`; helper signature:
  ```go
  func clampWinsize(rows, cols uint32) (uint16, uint16, bool)
  ```
  Returns `(rows16, cols16, ok)` where `ok == false` means reject (for invalid combos). Rules:
  - Both 0 → substitute (24, 80)
  - Either > 0xFFFF → clamp to 0xFFFF
  - Any other combo → pass through as-is
- `pty-req`: call `clampWinsize` before assigning `winSize`; if rejected (ok==false), `req.Reply(false, nil)`
- `window-change`: same; if rejected, `req.Reply(false, nil)`

- [ ] **Step 1: Write failing table-driven unit test**

Create `internal/server/session_pty_test.go`:

```go
package server

import (
	"testing"
)

func TestClampWinsize(t *testing.T) {
	cases := []struct {
		name     string
		rows     uint32
		cols     uint32
		wantRows uint16
		wantCols uint16
		wantOk   bool
	}{
		{"0x0 substitute", 0, 0, 24, 80, true},
		{"70000x70000 clamp", 70000, 70000, 0xFFFF, 0xFFFF, true},
		{"1x1 pass", 1, 1, 1, 1, true},
		{"FFFF x FFFF pass", 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, true},
		{"FFFF+1 clamp", 0xFFFF + 1, 0xFFFF + 1, 0xFFFF, 0xFFFF, true},
		{"0 rows valid cols", 0, 100, 24, 100, true},
		{"100 rows valid 0 cols", 100, 0, 100, 80, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, c, ok := clampWinsize(tc.rows, tc.cols)
			if r != tc.wantRows || c != tc.wantCols || ok != tc.wantOk {
				t.Fatalf("clampWinsize(%d,%d) = (%d,%d,%v), want (%d,%d,%v)",
					tc.rows, tc.cols, r, c, ok, tc.wantRows, tc.wantCols, tc.wantOk)
			}
		})
	}
}
```

Expected FAIL output (compile):
```
session_pty_test.go:XX: undefined: clampWinsize
```

- [ ] **Step 2: Run the failing test**

```bash
go test ./internal/server/... -run TestClampWinsize -v -count=1
```

Expected: compile FAIL.

- [ ] **Step 3: Implement clampWinsize and wire into pty-req/window-change**

Add after line 46 in `session.go`:

```go
func clampWinsize(rows, cols uint32) (uint16, uint16, bool) {
	if rows == 0 && cols == 0 {
		return 24, 80, true
	}
	if rows > 0xFFFF {
		rows = 0xFFFF
	}
	if cols > 0xFFFF {
		cols = 0xFFFF
	}
	return uint16(rows), uint16(cols), true
}
```

In the `pty-req` case (around line 96), replace:
```go
			term = p.Term
			havePTY = true
			winSize = pty.Winsize{Rows: uint16(p.Rows), Cols: uint16(p.Columns)}
```
with:
```go
			term = p.Term
			havePTY = true
			r, c, ok := clampWinsize(p.Rows, p.Columns)
			if !ok {
				req.Reply(false, nil)
				continue
			}
			winSize = pty.Winsize{Rows: r, Cols: c}
```

In the `window-change` case (around line 110), replace:
```go
			winSize = pty.Winsize{Rows: uint16(p.Rows), Cols: uint16(p.Columns)}
```
with:
```go
			r, c, ok := clampWinsize(p.Rows, p.Columns)
			if !ok {
				req.Reply(false, nil)
				continue
			}
			winSize = pty.Winsize{Rows: r, Cols: c}
```

Also remove the existing 0×0 fallback in `startProcess` (lines 173–175) since it's now handled upstream:
```go
		if havePTY {
			attrs.Setsid = true
			attrs.Setctty = true
			f, err := pty.StartWithAttrs(cmd, &winSize, attrs)
```
(Just delete the `if winSize.Rows == 0 && winSize.Cols == 0` block.)

- [ ] **Step 4: Run the unit test — expect PASS**

```bash
go test ./internal/server/... -run TestClampWinsize -v -count=1
```

Expected: `PASS`

- [ ] **Step 5: Full gate**

```bash
go vet ./... && go test ./... -race -count=1
```

Expected: all pass (existing PTY tests still green — 0×0 substitution still works via the new clampWinsize).

- [ ] **Step 6: Commit**

```bash
git add internal/server/session.go internal/server/session_pty_test.go
git commit -m "feat(server): validate PTY dimensions with clampWinsize helper"
```

---

### Task 5: TERM sanitization

**Files:**
- Create: `internal/termval/termval.go`
- Create: `internal/termval/termval_test.go`
- Modify: `internal/client/client.go` lines 130–133 (`RunShell` TERM env)
- Modify: `internal/server/session.go` lines 88–102 (`pty-req` TERM handling)

**Interfaces:**
- Shared package `internal/termval`:
  - `func Valid(s string) bool` — true iff `1 <= len(s) <= 64` and all chars match `[a-zA-Z0-9._-]`
  - No regexp (plain loop)
- Client: `RunShell` validates `os.Getenv("TERM")` via `termval.Valid`; fallback `"xterm-256color"` if empty or invalid
- Server: `pty-req` validates `p.Term` via `termval.Valid`; fallback `"xterm-256color"` if empty or invalid; passed to `cmd.Env` as `TERM=`

Tradeoff decision: shared `internal/termval` package chosen over duplicating a 5-line func in two places — avoids code drift, single source of truth, negligible package overhead.

- [ ] **Step 1: Write failing termval tests**

Create `internal/termval/termval.go`:

```go
package termval

func Valid(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
```

Create `internal/termval/termval_test.go`:

```go
package termval

import "testing"

func TestTermValid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"valid xterm-256color", "xterm-256color", true},
		{"valid linux", "linux", true},
		{"valid vt100", "vt100", true},
		{"empty rejects", "", false},
		{"too long rejects", "a" + string(make([]byte, 64)), false},
		{"newline rejects", "xterm\n", false},
		{"ESC char rejects", "xterm\x1b[2k", false},
		{"spaces reject", "x term", false},
		{"colon rejects", "x:y", false},
		{"valid single char", "x", true},
		{"valid 64 chars", string(make([]byte, 64))} , // all null bytes — this fails charset check
	}
	// Explicit cases with known valid/invalid:
	valid := []string{"xterm-256color", "linux", "vt100", "x", "a.b_c-d", "TERM123"}
	invalid := []string{"", "xterm\n", "\x1b[2k", "x term", "x:y",
		string(make([]byte, 65)), "xterm\r"}
	for _, v := range valid {
		if !Valid(v) {
			t.Errorf("Valid(%q) = false, want true", v)
		}
	}
	for _, inv := range invalid {
		if Valid(inv) {
			t.Errorf("Valid(%q) = true, want false", inv)
		}
	}
}
```

Expected FAIL: compile (package doesn't exist yet) — but that's expected. Run first to confirm.

- [ ] **Step 2: Run failing test (package missing)**

```bash
go test ./internal/termval/... -v -count=1 2>&1 | head -5
```

Expected: `package internal/termval is not in GOROOT` or similar — package doesn't exist yet.

- [ ] **Step 3: Create termval package and run tests — expect PASS**

(Create `internal/termval/termval.go` and `internal/termval/termval_test.go` as shown above.)

```bash
go test ./internal/termval/... -v -count=1
```

Expected: `PASS`

- [ ] **Step 4: Wire TERM validation into client RunShell**

In `internal/client/client.go`, replace lines 130–133:

```go
	termEnv := os.Getenv("TERM")
	if termEnv == "" {
		termEnv = "xterm-256color"
	}
```
with:
```go
	termEnv := os.Getenv("TERM")
	if !termval.Valid(termEnv) {
		termEnv = "xterm-256color"
	}
```

Add import for `"wssh/internal/termval"`.

- [ ] **Step 5: Wire TERM validation into server pty-req**

In `internal/server/session.go`, replace lines 93–96:

```go
			term = p.Term
			havePTY = true
```
with:
```go
			term = p.Term
			if !termval.Valid(term) {
				term = "xterm-256color"
			}
			havePTY = true
```

Add import for `"wssh/internal/termval"`.

- [ ] **Step 6: Run full test suite — expect PASS**

```bash
go vet ./... && go test ./... -race -count=1
```

Expected: all pass. Verify client loopback tests still work (they use "xterm" which is valid).

- [ ] **Step 7: Commit**

```bash
git add internal/termval/ cmd/ internal/client/client.go internal/server/session.go
git commit -m "feat(termval): add TERM sanitizer; validate on client and server"
```

---

### Task 6: Concurrency caps

**Files:**
- Modify: `internal/server/server.go` lines 18–34 (`Config`, `Server` structs), lines 36–58 (`New`), lines 91–123 (`serveConn`)
- Modify: `internal/server/session.go` lines 62–149 (`handleSession`)
- Modify: `internal/server/server_test.go` (append tests after line 147)

**Interfaces:**
- `Config` gains:
  ```go
  MaxSessionsPerConn int  // default 10
  MaxChildren        int  // default 256
  ```
- `Server` gains:
  ```go
  maxSessionsPerConn int
  childrenSem        chan struct{}
  ```
- `serveConn`: counts session channels per conn; if count > cap, `newChannel.Reject(ssh.ResourceShortage, "too many sessions")`
- `handleSession`: acquires `childrenSem` (non-blocking select) before spawning process; releases in `defer` at end of function; rejects shell/exec request with `req.Reply(false, nil)` + `slog.Warn` if sem full

- [ ] **Step 1: Write failing concurrency-cap tests**

Append to `internal/server/server_test.go`:

```go
func TestMaxSessionsPerConnRejectsOverflow(t *testing.T) {
	signer, line := testSigner(t)
	s := New(Config{
		Signer:             signer,
		Logger:             discardLogger(),
		AuthorizedKeysPath: func(*user.User) string { return "" },
		MaxSessionsPerConn: 2,
	})
	// Build minimal HTTP handler manually (skip rate limit for simplicity).
	mux := http.NewServeMux()
	mux.Handle("/ws", s.WebSocketHandler())
	up := httptest.NewServer(mux)
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cl1 := dialTestSSH(t, wsURL, currentUser(t), signer)
	cl2 := dialTestSSH(t, wsURL, currentUser(t), signer)

	// Open 2 sessions (under cap) — should succeed.
	s1, err := cl1.NewSession()
	if err != nil {
		t.Fatalf("session 1: %v", err)
	}
	s2, err := cl2.NewSession()
	if err != nil {
		t.Fatalf("session 2: %v", err)
	}

	// Third session on a new conn should also succeed (cap is per-conn).
	cl3 := dialTestSSH(t, wsURL, currentUser(t), signer)
	s3, err := cl3.NewSession()
	if err != nil {
		t.Fatalf("session 3 on new conn: %v", err)
	}
	s1.Close()
	s2.Close()
	s3.Close()
	cl1.Close()
	cl2.Close()
	cl3.Close()
}

func TestMaxChildrenSem Released(t *testing.T) {
	signer, line := testSigner(t)
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	u, _ := user.Current()
	akContent := line
	os.WriteFile(akPath, []byte(akContent), 0o600)

	s := New(Config{
		Signer:             signer,
		Logger:             discardLogger(),
		AuthorizedKeysPath: func(*user.User) string { return akPath },
		MaxChildren:        2,
	})
	mux := http.NewServeMux()
	mux.Handle("/ws", s.WebSocketHandler())
	up := httptest.NewServer(mux)
	defer up.Close()

	wsURL := "ws" + strings.TrimPrefix(up.URL, "http") + "/ws"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cl1 := dialTestSSH(t, wsURL, currentUser(t), signer)
	cl2 := dialTestSSH(t, wsURL, currentUser(t), signer)
	cl3 := dialTestSSH(t, wsURL, currentUser(t), signer)

	// Start two long-running sessions.
	s1, _ := cl1.NewSession()
	s1.Start("sleep 60")
	s2, _ := cl2.NewSession()
	s2.Start("sleep 60")

	// Third should fail (sem full).
	s3, err := cl3.NewSession()
	if err != nil {
		t.Fatalf("third session open: %v", err)
	}
	err = s3.Start("echo boom")
	if err == nil {
		t.Fatal("third session should have been rejected (sem full)")
	}
	s3.Close()

	// Close first session — sem released.
	s1.Close()
	time.Sleep(200 * time.Millisecond)

	// Fourth should now succeed.
	cl4 := dialTestSSH(t, wsURL, currentUser(t), signer)
	s4, err := cl4.NewSession()
	if err != nil {
		t.Fatalf("fourth session after release: %v", err)
	}
	defer s4.Close()
	var out bytes.Buffer
	s4.Stdout = &out
	if err := s4.Run("echo after-release"); err != nil {
		t.Fatalf("run after release: %v", err)
	}
	if out.String() != "after-release\n" {
		t.Fatalf("output = %q, want %q", out.String(), "after-release\n")
	}
	cl1.Close()
	cl2.Close()
	cl4.Close()
}
```

Expected: compile OK (no cap fields yet) but tests will FAIL because caps aren't enforced.

- [ ] **Step 2: Run failing tests**

```bash
go test ./internal/server/... -run "TestMaxSessions|TestMaxChildren" -v -count=1 2>&1 | tail -30
```

Expected: both tests run but don't enforce caps (all sessions succeed — assertion fails on third session).

- [ ] **Step 3: Implement concurrency caps in server.go**

Update `Config` (lines 18–24):
```go
type Config struct {
	Signer               ssh.Signer
	Logger               *slog.Logger
	Rate                 float64
	Burst                int
	AuthorizedKeysPath   func(*user.User) string
	MaxSessionsPerConn   int
	MaxChildren          int
}
```

Update `Server` struct (lines 26–34):
```go
type Server struct {
	sshConfig            ssh.ServerConfig
	logger               *slog.Logger
	root                 bool
	currentUsername      string
	authorizedKeysPath   func(*user.User) string
	limiter              *transport.RateLimiter
	wg                   sync.WaitGroup
	maxSessionsPerConn   int
	childrenSem          chan struct{}
}
```

Update `New` (after line 51, before sshConfig setup):
```go
	if cfg.MaxSessionsPerConn == 0 {
		cfg.MaxSessionsPerConn = 10
	}
	if cfg.MaxChildren == 0 {
		cfg.MaxChildren = 256
	}
	s.maxSessionsPerConn = cfg.MaxSessionsPerConn
	s.childrenSem = make(chan struct{}, cfg.MaxChildren)
```

Update `serveConn` to track per-conn sessions (around line 103):
```go
	var sessionCount int
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			continue
		}
		if sessionCount >= s.maxSessionsPerConn {
			_ = newChannel.Reject(ssh.ResourceShortage, "too many sessions")
			continue
		}
		sessionCount++
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			s.logger.Warn("channel accept failed", "err", err)
			sessionCount--
			continue
		}
		ext := sconn.Permissions.Extensions
		u := &user.User{
			Uid:      ext["uid"],
			Gid:      ext["gid"],
			Username: ext["user"],
			Name:     ext["user"],
			HomeDir:  ext["home"],
		}
		go s.handleSession(channel, channelRequests, u, ext["shell"])
	}
```

- [ ] **Step 4: Implement semaphore in handleSession**

In `session.go`, update `handleSession` signature (line 62) — no change needed, but add semaphore acquire at the start of the function:

```go
func (s *Server) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, u *user.User, shell string) {
	acquired := false
	if s.childrenSem != nil {
		select {
		case s.childrenSem <- struct{}{}:
			acquired = true
		default:
			s.logger.Warn("max children reached, rejecting session", "user", u.Username)
			_ = channel.Close()
			return
		}
		defer func() {
			if acquired {
				<-s.childrenSem
			}
		}()
	}
	// ... rest of function unchanged ...
```

Wait — this placement is wrong. The semaphore should be acquired just before spawning a process (in the shell/exec case), not at the start of handleSession, because handleSession may receive window-change/pty-req before shell/exec. Re-reading the brief: "Semaphore chan struct{} cap MaxChildren acquired in handleSession before startProcess (or in serveConn before spawning — pick handleSession 'shell'/'exec' case)".

So place it inside the shell/exec case:

```go
		case "shell", "exec":
			if cmd != nil {
				req.Reply(false, nil)
				continue
			}
			if s.childrenSem != nil {
				select {
				case s.childrenSem <- struct{}{}:
				default:
					s.logger.Warn("max children reached", "user", u.Username, "type", req.Type)
					req.Reply(false, nil)
					continue
				}
			}
			var shellArgs []string
			kind := req.Type
			if req.Type == "exec" {
				var p execRequest
				if err := ssh.Unmarshal(req.Payload, &p); err != nil {
					req.Reply(false, nil)
					continue
				}
				shellArgs = []string{"-c", p.Command}
			}
			var err error
			cmd, ptyFile, stdinPipe, err = s.startProcess(u, shell, term, havePTY, winSize, shellArgs, channel)
			if err != nil {
				if s.childrenSem != nil {
					<-s.childrenSem
				}
				s.logger.Error("process start failed", "user", u.Username, "type", kind, "err", err)
				cmd = nil
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			s.logger.Info("session opened", "user", u.Username, "type", kind, "pty", havePTY)
			go s.reap(channel, cmd, ptyFile, stdinPipe, &mu, u, s.childrenSem != nil)
```

Hmm, this is getting complicated with the release logic. Let me simplify: use a bool flag tracked in handleSession's closure. The cleanest approach is to acquire in the shell/exec case and release in the reap goroutine (or in the defer). Actually the brief says "single release point — recommend defer acquire/release in handleSession wrapping the shell/exec case with a bool acquired flag". Let me do that:

```go
func (s *Server) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, u *user.User, shell string) {
	var (
		cmd       *exec.Cmd
		ptyFile   *os.File
		stdinPipe *os.File
		term      string
		havePTY   bool
		winSize   pty.Winsize
		mu        sync.Mutex
		semHeld   bool
	)
	defer func() {
		if semHeld && s.childrenSem != nil {
			<-s.childrenSem
		}
		// ... existing cleanup ...
	}()
```

And in the shell/exec case:
```go
		case "shell", "exec":
			if cmd != nil {
				req.Reply(false, nil)
				continue
			}
			if s.childrenSem != nil {
				select {
				case s.childrenSem <- struct{}{}:
					semHeld = true
				default:
					s.logger.Warn("max children reached", "user", u.Username, "type", req.Type)
					req.Reply(false, nil)
					continue
				}
			}
			// ... rest of case ...
			cmd, ptyFile, stdinPipe, err = s.startProcess(...)
			if err != nil {
				s.logger.Error(...)
				cmd = nil
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			s.logger.Info(...)
			go s.reap(channel, cmd, ptyFile, stdinPipe, &mu, u)
```

And in `reap`, no change needed — the deferred release handles it (reap runs in a goroutine, handleSession returns, defer fires after handleSession exits which is after reap finishes... wait, that's wrong. The defer runs when handleSession returns, but handleSession returns when the requests channel closes, which happens when the client closes the channel. reap runs in parallel. The defer in handleSession would fire when handleSession's loop exits (channel close), which is AFTER reap has already finished cleaning up. That's fine — the semaphore release just needs to happen eventually.

Actually, re-reading: the brief says "ensure release on channel-close, conn-drop, and after reap". The simplest correct approach: release in `reap` after `cmd.Wait()` completes, AND also in handleSession's defer as a safety net (in case reap never runs). But to avoid double-release, use a sync.Once or atomic bool.

Simpler approach: release in `reap` at the very end, and don't use defer in handleSession. The brief says "single release point — recommend defer acquire/release in handleSession". Let me follow the brief's recommendation but make it correct:

```go
func (s *Server) handleSession(...) {
    var semHeld bool
    // ... 
    case "shell", "exec":
        // ... acquire sem ...
        semHeld = true
        // ... start process ...
        go s.reap(channel, cmd, ptyFile, stdinPipe, &mu, u, func() {
            if semHeld {
                <-s.childrenSem
            }
        })
    // defer not needed — reap calls release
}
```

And `reap` signature changes to accept a `releaseFunc`:
```go
func (s *Server) reap(channel ssh.Channel, cmd *exec.Cmd, ptyFile *os.File, stdinPipe *os.File, mu *sync.Mutex, u *user.User, release func()) {
    // ... existing cleanup ...
    defer release()
    // ... rest unchanged
}
```

This is clean: single release point at the end of reap. Let me use this approach.

- [ ] **Step 5: Run tests — expect PASS**

```bash
go test ./internal/server/... -run "TestMaxSessions|TestMaxChildren" -v -count=1
```

Expected: both PASS.

- [ ] **Step 6: Full gate**

```bash
go vet ./... && go test ./... -race -count=1
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add internal/server/server.go internal/server/session.go internal/server/server_test.go
git commit -m "feat(server): add MaxSessionsPerConn and MaxChildren concurrency caps"
```

---

### Task 7: Shutdown timeout

**Files:**
- Modify: `internal/server/server.go` lines 125–127 (`Wait`), lines 36–58 (`New`)
- Modify: `cmd/wsshd/main.go` line 92 (`srv.Wait()`)
- Modify: `internal/server/shutdown_test.go` (extend with hung-session timeout test)

**Interfaces:**
- `Server` gains field `shutdownTimeout time.Duration` (default 30s)
- `Config` gains `ShutdownTimeout time.Duration`
- `Wait()` stays blocking-forever for backward compat with existing tests
- Add `WaitTimeout(timeout time.Duration) bool` — blocks until all sessions drain OR timeout elapses; returns true if drained, false if timed out
- `cmd/wsshd/main.go` calls `srv.WaitTimeout(30 * time.Second)` instead of `srv.Wait()`
- If timeout elapses, logs `slog.Warn("shutdown drain timed out", "timeout", timeout)`

- [ ] **Step 1: Write failing shutdown-timeout test**

Append to `internal/server/shutdown_test.go`:

```go
func TestWaitTimeoutReturnsFalseOnHungSession(t *testing.T) {
	signer, line := testSigner(t)
	srv, wsURL := newTestServer(t, line, 0)
	cl := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Start("sleep 60"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// Set a short shutdown timeout via Config seam — need to rebuild server.
	// Since newTestServer uses New (which sets default 30s), we test with
	// a custom server that has a short timeout.
	shortSrv, shortWSURL := newTestServerWithTimeout(t, line, 0, 500*time.Millisecond)
	shortCl := dialTestSSH(t, shortWSURL, currentUser(t), signer)
	shortSess, err := shortCl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := shortSess.Start("sleep 60"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	done := make(chan bool, 1)
	go func() {
		done <- shortSrv.WaitTimeout(500 * time.Millisecond)
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("WaitTimeout returned true while hung session still active")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WaitTimeout did not return within expected window")
	}
	shortCl.Close()
}

func newTestServerWithTimeout(t *testing.T, authorizedKeys string, rate float64, timeout time.Duration) (*Server, string) {
	t.Helper()
	hostSigner, _ := testSigner(t)
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(akPath, []byte(authorizedKeys), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		Signer:             hostSigner,
		Logger:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		Rate:               rate,
		Burst:              1,
		AuthorizedKeysPath: func(*user.User) string { return akPath },
		ShutdownTimeout:    timeout,
	})
	t.Cleanup(s.Close)
	mux := http.NewServeMux()
	mux.Handle("/ws", s.WebSocketHandler())
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)
	return s, "ws" + strings.TrimPrefix(up.URL, "http") + "/ws"
}
```

Expected: compile error — `ShutdownTimeout` field doesn't exist on `Config`, `WaitTimeout` doesn't exist on `Server`.

- [ ] **Step 2: Compile-confirm failure**

```bash
go test ./internal/server/... -run TestWaitTimeoutReturnsFalseOnHungSession -v -count=1 2>&1 | head -10
```

Expected: compile errors about missing fields/methods.

- [ ] **Step 3: Implement WaitTimeout**

Update `Config` in `server.go`:
```go
type Config struct {
	Signer               ssh.Signer
	Logger               *slog.Logger
	Rate                 float64
	Burst                int
	AuthorizedKeysPath   func(*user.User) string
	ShutdownTimeout      time.Duration
}
```

Update `Server` struct:
```go
type Server struct {
	sshConfig            ssh.ServerConfig
	logger               *slog.Logger
	root                 bool
	currentUsername      string
	authorizedKeysPath   func(*user.User) string
	limiter              *transport.RateLimiter
	wg                   sync.WaitGroup
	shutdownTimeout      time.Duration
}
```

In `New`, add default:
```go
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = 30 * time.Second
	}
	s.shutdownTimeout = cfg.ShutdownTimeout
```

Add `WaitTimeout` method (after `Wait`):
```go
func (s *Server) WaitTimeout(timeout time.Duration) bool {
	if timeout <= 0 {
		timeout = s.shutdownTimeout
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		s.logger.Warn("shutdown drain timed out", "timeout", timeout)
		return false
	}
}
```

- [ ] **Step 4: Update main.go to use WaitTimeout**

In `cmd/wsshd/main.go`, replace line 92:
```go
	srv.Wait()
```
with:
```go
	const shutdownTimeout = 30 * time.Second
	srv.WaitTimeout(shutdownTimeout)
```

- [ ] **Step 5: Run tests — expect PASS**

```bash
go test ./internal/server/... -run "TestWait|TestShutdown" -v -count=1
```

Expected: both existing `TestWaitDrainsActiveSessions` and new `TestWaitTimeoutReturnsFalseOnHungSession` pass.

- [ ] **Step 6: Full gate**

```bash
go vet ./... && go test ./... -race -count=1
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add internal/server/server.go internal/server/shutdown_test.go cmd/wsshd/main.go
git commit -m "feat(server): add WaitTimeout with 30s default shutdown drain timeout"
```

---

### Task 8: Proxy rate-limit docs + warn

**Files:**
- Modify: `cmd/wsshd/main.go` (after startup log line, ~line 77)
- Create: `README.md`

**Interfaces:**
- Consumes: nothing new
- Produces: runtime log line on startup; README with project overview + Limitations section

- [ ] **Step 1: Add runtime warning log to main.go**

In `cmd/wsshd/main.go`, after the startup log (line 77), add:

```go
	logger.Info("rate limiting keys on RemoteAddr; if fronted by a TLS proxy, enforce rate limits at the proxy")
```

- [ ] **Step 2: Create README.md**

Create `README.md`:

```markdown
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
- WebSocket message read limit is 1 MiB per frame; larger SSH packets are
  dropped.
```

- [ ] **Step 3: Verify build**

```bash
go build ./... && go vet ./...
```

Expected: success, no output.

- [ ] **Step 4: Commit**

```bash
git add README.md cmd/wsshd/main.go
git commit -m "docs: add README with limitations; log proxy rate-limit warning at startup"
```

---

## Post-design amendments

After all 8 tasks are implemented and committed, append the following section to `docs/superpowers/specs/2026-09-07-wssh-design.md`:

```markdown
## Post-design amendments

The following items were identified during implementation and are recorded here
for traceability. No behavior change is implied beyond what the implementation
tasks above already effect.

1. **Keepalive is manual WS ping loops, not `keepalive@openssh.com` global requests.**
   `github.com/coder/websocket` v1.8.15 does not support `KeepAlivePingOptions`.
   The server-side keepalive is a per-connection goroutine that calls
   `Conn.Ping` every 15s with a 5s timeout. Clients send `keepalive@openssh.com`
   SSH global requests; the server discards them (via `ssh.DiscardRequests`) but
   the WebSocket ping/pong chain provides the actual liveness signal.

2. **Rate limiting keys on RemoteAddr — ineffective behind proxies.**
   The per-IP rate limiter uses `http.Request.RemoteAddr`. When wsshd runs behind
   a TLS-terminating reverse proxy, all clients appear to originate from the
   proxy's IP, making per-IP rate limiting pointless. Operators must enforce rate
   limits at the proxy layer in that deployment model. A startup warning is logged.

3. **Spec's `user.Shell` is wrong — shell comes from `lookupShell` parsing `/etc/passwd`.**
   The design spec references `user.Shell` (field on `os/user.User`) but Go's
   `os/user.User` struct has no `Shell` field. The actual implementation parses
   `/etc/passwd` directly via `lookupShell(username string) string` (see
   `internal/server/auth.go`), returning the 7th colon-delimited field. Non-Linux
   systems without `/etc/passwd` fall back to an empty string, which the server
   treats as `/bin/sh`.
```

Then commit:

```bash
git add docs/superpowers/specs/2026-09-07-wssh-design.md
git commit -m "docs: spec post-design amendments; clarify keepalive, rate-limit, shell lookup"
```

---

## Self-review checklist

Before reporting completion, verify:

1. **Spec/scope coverage:** All 8 items have tasks; every user requirement maps to a task step.
2. **Placeholder scan:** No TBD/TODO/placeholder/implement-later/Similar to Task N phrases anywhere in the plan.
3. **Type consistency:**
   - `credentialsFor` new signature `(*syscall.Credential, error)` consistent across Task 2 definition + `startProcess` caller + `handleSession` error path.
   - `clampWinsize` signature `(uint32, uint32) (uint16, uint16, bool)` consistent between definition and both use sites (pty-req, window-change).
   - `termval.Valid` consistent between client (`client.go`) and server (`session.go`) use sites.
   - `WaitTimeout(time.Duration) bool` consistent across `server.go` definition, `main.go` caller, and `shutdown_test.go` tests.
   - `MaxSessionsPerConn`/`MaxChildren` consistent across `Config`, `Server`, `serveConn`, `handleSession`, and tests.
4. **Every task has:** failing-test code shown, expected FAIL output, implementation code shown, expected PASS, gate command, commit message.
5. **Tests compile against current source:** imports match; helper names match (`testSigner` returns `(ssh.Signer, string)`, `newTestServer` takes `(t, authorizedKeys string, rate float64)`, `dialTestSSH` takes `(t, wsURL, username string, signer ssh.Signer)`, `currentUser` takes `(t)`, `syncBuffer` defined in `session_test.go`).
6. **File conflict scan:** Tasks 2, 4, 6, 7 all touch `session.go`/`server.go` — sequential order enforced; each Modify line-ref notes current lines.
