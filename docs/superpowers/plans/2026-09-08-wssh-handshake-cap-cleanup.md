# wssh Handshake Cap + Batch-4-Deferred Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the last audit security gap — unbounded concurrent in-flight SSH handshakes — with a `MaxHandshakes` semaphore (the handshake analog of `childrenSem`), plus the four items deferred in the Batch 4 ledger: StrictModes fstat-after-open TOCTOU hardening + guard-clause tests, the handshakeTimeout/t.Parallel comment, the cap-test `!=` tightening, and the README trusted-proxies precedence note.

**Architecture:** All four tasks are localized, dependency-free changes. Task 1 adds a buffered-channel semaphore acquired in `WebSocketHandler` (non-blocking, 503 at cap) and released in `serveConn` immediately after `ssh.NewServerConn` returns — never held for the session lifetime. Task 2 restructures `checkStrictModes` into `openVerifiedAuthorizedKeys`, which opens the file first and Fstats the opened fd, so permission checks apply to the file actually read. Task 3 is README-only. Task 4 is test-only hygiene. Spec: `docs/superpowers/specs/2026-09-07-wssh-design.md`.

**Tech Stack:** Go 1.26.8 (`go.mod`), `golang.org/x/crypto/ssh`, `github.com/coder/websocket` v1.8.15, stdlib `syscall` (Unix-only — repo already relies on Unix semantics).

## Global Constraints

- Go floor per `go.mod` (`go 1.26.8`); CI pins via `go-version-file: go.mod`. No new dependencies — the existing pinned modules (`x/crypto`, `coder/websocket`, `creack/pty`, `x/term`, `x/time`, `BurntSushi/toml`, indirect `x/sys`) stay exactly as-is.
- No new CLI flags and no new TOML keys. `MaxHandshakes` is a `Config` field with a default only (same treatment as `MaxChildren`).
- Additive only: do not regress any behavior from Batches 1–4 (handshake deadline, StrictModes stat-chain, rate-limiter cap, http timeouts, trusted-proxy clientIP, TOML config, etc.). Do not change the 60s handshake deadline value.
- Repo conventions: no comments in Go code EXCEPT the single justified comment in Task 4; conventional commits (`feat:`/`fix:`/`test:`/`docs:`); every task ends in a commit.
- All tests pass with `-race -count=1`. SSH handshake tests use TCP loopback (via `httptest` + `transport.Dial`), NOT `net.Pipe` — `net.Pipe` deadlocks the SSH version exchange (both sides write before reading).
- slog for all logging; no key material or secrets in logs.
- Verify with: `go vet ./... && go test ./... -race -count=1 && go build ./...` (CI parity).

## Task Ordering Constraint

- **Task 1 MUST execute before Task 4.** Both edit `internal/server/server_test.go` (Task 1 adds the semaphore tests and seeds the two direct `serveConn` test callers; Task 4 adds a comment to `TestServeConnHandshakeDeadline`).
- Tasks 2 and 3 are disjoint from the others and from each other.

---

### Task 1: Bound concurrent in-flight handshakes (`MaxHandshakes` semaphore)  [security — the main event]

**Files:**
- Modify: `internal/server/server.go` (`Config` struct, `Server` struct, `New`, `WebSocketHandler`, `serveConn`)
- Test: `internal/server/server_test.go` (append 3 tests; seed 2 existing direct-`serveConn` tests)

**Interfaces:**
- Consumes: existing `childrenSem` pattern (`chan struct{}` + buffered `make` in `New`), `transport.Accept(w, r) (net.Conn, error)`, `handshakeTimeout` package var (unchanged, 60s).
- Produces: `Config.MaxHandshakes int` (default 64 when 0, applied in `New`); unexported `Server.handshakeSem chan struct{}` buffered to `MaxHandshakes`. Contract: `WebSocketHandler` acquires exactly one slot per accepted upgrade (non-blocking; HTTP 503 when full) and releases it if `transport.Accept` fails; `serveConn` releases the slot immediately after `ssh.NewServerConn` returns (success OR failure) — the slot is NEVER held for the session-serving lifetime. Any test calling `serveConn` directly must seed one token first.

Design decisions (fixed — implement, do not re-litigate):
- Not a CLI flag, not a TOML key — consistent with `MaxChildren`.
- Acquire is NON-BLOCKING (`select`/`default`); at cap respond `503 Service Unavailable` (clean status, consistent with the rate limiter's 429). Do not block.
- Release is NOT a function-level `defer` (that would hold the slot until the connection closes — the wrong cap). Releasing right after `NewServerConn` is safe: it returns errors, not panics.
- Deliberate deviation from the wiring sketch: the sketch shows `netConn.SetDeadline(time.Time{})` unconditionally before the release. Keeping Batch 4's exact semantics (deadline cleared only on the success path) is required — `stallConn` records only the latest `SetDeadline` value, and `TestServeConnHandshakeDeadline` asserts it is non-zero after `serveConn` returns; an unconditional clear would zero it and regress the Batch 4 test. The release therefore happens immediately after `NewServerConn` returns, BEFORE the error check; the deadline clear stays where Batch 4 put it (success path only). Slot accounting is identical.

- [ ] **Step 1: Write the failing tests**

Append to `internal/server/server_test.go` (all imports already present: `bytes`, `context`, `net/http`, `net/http/httptest`, `os`, `os/user`, `path/filepath`, `strings`, `testing`, `time`, `ssh`, `transport`):

```go
func TestMaxHandshakesDefault(t *testing.T) {
	signer, _ := testSigner(t)
	s := New(Config{Signer: signer})
	if cap(s.handshakeSem) != 64 {
		t.Fatalf("default MaxHandshakes = %d, want 64", cap(s.handshakeSem))
	}
	s2 := New(Config{Signer: signer, MaxHandshakes: 2})
	if cap(s2.handshakeSem) != 2 {
		t.Fatalf("MaxHandshakes = %d, want 2", cap(s2.handshakeSem))
	}
}

func newMaxHandshakesServer(t *testing.T, maxHandshakes int) (*Server, string, string) {
	t.Helper()
	signer, line := testSigner(t)
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(akPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Config{
		Signer:             signer,
		Logger:             discardLogger(),
		AuthorizedKeysPath: func(*user.User) string { return akPath },
		MaxHandshakes:      maxHandshakes,
	})
	t.Cleanup(s.Close)
	mux := http.NewServeMux()
	mux.Handle("/ws", s.WebSocketHandler())
	up := httptest.NewServer(mux)
	t.Cleanup(up.Close)
	wsURL := "ws" + strings.TrimPrefix(up.URL, "http") + "/ws"
	httpURL := "http" + strings.TrimPrefix(up.URL, "http") + "/ws"
	return s, wsURL, httpURL
}

func TestMaxHandshakesSemRejectsAtCapacity(t *testing.T) {
	signer, _ := testSigner(t)
	_, wsURL, httpURL := newMaxHandshakesServer(t, 1)

	held, err := transport.Dial(context.Background(), wsURL)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer held.Close()

	resp, err := http.Get(httpURL)
	if err != nil {
		t.Fatalf("probe get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("probe status = %d, want 503 while handshake in flight", resp.StatusCode)
	}

	held.Close()
	var recovered *ssh.Client
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		netConn, err := transport.Dial(ctx, wsURL)
		if err != nil {
			cancel()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		cfg := &ssh.ClientConfig{
			User:            currentUser(t),
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         2 * time.Second,
		}
		conn, chans, reqs, err := ssh.NewClientConn(netConn, "test:1", cfg)
		cancel()
		if err != nil {
			netConn.Close()
			time.Sleep(20 * time.Millisecond)
			continue
		}
		recovered = ssh.NewClient(conn, chans, reqs)
		break
	}
	if recovered == nil {
		t.Fatal("handshake slot not released after stalled handshake closed")
	}
	defer recovered.Close()
	sess, err := recovered.NewSession()
	if err != nil {
		t.Fatalf("session after recovery: %v", err)
	}
	defer sess.Close()
	var out bytes.Buffer
	sess.Stdout = &out
	if err := sess.Run("echo recovered"); err != nil {
		t.Fatalf("run after recovery: %v", err)
	}
	if out.String() != "recovered\n" {
		t.Fatalf("output = %q, want %q", out.String(), "recovered\n")
	}
}

func TestMaxHandshakesSemReleasedAfterHandshake(t *testing.T) {
	signer, _ := testSigner(t)
	_, wsURL, _ := newMaxHandshakesServer(t, 1)

	cl1 := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess1, err := cl1.NewSession()
	if err != nil {
		t.Fatalf("session 1: %v", err)
	}
	if err := sess1.Start("sleep 60"); err != nil {
		t.Fatalf("start long-lived session: %v", err)
	}

	cl2 := dialTestSSH(t, wsURL, currentUser(t), signer)
	sess2, err := cl2.NewSession()
	if err != nil {
		t.Fatalf("session 2: %v", err)
	}
	defer sess2.Close()
	var out bytes.Buffer
	sess2.Stdout = &out
	if err := sess2.Run("echo while-alive"); err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.String() != "while-alive\n" {
		t.Fatalf("output = %q, want %q", out.String(), "while-alive\n")
	}

	sess1.Close()
	cl1.Close()
	cl2.Close()
}
```

How the tests work (for the implementer): `transport.Dial` completes only the WebSocket upgrade — the server handler acquires the slot BEFORE `transport.Accept`, so once `Dial` returns the slot is definitively held. `held` never sends an SSH version banner, so the server blocks inside `ssh.NewServerConn` (bounded by the 60s deadline, far beyond the test). A plain `http.Get` to the endpoint passes the (disabled) rate limiter and hits the full semaphore → 503. Closing `held` unblocks `NewServerConn` with a read error → slot released → the retry loop's full SSH handshake succeeds. `TestMaxHandshakesSemReleasedAfterHandshake` keeps `cl1` connected with a live `sleep 60` session while `cl2` handshakes — if the slot were held for the session lifetime (e.g. a function-level `defer` release), `cl2`'s upgrade would get 503 and `dialTestSSH` would fail.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/ -run 'TestMaxHandshakes' -v`
Expected: FAIL to build — `unknown field MaxHandshakes in struct literal` / `s.handshakeSem undefined`.

- [ ] **Step 3: Implement the semaphore**

In `internal/server/server.go`:

1. Add `MaxHandshakes int` to the `Config` struct, after `MaxChildren`:

```go
type Config struct {
	Signer             ssh.Signer
	Logger             *slog.Logger
	Rate               float64
	Burst              int
	AuthorizedKeysPath func(*user.User) string
	MaxSessionsPerConn int
	MaxChildren        int
	MaxHandshakes      int
	TrustedProxies     []string
}
```

2. Add `handshakeSem chan struct{}` to the `Server` struct, after `childrenSem`:

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
	handshakeSem       chan struct{}
}
```

3. In `New`, add the default directly after the `MaxChildren` default, and the field to the struct literal:

```go
	if cfg.MaxChildren == 0 {
		cfg.MaxChildren = 256
	}
	if cfg.MaxHandshakes == 0 {
		cfg.MaxHandshakes = 64
	}
	s := &Server{
		logger:             cfg.Logger,
		root:               os.Geteuid() == 0,
		currentUsername:    currentUserFromOS(),
		authorizedKeysPath: cfg.AuthorizedKeysPath,
		maxSessionsPerConn: cfg.MaxSessionsPerConn,
		childrenSem:        make(chan struct{}, cfg.MaxChildren),
		handshakeSem:       make(chan struct{}, cfg.MaxHandshakes),
	}
```

4. Replace `WebSocketHandler` (acquire after the rate-limiter check, before `transport.Accept`; release on upgrade failure):

```go
func (s *Server) WebSocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		if s.limiter != nil && !s.limiter.Allow(ip) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		select {
		case s.handshakeSem <- struct{}{}:
		default:
			http.Error(w, "too many concurrent handshakes", http.StatusServiceUnavailable)
			return
		}
		netConn, err := transport.Accept(w, r)
		if err != nil {
			<-s.handshakeSem
			s.logger.Warn("websocket upgrade failed", "remote", r.RemoteAddr, "err", err)
			return
		}
		s.wg.Add(1)
		go s.serveConn(netConn, r.RemoteAddr)
	})
}
```

5. Replace the head of `serveConn` (release immediately after `NewServerConn` returns, before the error check; deadline clear stays on the success path exactly as Batch 4 left it):

```go
func (s *Server) serveConn(netConn net.Conn, remoteAddr string) {
	defer s.wg.Done()
	defer netConn.Close()
	if err := netConn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		s.logger.Warn("ssh handshake deadline not set", "remote", remoteAddr, "err", err)
	}
	sconn, chans, reqs, err := ssh.NewServerConn(netConn, &s.sshConfig)
	<-s.handshakeSem
	if err != nil {
		s.logger.Warn("ssh handshake failed", "remote", remoteAddr, "err", err)
		return
	}
	_ = netConn.SetDeadline(time.Time{}) // handshake done; allow long-lived sessions
	defer sconn.Close()
```

The remainder of `serveConn` (from `go ssh.DiscardRequests(reqs)` down) is unchanged.

6. Seed the two existing tests that call `serveConn` directly (they bypass `WebSocketHandler`, so without a token the new `<-s.handshakeSem` would block forever). In `internal/server/server_test.go`:

In `TestServeConnHandshakeDeadline`, add the seed line before `s.wg.Add(1)`:

```go
	sc := &stallConn{closed: make(chan struct{})}
	s.handshakeSem <- struct{}{}
	s.wg.Add(1)
```

In `TestServeConnClearsDeadlineAfterHandshake`, add the seed line inside the accept goroutine, before `s.wg.Add(1)`:

```go
		s.handshakeSem <- struct{}{}
		s.wg.Add(1)
		s.serveConn(rc, ln.Addr().String())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ -run 'TestMaxHandshakes|TestServeConn|TestMaxChildrenSem' -v -count=1`
Expected: all PASS — new semaphore tests, both seeded deadline tests, and the children-semaphore tests (unchanged behavior).

Run: `go vet ./... && go test ./... -race -count=1 && go build ./...`
Expected: all packages `ok`; vet and build clean (e2e and client suites exercise the new acquire path with the default cap of 64).

- [ ] **Step 5: Commit**

```bash
git add internal/server/server.go internal/server/server_test.go
git commit -m "feat: cap concurrent in-flight SSH handshakes"
```

---

### Task 2: StrictModes fstat-after-open TOCTOU hardening  [security]

**Files:**
- Modify: `internal/server/auth.go` (`loadAuthorizedKeys`; replace `checkStrictModes` with `openVerifiedAuthorizedKeys` + two helpers)
- Test: `internal/server/auth_test.go` (rewrite the three `TestCheckStrictModes*` tests onto the new API; add guard-clause tests)

**Interfaces:**
- Consumes: `*user.User` (fields `Uid`, `Gid`, `Username`, `HomeDir`), existing `loadAuthorizedKeys(u *user.User) ([]ssh.PublicKey, error)` signature (unchanged), `syscall.Stat_t`.
- Produces: `openVerifiedAuthorizedKeys(path string, u *user.User) (*os.File, error)` — unexported, package `server`. Opens `authorized_keys`, verifies the home dir and `.ssh` dir path-based (`os.Stat`), verifies the FILE via `f.Stat()` on the opened fd, and returns the verified, opened `*os.File` (caller closes). Helpers: `checkPathPerms(path string, uid uint32) error`, `checkInfoPerms(path string, fi os.FileInfo, uid uint32) error`. `checkStrictModes` is deleted. Rejection semantics unchanged: any violation → error → `publicKeyCallback` logs Warn and returns `errAccessDenied`.

Design decisions (fixed — implement, do not re-litigate):
- The file is opened EXACTLY ONCE; the key reader consumes the returned fd. Opening twice would re-create the TOCTOU window this closes.
- The FILE's permissions/ownership are checked via `Fstat` on the opened fd (`f.Stat()`), so the checks apply to the file actually read.
- Parent-directory and home-directory checks remain path-based (`os.Stat`); directory-swap TOCTOU is not closeable without `O_DIRECTORY`/`O_NOFOLLOW` gymnastics — documented residual limitation (recorded in this plan's Self-Review section, NOT as a code comment; the repo's no-comments convention applies).
- Check order preserved from Batch 4: home → `.ssh` dir → file; same error messages (path-prefixed); fail closed.

- [ ] **Step 1: Write the failing tests**

In `internal/server/auth_test.go`, append (all imports already present: `io`, `os`, `os/user`, `path/filepath`, `testing`):

```go
func TestOpenVerifiedAuthorizedKeys(t *testing.T) {
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
			if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA test\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(keyPath, tc.fileMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(sshDir, tc.dirMode); err != nil {
				t.Fatal(err)
			}
			u := &user.User{Uid: me.Uid, Gid: me.Gid, Username: me.Username, HomeDir: home}
			f, err := openVerifiedAuthorizedKeys(keyPath, u)
			if tc.wantErr {
				if err == nil {
					f.Close()
					t.Fatal("openVerifiedAuthorizedKeys accepted insecure permissions")
				}
				return
			}
			if err != nil {
				t.Fatalf("openVerifiedAuthorizedKeys rejected secure permissions: %v", err)
			}
			f.Close()
		})
	}
}

func TestOpenVerifiedAuthorizedKeysCleanFile(t *testing.T) {
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
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA clean\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u := &user.User{Uid: me.Uid, Gid: me.Gid, Username: me.Username, HomeDir: home}
	f, err := openVerifiedAuthorizedKeys(keyPath, u)
	if err != nil {
		t.Fatalf("clean file rejected: %v", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("fstat on returned fd: %v", err)
	}
	if !fi.Mode().IsRegular() {
		t.Fatalf("opened file not regular: %v", fi.Mode())
	}
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read verified fd: %v", err)
	}
	if string(data) != "ssh-ed25519 AAAA clean\n" {
		t.Fatalf("verified fd content = %q", data)
	}
}

func TestOpenVerifiedAuthorizedKeysGroupWritableHome(t *testing.T) {
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
	if f, err := openVerifiedAuthorizedKeys(keyPath, u); err == nil {
		f.Close()
		t.Fatal("group-writable home accepted")
	}
}

func TestOpenVerifiedAuthorizedKeysUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens files regardless of mode")
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
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA test\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	u := &user.User{Uid: me.Uid, Gid: me.Gid, Username: me.Username, HomeDir: home}
	if f, err := openVerifiedAuthorizedKeys(keyPath, u); err == nil {
		f.Close()
		t.Fatal("unreadable file accepted")
	}
}

func TestOpenVerifiedAuthorizedKeysMissing(t *testing.T) {
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
	u := &user.User{Uid: me.Uid, Gid: me.Gid, Username: me.Username, HomeDir: home}
	if f, err := openVerifiedAuthorizedKeys(keyPath, u); err == nil {
		f.Close()
		t.Fatal("missing file accepted")
	}
}

func TestOpenVerifiedAuthorizedKeysBadUser(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(keyPath, []byte("ssh-ed25519 AAAA test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	noHome := &user.User{Uid: "1000", Gid: "1000", Username: "x", HomeDir: ""}
	if f, err := openVerifiedAuthorizedKeys(keyPath, noHome); err == nil {
		f.Close()
		t.Fatal("empty home accepted")
	}
	badUID := &user.User{Uid: "notanumber", Gid: "1000", Username: "x", HomeDir: home}
	if f, err := openVerifiedAuthorizedKeys(keyPath, badUID); err == nil {
		f.Close()
		t.Fatal("invalid uid accepted")
	}
}

func TestOpenVerifiedAuthorizedKeysOwnership(t *testing.T) {
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
	f, err := openVerifiedAuthorizedKeys(keyPath, u)
	if err != nil {
		t.Fatalf("root-owned key rejected: %v", err)
	}
	f.Close()

	if err := os.Chown(keyPath, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if f, err := openVerifiedAuthorizedKeys(keyPath, u); err == nil {
		f.Close()
		t.Fatal("foreign-owned key accepted")
	}
}
```

Then DELETE the three Batch 4 tests `TestCheckStrictModes`, `TestCheckStrictModesGroupWritableHome`, and `TestCheckStrictModesOwnership` (auth_test.go:173-276) — they call `checkStrictModes`, which this task deletes; their coverage is fully preserved by the rewritten tests above (table: file/dir perms; group-writable home; root-gated ownership).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/server/ -run 'TestOpenVerifiedAuthorizedKeys' -v`
Expected: FAIL to build — `undefined: openVerifiedAuthorizedKeys`.

- [ ] **Step 3: Implement `openVerifiedAuthorizedKeys` and rewire `loadAuthorizedKeys`**

In `internal/server/auth.go`, replace the body of `loadAuthorizedKeys` (currently lines 71-99) with:

```go
func (s *Server) loadAuthorizedKeys(u *user.User) ([]ssh.PublicKey, error) {
	path := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	if s.authorizedKeysPath != nil {
		path = s.authorizedKeysPath(u)
	}
	f, err := openVerifiedAuthorizedKeys(path, u)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var keys []ssh.PublicKey
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue
		}
		keys = append(keys, key)
	}
	return keys, scanner.Err()
}
```

Then delete `checkStrictModes` (currently lines 101-131, including its doc comment) and add in its place:

```go
func openVerifiedAuthorizedKeys(path string, u *user.User) (*os.File, error) {
	if u.HomeDir == "" {
		return nil, errors.New("user has no home directory")
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid uid %q for user %q", u.Uid, u.Username)
	}
	uid := uint32(uid64)
	if err := checkPathPerms(u.HomeDir, uid); err != nil {
		return nil, err
	}
	if err := checkPathPerms(filepath.Dir(path), uid); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if err := checkInfoPerms(path, fi, uid); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func checkPathPerms(path string, uid uint32) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	return checkInfoPerms(path, fi, uid)
}

func checkInfoPerms(path string, fi os.FileInfo, uid uint32) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("permission checks unsupported on this platform (%s)", path)
	}
	if st.Uid != uid && st.Uid != 0 {
		return fmt.Errorf("%s: owned by uid %d, want %d or root", path, st.Uid, uid)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s: permissions %04o allow group/other writes", path, perm)
	}
	return nil
}
```

No import changes: `bufio`, `bytes`, `errors`, `fmt`, `os`, `os/user`, `path/filepath`, `strconv`, `strings`, `syscall`, `ssh` are all already imported and all remain used (`strings`/`bufio` by `lookupShell`).

Note for the implementer: the file-level check MUST go through `f.Stat()` on the fd returned by the single `os.Open` — never `os.Stat(path)` for the file itself. The home and `.ssh` dir checks stay on `os.Stat` (path-based residual, by design). `publicKeyCallback` needs no change: it already logs and rejects on `loadAuthorizedKeys` error.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/server/ -run 'TestOpenVerifiedAuthorizedKeys|TestLoadAuthorizedKeys|TestPublicKeyCallback|FuzzLoadAuthorizedKeys' -v -count=1`
Expected: all PASS — new guard-clause tests, rewritten perms/ownership tests, and the existing parse/callback/fuzz tests through the new single-open path. (`TestOpenVerifiedAuthorizedKeysOwnership` SKIPs as non-root; `TestOpenVerifiedAuthorizedKeysUnreadable` SKIPs as root.)

Run: `go vet ./... && go test ./... -race -count=1 && go build ./...`
Expected: all packages `ok`; vet and build clean (e2e exercises the full auth path through `AuthorizedKeysPath` overrides with `t.TempDir()` files — 0700/0600, current-user-owned, legal under StrictModes).

- [ ] **Step 5: Commit**

```bash
git add internal/server/auth.go internal/server/auth_test.go
git commit -m "fix: verify authorized_keys permissions on the opened file"
```

---

### Task 3: README note: empty `-trusted-proxies` cannot clear a file-configured list  [docs]

**Files:**
- Modify: `README.md` (Limitations section — two new bullets; no code changes)

**Interfaces:**
- Consumes: verified behavior of `internal/config.Merge` (config.go:55-84: an overlay's `TrustedProxies` is applied only when the slice is non-nil), `cmd/wsshd/main.go` `flag.Visit` wiring (main.go:44-63: only explicitly-set flags are visited) and `splitList` (main.go:148-156: an empty flag value yields a nil slice).
- Produces: documentation only.

Verified behavior (checked against the code — do not re-derive, do not weaken):
1. TOML sets `trusted_proxies`, `-trusted-proxies` absent → flag never visited → CLI overlay slice nil → `Merge` keeps the file value.
2. TOML sets `trusted_proxies`, `-trusted-proxies ""` passed explicitly → `splitList("")` returns nil → CLI overlay slice nil → `Merge` keeps the file value. Even an explicitly empty flag does NOT clear it.
3. Non-empty `-trusted-proxies a,b` → non-nil slice → overrides the file (normal precedence).
4. To clear: remove the `trusted_proxies` key from the TOML file (or set `trusted_proxies = []` — either way the resolved list ends up empty).

- [ ] **Step 1: Add the two bullets to the README Limitations section**

In `README.md`, append to the end of the `## Limitations` bullet list (after the WebSocket read-limit bullet):

```markdown
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
```

(The second bullet is the optional security note from the batch scope — it is not documented anywhere in the README today, and `transport.Accept` passes no `OriginPatterns`, so the empty-default is the secure behavior worth pinning in prose.)

- [ ] **Step 2: Verify nothing else changed**

Run: `git diff --stat` (only `README.md` modified) && `go build ./... && go vet ./...`
Expected: clean; docs-only change.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document trusted-proxies precedence and origin policy"
```

---

### Task 4: Test hygiene pair  [tests]

**Files:**
- Modify: `internal/server/server_test.go` (one 2-line comment above `TestServeConnHandshakeDeadline`; execute AFTER Task 1)
- Modify: `internal/transport/ratelimit_test.go` (tighten the cap-test `!=` bound)

**Interfaces:**
- Consumes: `TestServeConnHandshakeDeadline` as seeded by Task 1; `TestRateLimiterCapsEntries` as committed in Batch 4 (ea25bef).
- Produces: no production changes; no behavioral test changes.

- [ ] **Step 1: Add the justified comment to the handshake-deadline test**

In `internal/server/server_test.go`, immediately above `func TestServeConnHandshakeDeadline(t *testing.T) {`, add exactly this two-line comment (the single justified exception to the no-comments convention):

```go
// Rewrites the package-level handshakeTimeout (restored via t.Cleanup); must
// not run under t.Parallel, which would race other tests' handshakes.
func TestServeConnHandshakeDeadline(t *testing.T) {
```

- [ ] **Step 2: Tighten the cap-test bound**

In `internal/transport/ratelimit_test.go`, in `TestRateLimiterCapsEntries`, the invariant is that the map size never EXCEEDS the cap. Replace the exact-equality check after the fill loop:

```go
	rl.mu.Lock()
	n := len(rl.entries)
	rl.mu.Unlock()
	if n != maxEntries {
		t.Fatalf("entries = %d, want %d", n, maxEntries)
	}
```

with:

```go
	rl.mu.Lock()
	n := len(rl.entries)
	rl.mu.Unlock()
	if n > maxEntries {
		t.Fatalf("entries = %d, exceeds cap %d", n, maxEntries)
	}
```

The later post-overflow check (`if n > maxEntries` after `Allow("ip-overflow")`) is already correct — leave it untouched. The eviction assertions (`oldestPresent`, `Allow("ip-1")`) continue to pin that the cap is actually reached and enforced, so what the test verifies is unchanged.

- [ ] **Step 3: Run the affected suites**

Run: `go test ./internal/transport/ ./internal/server/ -race -count=1`
Expected: both packages `ok`.

- [ ] **Step 4: Full verification (CI parity)**

Run: `go vet ./... && go test ./... -race -count=1 && go build ./...`
Expected: all packages `ok`; vet and build clean.

- [ ] **Step 5: Commit**

```bash
git add internal/server/server_test.go internal/transport/ratelimit_test.go
git commit -m "test: annotate handshake-timeout test and tighten cap-test bound"
```

---

## Final Verification (after Task 4)

```bash
go vet ./... && go test ./... -race -count=1 && go build ./...
git log --oneline -5
```

Expected: all packages `ok`, vet/build clean, and a commit log of exactly one commit per task:

```
... test: annotate handshake-timeout test and tighten cap-test bound
... docs: document trusted-proxies precedence and origin policy
... fix: verify authorized_keys permissions on the opened file
... feat: cap concurrent in-flight SSH handshakes
```

---

## Self-Review

**1. Spec coverage:**
- Unbounded in-flight handshakes → Task 1 (`MaxHandshakes` semaphore, 503 at cap, release post-handshake, release on failed upgrade). ✔
- StrictModes fstat-after-open TOCTOU + guard-clause tests → Task 2. ✔
- README trusted-proxies precedence note (+ optional origin-policy note, verified undocumented) → Task 3. ✔
- handshakeTimeout/t.Parallel comment + cap-test `!=` tightening → Task 4. ✔
- Out-of-scope items (CLI/TOML surface for `MaxHandshakes`, dir-swap TOCTOU, IPv6 items, 60s deadline change, `connWithDone` TLS injection) — deliberately absent from all tasks. ✔

**2. Placeholder scan:** every code step contains complete code; no "TBD"/"add error handling"/"similar to Task N" shorthand; every run command has expected output. ✔

**3. Type/signature consistency:**
- `handshakeSem` acquire/release pairing: exactly one acquire per accepted upgrade in `WebSocketHandler`; exactly one release per acquire — in `WebSocketHandler` when `transport.Accept` fails (serveConn never spawned), otherwise in `serveConn` immediately after `ssh.NewServerConn` returns (success OR failure), before the error check. The release is a plain channel receive, NOT a function-level `defer`. Direct `serveConn` test callers (`TestServeConnHandshakeDeadline`, `TestServeConnClearsDeadlineAfterHandshake`) seed one token each, preserving the invariant. ✔
- Release ordering deviation from the prompt's sketch (release BEFORE the deadline clear, clear stays success-only) is deliberate and documented in Task 1: an unconditional clear would zero `stallConn`'s recorded deadline and break the Batch 4 test `TestServeConnHandshakeDeadline`, and would regress Batch 4's clear-on-success semantics. Slot accounting is identical either way. ✔
- Task 2 Fstat flow: `authorized_keys` is opened exactly once by `openVerifiedAuthorizedKeys`; the file-level check uses `f.Stat()` on that fd; `loadAuthorizedKeys` consumes the returned fd (no second open). The Fstat-vs-path-Stat property is enforced structurally (single open, `f.Stat()` in the code) and behaviorally (`TestOpenVerifiedAuthorizedKeysCleanFile` reads the verified fd; guard-clause table exercises every early return through the single entry point). A deterministic race-window test is impossible without seams; the swap-window itself is the TOCTOU being closed. ✔
- `openVerifiedAuthorizedKeys(path string, u *user.User) (*os.File, error)` signature matches the prompt's target shape; helpers `checkPathPerms`/`checkInfoPerms` are defined in Task 2 and used only there. ✔
- Task 1 → Task 4 ordering on `server_test.go` is stated in the header and in Task 4's Files block. ✔
- Residual limitation (directory-swap TOCTOU on parent/home dirs) recorded here per the no-comments convention: path-based `os.Stat` checks on `u.HomeDir` and `filepath.Dir(path)` remain vulnerable to a local attacker swapping the directory between check and open; closing that requires `O_DIRECTORY`/`O_NOFOLLOW`-style syscalls and is explicitly out of scope. ✔
