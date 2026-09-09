package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testSigner(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type connMeta struct{ user string }

func (m connMeta) User() string          { return m.user }
func (m connMeta) SessionID() []byte     { return nil }
func (m connMeta) ClientVersion() []byte { return nil }
func (m connMeta) ServerVersion() []byte { return nil }
func (m connMeta) RemoteAddr() net.Addr  { return nil }
func (m connMeta) LocalAddr() net.Addr   { return nil }

func newAuthServer(t *testing.T, authorizedKeys string) *Server {
	t.Helper()
	signer, _ := testSigner(t)
	akPath := filepath.Join(t.TempDir(), "authorized_keys")
	if err := os.WriteFile(akPath, []byte(authorizedKeys), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(Config{
		Signer:             signer,
		Logger:             discardLogger(),
		AuthorizedKeysPath: func(*user.User) string { return akPath },
	})
}

func TestLoadAuthorizedKeysParsesCommentsAndJunk(t *testing.T) {
	_, line := testSigner(t)
	s := newAuthServer(t, "# comment\n\n"+line+"\nnot a valid key line\n")
	u, _ := user.Current()
	keys, err := s.loadAuthorizedKeys(u)
	if err != nil {
		t.Fatalf("loadAuthorizedKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("got %d keys, want 1", len(keys))
	}
}

func TestPublicKeyCallbackAcceptsAuthorizedKey(t *testing.T) {
	signer, line := testSigner(t)
	s := newAuthServer(t, line)
	u, _ := user.Current()
	perms, err := s.publicKeyCallback(connMeta{user: u.Username}, signer.PublicKey())
	if err != nil {
		t.Fatalf("callback rejected valid key: %v", err)
	}
	if perms.Extensions["user"] != u.Username {
		t.Fatalf("extensions user = %q", perms.Extensions["user"])
	}
	if perms.Extensions["shell"] == "" || perms.Extensions["home"] == "" || perms.Extensions["uid"] == "" {
		t.Fatalf("incomplete extensions: %v", perms.Extensions)
	}
}

func TestPublicKeyCallbackRejectsUnknownKey(t *testing.T) {
	_, line := testSigner(t)
	s := newAuthServer(t, line)
	u, _ := user.Current()
	other, _ := testSigner(t)
	if _, err := s.publicKeyCallback(connMeta{user: u.Username}, other.PublicKey()); err == nil {
		t.Fatal("callback accepted unauthorized key")
	}
}

func TestPublicKeyCallbackRejectsOtherUserWhenNonRoot(t *testing.T) {
	s := newAuthServer(t, "")
	if s.Root() {
		t.Skip("running as root; non-root restriction not active")
	}
	_, line := testSigner(t)
	s = newAuthServer(t, line)
	signer, _ := testSigner(t)
	if _, err := s.publicKeyCallback(connMeta{user: "nosuchuser"}, signer.PublicKey()); err == nil {
		t.Fatal("callback accepted unknown user in non-root mode")
	}
}

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

func TestOpenVerifiedAuthorizedKeys(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix-style file permissions")
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix-style file permissions")
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix-style file permissions")
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix-style file permissions")
	}
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
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix-style file permissions")
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
