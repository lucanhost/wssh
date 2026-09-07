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
