package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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

func testKey(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer, signer.PublicKey()
}

type fakeAddr struct{}

func (fakeAddr) Network() string { return "tcp" }
func (fakeAddr) String() string  { return "127.0.0.1:1" }

func writeKnownHosts(t *testing.T, dir string, entries []string) string {
	t.Helper()
	path := filepath.Join(dir, "known_hosts")
	os.WriteFile(path, []byte(strings.Join(entries, "\n")+"\n"), 0o600)
	return path
}

func keyLine(t *testing.T, host string, key ssh.PublicKey) string {
	t.Helper()
	return host + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestHostKeyKnownMatch(t *testing.T) {
	dir := t.TempDir()
	_, key := testKey(t)
	kh := writeKnownHosts(t, dir, []string{keyLine(t, "srv:8080", key)})
	cb := HostKeyCallback(HostKeyOptions{KnownHostsPath: kh})
	if err := cb("srv:8080", fakeAddr{}, key); err != nil {
		t.Fatalf("known key rejected: %v", err)
	}
}

func TestHostKeyChangedHardError(t *testing.T) {
	dir := t.TempDir()
	_, oldKey := testKey(t)
	_, newKey := testKey(t)
	kh := writeKnownHosts(t, dir, []string{keyLine(t, "srv:8080", oldKey)})
	cb := HostKeyCallback(HostKeyOptions{KnownHostsPath: kh})
	err := cb("srv:8080", fakeAddr{}, newKey)
	if err == nil {
		t.Fatal("changed key accepted")
	}
	if !strings.Contains(err.Error(), "known_hosts") {
		t.Fatalf("error should mention known_hosts: %v", err)
	}
}

func TestHostKeyUnknownAcceptNewAppends(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, nil, 0o600)
	_, key := testKey(t)
	cb := HostKeyCallback(HostKeyOptions{KnownHostsPath: kh, AcceptNew: true})
	if err := cb("srv:8080", fakeAddr{}, key); err != nil {
		t.Fatalf("TOFU rejected: %v", err)
	}
	data, _ := os.ReadFile(kh)
	if !strings.Contains(string(data), "srv:8080 ssh-ed25519 ") {
		t.Fatalf("entry not appended: %q", data)
	}
	cb2 := HostKeyCallback(HostKeyOptions{KnownHostsPath: kh})
	if err := cb2("srv:8080", fakeAddr{}, key); err != nil {
		t.Fatalf("key not accepted after TOFU append: %v", err)
	}
}

func TestHostKeyUnknownPromptYes(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, nil, 0o600)
	_, key := testKey(t)
	in := bytes.NewBufferString("yes\n")
	var out bytes.Buffer
	cb := HostKeyCallback(HostKeyOptions{KnownHostsPath: kh, In: in, Out: &out})
	if err := cb("srv:8080", fakeAddr{}, key); err != nil {
		t.Fatalf("prompt yes rejected: %v", err)
	}
	if !strings.Contains(out.String(), "fingerprint") || !strings.Contains(out.String(), "SHA256:") {
		t.Fatalf("prompt missing fingerprint: %q", out.String())
	}
	data, _ := os.ReadFile(kh)
	if !strings.Contains(string(data), "srv:8080") {
		t.Fatal("entry not appended after yes")
	}
}

func TestHostKeyUnknownPromptNo(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, nil, 0o600)
	_, key := testKey(t)
	cb := HostKeyCallback(HostKeyOptions{KnownHostsPath: kh, In: bytes.NewBufferString("no\n"), Out: &bytes.Buffer{}})
	if err := cb("srv:8080", fakeAddr{}, key); err == nil {
		t.Fatal("prompt no accepted")
	}
}

func TestHostKeyUnknownPromptEOF(t *testing.T) {
	dir := t.TempDir()
	kh := filepath.Join(dir, "known_hosts")
	os.WriteFile(kh, nil, 0o600)
	_, key := testKey(t)
	cb := HostKeyCallback(HostKeyOptions{KnownHostsPath: kh, In: bytes.NewBufferString(""), Out: &bytes.Buffer{}})
	if err := cb("srv:8080", fakeAddr{}, key); err == nil {
		t.Fatal("EOF accepted")
	}
}

func TestHostKeyCallbackWithWebsocketRemoteAddr(t *testing.T) {
	dir := t.TempDir()
	_, key := testKey(t)
	kh := writeKnownHosts(t, dir, []string{keyLine(t, "srv:8080", key)})
	cb := HostKeyCallback(HostKeyOptions{KnownHostsPath: kh})
	wsAddr := websocketMockAddr{}
	if err := cb("srv:8080", wsAddr, key); err != nil {
		t.Fatalf("known key rejected with websocket remote addr: %v", err)
	}
}

type websocketMockAddr struct{}

func (websocketMockAddr) Network() string { return "websocket" }
func (websocketMockAddr) String() string  { return "websocket/unknown-addr" }

var _ = net.SplitHostPort
var _ = knownhosts.New

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
