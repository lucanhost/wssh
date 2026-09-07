package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func writeTestKey(t *testing.T, dir, name string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	out := string(pem.EncodeToMemory(block))
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadSignersExplicitPaths(t *testing.T) {
	dir := t.TempDir()
	p1 := writeTestKey(t, dir, "k1")
	p2 := writeTestKey(t, dir, "k2")
	signers, err := LoadSigners([]string{p1, p2}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 2 {
		t.Fatalf("got %d signers, want 2", len(signers))
	}
}

func TestLoadSignersSkipsBadKeysWithWarning(t *testing.T) {
	dir := t.TempDir()
	good := writeTestKey(t, dir, "good")
	bad := filepath.Join(dir, "bad")
	os.WriteFile(bad, []byte("garbage"), 0o600)
	var sb strings.Builder
	signers, err := LoadSigners([]string{good, bad}, &sb)
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 1 {
		t.Fatalf("got %d signers, want 1", len(signers))
	}
	if !strings.Contains(sb.String(), "bad") {
		t.Fatalf("warning missing for bad key: %q", sb.String())
	}
}

func TestLoadSignersNoKeysErrors(t *testing.T) {
	_, err := LoadSigners([]string{filepath.Join(t.TempDir(), "none")}, io.Discard)
	if err == nil {
		t.Fatal("expected error when no keys load")
	}
}

func TestLoadSignersDefaultsMissingSilent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	var sb strings.Builder
	_, err := LoadSigners(nil, &sb)
	if err == nil {
		t.Fatal("expected error: no default keys exist")
	}
	if sb.String() != "" {
		t.Fatalf("default-missing should be silent, got %q", sb.String())
	}
}
