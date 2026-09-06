package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLoadOrGenerateHostKeyGenerates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "host_key")
	signer, err := LoadOrGenerateHostKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey: %v", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("key type = %s, want %s", signer.PublicKey().Type(), ssh.KeyAlgoED25519)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("generated file missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), "OPENSSH PRIVATE KEY") {
		t.Fatal("generated key not in OpenSSH format")
	}
}

func TestLoadOrGenerateHostKeyReloadsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_key")
	first, err := LoadOrGenerateHostKey(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrGenerateHostKey(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(first.PublicKey().Marshal()) != string(second.PublicKey().Marshal()) {
		t.Fatal("reloaded key differs from generated key")
	}
}

func TestLoadOrGenerateHostKeyRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host_key")
	os.WriteFile(path, []byte("not a key"), 0o600)
	if _, err := LoadOrGenerateHostKey(path); err == nil {
		t.Fatal("expected error for garbage key file")
	}
}
