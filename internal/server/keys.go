package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func LoadOrGenerateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(priv, "wssh auto-generated host key")
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		pemBytes := pem.EncodeToMemory(block)
		if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
			return nil, err
		}
		return ssh.ParsePrivateKey(pemBytes)
	}
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}
