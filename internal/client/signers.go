package client

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func LoadSigners(paths []string, warn io.Writer) ([]ssh.Signer, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	isDefault := false
	if len(paths) == 0 {
		isDefault = true
		paths = []string{
			filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".ssh", "id_rsa"),
		}
	}
	var signers []ssh.Signer
	for _, p := range paths {
		if strings.HasPrefix(p, "~/") {
			p = filepath.Join(home, strings.TrimPrefix(p, "~/"))
		}
		data, err := os.ReadFile(p)
		if err != nil {
			if !(isDefault && errors.Is(err, os.ErrNotExist)) {
				fmt.Fprintf(warn, "wssh: skipping key %s: %v\n", p, err)
			}
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			fmt.Fprintf(warn, "wssh: skipping key %s: %v\n", p, err)
			continue
		}
		signers = append(signers, signer)
	}
	if len(signers) == 0 {
		return nil, fmt.Errorf("no usable private keys (tried: %s)", strings.Join(paths, ", "))
	}
	return signers, nil
}
