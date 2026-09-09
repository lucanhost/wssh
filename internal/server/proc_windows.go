//go:build windows

package server

import (
	"os/exec"
	"os/user"
	"syscall"

	pty "github.com/aymanbagabas/go-pty"
)

// setupProcAttrs configures SysProcAttr for a PTY-backed command on
// Windows: new process group without a visible window. Credential
// dropping is skipped on Windows.
func setupProcAttrs(cmd *pty.Cmd, u *user.User) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | 0x08000000,
	}
	return nil
}

// setupExecProcAttrs is a no-op on Windows: no credential dropping.
func setupExecProcAttrs(cmd *exec.Cmd, u *user.User) error {
	return nil
}

// credentialsFor is a stub on Windows so shared test files referencing it
// still compile; Windows never drops privileges.
func credentialsFor(u *user.User) (any, error) {
	return nil, nil
}
