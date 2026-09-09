//go:build !windows

package server

import (
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"

	pty "github.com/aymanbagabas/go-pty"
)

// setupProcAttrs configures SysProcAttr for a PTY-backed command: new
// session with controlling terminal, plus credential dropping when running
// as root.
func setupProcAttrs(cmd *pty.Cmd, u *user.User) error {
	attrs := &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
	}
	cred, err := credentialsFor(u)
	if err != nil {
		return err
	}
	if cred != nil {
		attrs.Credential = cred
	}
	cmd.SysProcAttr = attrs
	return nil
}

// setupExecProcAttrs configures SysProcAttr for a non-PTY exec command:
// credential dropping when running as root.
func setupExecProcAttrs(cmd *exec.Cmd, u *user.User) error {
	cred, err := credentialsFor(u)
	if err != nil {
		return err
	}
	if cred != nil {
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		cmd.SysProcAttr.Credential = cred
	}
	return nil
}

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
