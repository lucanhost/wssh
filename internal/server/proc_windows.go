//go:build windows

package server

import (
	"os"
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

// baseEnv returns the environment a child process runs under on Windows.
// Unlike the Unix baseEnv, the PATH cannot be a hardcoded /usr list: none of
// those directories exist on Windows, and a missing SystemRoot can make
// cmd.exe itself misbehave. Forward the host's real values instead (none are
// sensitive); u.HomeDir maps to USERPROFILE and the resolved shell to ComSpec.
func baseEnv(u *user.User, shell string) []string {
	sysRoot := os.Getenv("SystemRoot")
	return []string{
		"USERPROFILE=" + u.HomeDir,
		"USERNAME=" + u.Username,
		"ComSpec=" + shell,
		"SystemRoot=" + sysRoot,
		"windir=" + sysRoot,
		"PATH=" + sysRoot + `\system32;` + sysRoot + `;` + sysRoot + `\System32\Wbem`,
		"PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS",
		"TEMP=" + os.Getenv("TEMP"),
		"TMP=" + os.Getenv("TMP"),
	}
}
