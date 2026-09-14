//go:build windows

package server

import (
	"os"
	"os/exec"
	"os/user"
	"syscall"
	"unsafe"

	pty "github.com/aymanbagabas/go-pty"
	"golang.org/x/sys/windows"
)

// setupProcAttrs configures SysProcAttr for a PTY-backed command on
// Windows: a new process group so the child does not share the daemon's
// Ctrl+C handling. CREATE_NO_WINDOW is deliberately NOT set: it is a
// pre-ConPTY console mechanism (suppress the legacy conhost window a
// console app would otherwise pop up), but a ConPTY-attached process is
// headless by virtue of the pseudo-console, and Microsoft's own ConPTY
// samples do not combine the two. Keeping the spawn path minimal here makes
// it easier to isolate ConPTY output-flow behavior. Credential dropping is
// skipped on Windows.
func setupProcAttrs(cmd *pty.Cmd, u *user.User) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
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

// jobObject wraps a Windows Job Object handle created with
// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE. Windows has no POSIX process group, so
// Process.Kill() only terminates the direct child and leaves descendants
// (e.g. a grandchild ping.exe behind cmd.exe /C) running while they still
// hold the inherited stdio handles that keep cmd.Wait() blocked. Closing the
// job object kills the entire tree in one call, which the shared session
// teardown relies on to reap a closed child promptly.
type jobObject struct {
	handle windows.Handle
}

// newJobObject creates a Job Object that terminates every process assigned to
// it when the handle is closed.
func newJobObject() (*jobObject, error) {
	h, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(h, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return &jobObject{handle: h}, nil
}

// assign adds the process pid to the job so it is killed with the tree.
func (j *jobObject) assign(pid int) error {
	ph, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, uint32(pid))
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(ph) }()
	return windows.AssignProcessToJobObject(j.handle, ph)
}

// close releases the job object handle; with KILL_ON_JOB_CLOSE set this also
// terminates every process still assigned to it, parent and descendants.
func (j *jobObject) close() {
	_ = windows.CloseHandle(j.handle)
}
