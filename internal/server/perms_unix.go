//go:build !windows

package server

import (
	"fmt"
	"os"
	"syscall"
)

func checkPathPerms(path string, uid uint32) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	return checkInfoPerms(path, fi, uid)
}

func checkInfoPerms(path string, fi os.FileInfo, uid uint32) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("permission checks unsupported on this platform (%s)", path)
	}
	if st.Uid != uid && st.Uid != 0 {
		return fmt.Errorf("%s: owned by uid %d, want %d or root", path, st.Uid, uid)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s: permissions %04o allow group/other writes", path, perm)
	}
	return nil
}
