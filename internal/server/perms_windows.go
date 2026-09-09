//go:build windows

package server

import (
	"os"
)

func checkPathPerms(path string, uid uint32) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	return checkInfoPerms(path, fi, uid)
}

func checkInfoPerms(path string, fi os.FileInfo, uid uint32) error {
	// Permission ownership checks are Unix-specific; on Windows ACLs
	// apply instead, so skip strict uid/mode enforcement.
	return nil
}
