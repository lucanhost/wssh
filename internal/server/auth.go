package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

var errAccessDenied = errors.New("access denied")

func lookupShell(username string) string {
	// 1. Try /etc/passwd first (Linux and most Unix systems)
	f, err := os.Open("/etc/passwd")
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Split(line, ":")
			if len(fields) >= 7 && fields[0] == username {
				return strings.TrimSpace(fields[6])
			}
		}
	}
	// 2. Fallback for macOS, which uses OpenDirectory
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("dscl", ".", "-read", "/Users/"+username, "UserShell")
		if out, err := cmd.Output(); err == nil {
			parts := strings.SplitN(string(out), ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	// 3. Fallback for Windows
	if runtime.GOOS == "windows" {
		// Try COMSPEC environment variable (typically cmd.exe)
		if shell := os.Getenv("COMSPEC"); shell != "" {
			return shell
		}
		// Default to standard Windows command prompt
		return "C:\\Windows\\System32\\cmd.exe"
	}

	return ""
}

func (s *Server) publicKeyCallback(meta ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	username := meta.User()
	if !s.root && username != s.currentUsername {
		s.logger.Warn("auth rejected: user not permitted", "user", username, "remote", meta.RemoteAddr())
		return nil, errAccessDenied
	}
	u, err := user.Lookup(username)
	if err != nil {
		s.logger.Warn("auth rejected: unknown user", "user", username)
		return nil, errAccessDenied
	}
	keys, err := s.loadAuthorizedKeys(u)
	if err != nil {
		s.logger.Warn("auth rejected: cannot read authorized_keys", "user", username, "err", err)
		return nil, errAccessDenied
	}
	for _, k := range keys {
		if bytes.Equal(k.Marshal(), pubKey.Marshal()) {
			s.logger.Info("auth ok", "user", username, "remote", meta.RemoteAddr())
			return &ssh.Permissions{
				Extensions: map[string]string{
					"uid":   u.Uid,
					"gid":   u.Gid,
					"user":  u.Username,
					"home":  u.HomeDir,
					"shell": lookupShell(username),
				},
			}, nil
		}
	}
	s.logger.Warn("auth rejected: key not authorized", "user", username, "remote", meta.RemoteAddr())
	return nil, errAccessDenied
}

func (s *Server) loadAuthorizedKeys(u *user.User) ([]ssh.PublicKey, error) {
	path := filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
	if s.authorizedKeysPath != nil {
		path = s.authorizedKeysPath(u)
	}
	f, err := openVerifiedAuthorizedKeys(path, u)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var keys []ssh.PublicKey
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue
		}
		keys = append(keys, key)
	}
	return keys, scanner.Err()
}

func openVerifiedAuthorizedKeys(path string, u *user.User) (*os.File, error) {
	if u.HomeDir == "" {
		return nil, errors.New("user has no home directory")
	}
	// Windows uses SIDs for Uid, not numeric strings. Skip Unix-style checks.
	if runtime.GOOS == "windows" {
		return os.Open(path)
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid uid %q for user %q", u.Uid, u.Username)
	}
	uid := uint32(uid64)
	if err := checkPathPerms(u.HomeDir, uid); err != nil {
		return nil, err
	}
	if err := checkPathPerms(filepath.Dir(path), uid); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if err := checkInfoPerms(path, fi, uid); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
