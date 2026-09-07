package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

var errAccessDenied = errors.New("access denied")

func lookupShell(username string) string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) >= 7 && fields[0] == username {
			return fields[6]
		}
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
	if err := checkStrictModes(u, path); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
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

// checkStrictModes enforces the same invariants as OpenSSH StrictModes: the
// authorized_keys file, its .ssh directory, and the user's home directory must
// be owned by the user (or root) and must not be group- or world-writable.
// Any violation is an authentication error (fail closed).
func checkStrictModes(u *user.User, path string) error {
	if u.HomeDir == "" {
		return errors.New("user has no home directory")
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return fmt.Errorf("invalid uid %q for user %q", u.Uid, u.Username)
	}
	uid := uint32(uid64)
	for _, dir := range []string{u.HomeDir, filepath.Dir(path), path} {
		fi, err := os.Stat(dir)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("permission checks unsupported on this platform (%s)", dir)
		}
		if st.Uid != uid && st.Uid != 0 {
			return fmt.Errorf("%s: owned by uid %d, want %d or root", dir, st.Uid, uid)
		}
		if perm := fi.Mode().Perm(); perm&0o022 != 0 {
			return fmt.Errorf("%s: permissions %04o allow group/other writes", dir, perm)
		}
	}
	return nil
}
