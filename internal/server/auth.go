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
