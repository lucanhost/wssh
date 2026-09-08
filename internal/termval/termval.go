// Package termval validates terminal type (TERM) values.
//
// Both wsshd and wssh use it to sanitize the TERM string exchanged in SSH
// pty-req requests before placing it in a child process environment or
// sending it in a pty request, falling back to "xterm-256color" when invalid.
package termval

func Valid(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
