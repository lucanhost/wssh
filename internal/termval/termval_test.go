package termval

import "testing"

func TestTermValid(t *testing.T) {
	valid := []string{"xterm-256color", "linux", "vt100", "x", "a.b_c-d", "TERM123"}
	invalid := []string{"", "xterm\n", "\x1b[2k", "x term", "x:y",
		string(make([]byte, 65)), "xterm\r"}
	for _, v := range valid {
		if !Valid(v) {
			t.Errorf("Valid(%q) = false, want true", v)
		}
	}
	for _, inv := range invalid {
		if Valid(inv) {
			t.Errorf("Valid(%q) = true, want false", inv)
		}
	}
}
