package client

import "testing"

func TestPlaintextNote(t *testing.T) {
	cases := []struct {
		scheme string
		want   string
	}{
		{"ws", "wssh: note: plaintext ws:// transport; SSH crypto still applies, but prefer wss:// on untrusted networks"},
		{"wss", ""},
	}
	for _, tc := range cases {
		got := PlaintextNote(&Target{Scheme: tc.scheme})
		if got != tc.want {
			t.Errorf("PlaintextNote(scheme=%q) = %q, want %q", tc.scheme, got, tc.want)
		}
	}
}
