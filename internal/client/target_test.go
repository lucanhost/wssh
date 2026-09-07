package client

import "testing"

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in    string
		want  Target
		fails bool
	}{
		{in: "alice@server", want: Target{Scheme: "ws", User: "alice", Host: "server", Port: 80, Path: "/ws"}},
		{in: "wss://bob@srv", want: Target{Scheme: "wss", User: "bob", Host: "srv", Port: 443, Path: "/ws"}},
		{in: "carol@box:8080", want: Target{Scheme: "ws", User: "carol", Host: "box", Port: 8080, Path: "/ws"}},
		{in: "wss://dan@h:8443/ws/custom", want: Target{Scheme: "wss", User: "dan", Host: "h", Port: 8443, Path: "/ws/custom"}},
		{in: "ws://eve@h:8080", want: Target{Scheme: "ws", User: "eve", Host: "h", Port: 8080, Path: "/ws"}},
		{in: "server", fails: true},
		{in: "ftp://a@b", fails: true},
		{in: "user@", fails: true},
		{in: "user@:8080", fails: true},
		{in: "user@host:notaport", fails: true},
		{in: "user@host:99999", fails: true},
	}
	for _, tc := range cases {
		got, err := ParseTarget(tc.in)
		if tc.fails {
			if err == nil {
				t.Errorf("ParseTarget(%q) = %+v, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", tc.in, err)
			continue
		}
		if *got != tc.want {
			t.Errorf("ParseTarget(%q) = %+v, want %+v", tc.in, *got, tc.want)
		}
	}
}

func TestWebSocketURL(t *testing.T) {
	tg, _ := ParseTarget("alice@server")
	if got := tg.WebSocketURL(); got != "ws://server:80/ws" {
		t.Fatalf("WebSocketURL = %q", got)
	}
	tg, _ = ParseTarget("wss://bob@srv")
	if got := tg.WebSocketURL(); got != "wss://srv:443/ws" {
		t.Fatalf("WebSocketURL = %q", got)
	}
	if got := tg.SSHAddr(); got != "srv:443" {
		t.Fatalf("SSHAddr = %q", got)
	}
}

func TestParseTargetIPv6(t *testing.T) {
	cases := []struct {
		in   string
		want Target
	}{
		{in: "user@[::1]:8080", want: Target{Scheme: "ws", User: "user", Host: "::1", Port: 8080, Path: "/ws"}},
		{in: "wss://user@[2001:db8::1]/ws", want: Target{Scheme: "wss", User: "user", Host: "2001:db8::1", Port: 443, Path: "/ws"}},
		{in: "user@[::1]", want: Target{Scheme: "ws", User: "user", Host: "::1", Port: 80, Path: "/ws"}},
	}
	for _, tc := range cases {
		got, err := ParseTarget(tc.in)
		if err != nil {
			t.Errorf("ParseTarget(%q): %v", tc.in, err)
			continue
		}
		if *got != tc.want {
			t.Errorf("ParseTarget(%q) = %+v, want %+v", tc.in, *got, tc.want)
		}
	}
}

func TestTargetIPv6AddressForms(t *testing.T) {
	tg, err := ParseTarget("user@[::1]:8080")
	if err != nil {
		t.Fatal(err)
	}
	if got := tg.WebSocketURL(); got != "ws://[::1]:8080/ws" {
		t.Fatalf("WebSocketURL = %q, want %q", got, "ws://[::1]:8080/ws")
	}
	if got := tg.SSHAddr(); got != "[::1]:8080" {
		t.Fatalf("SSHAddr = %q, want %q", got, "[::1]:8080")
	}
	tg, err = ParseTarget("wss://user@[2001:db8::1]/ws")
	if err != nil {
		t.Fatal(err)
	}
	if got := tg.WebSocketURL(); got != "wss://[2001:db8::1]:443/ws" {
		t.Fatalf("WebSocketURL = %q, want %q", got, "wss://[2001:db8::1]:443/ws")
	}
	if got := tg.SSHAddr(); got != "[2001:db8::1]:443" {
		t.Fatalf("SSHAddr = %q, want %q", got, "[2001:db8::1]:443")
	}
}

func FuzzParseTarget(f *testing.F) {
	for _, seed := range []string{
		"alice@server",
		"wss://bob@srv:8443/custom",
		"user@host:8080",
		"ws://",
		"@host",
		"user@",
		"user@host:99999",
		"user@host:0",
		"user@host:-1",
		"ftp://a@b",
		"ws://user@[::1]:8080/ws",
		"ws://user@host/%zz",
		"ws://us%2Fer@host",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = ParseTarget(s)
	})
}
