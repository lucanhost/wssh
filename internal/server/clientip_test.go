package server

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name           string
		trustedProxies []string
		remoteAddr     string
		headers        map[string]string
		want           string
	}{
		{
			name:       "no trusted proxies ignores XFF",
			remoteAddr: "203.0.113.7:1234",
			headers:    map[string]string{"X-Forwarded-For": "198.51.100.1"},
			want:       "203.0.113.7",
		},
		{
			name:           "untrusted peer ignores XFF",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "203.0.113.7:1234",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.1"},
			want:           "203.0.113.7",
		},
		{
			name:           "trusted peer CF-Connecting-IP",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:443",
			headers:        map[string]string{"CF-Connecting-IP": "198.51.100.9"},
			want:           "198.51.100.9",
		},
		{
			name:           "trusted peer X-Real-IP without CF header",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:443",
			headers:        map[string]string{"X-Real-IP": "198.51.100.10"},
			want:           "198.51.100.10",
		},
		{
			name:           "trusted peer XFF rightmost untrusted wins",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:443",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.20, 10.0.0.9"},
			want:           "198.51.100.20",
		},
		{
			name:           "trusted peer XFF all trusted falls back to leftmost",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:443",
			headers:        map[string]string{"X-Forwarded-For": "10.0.0.9, 10.0.0.8"},
			want:           "10.0.0.9",
		},
		{
			name:           "bare IP trusted proxy",
			trustedProxies: []string{"127.0.0.1"},
			remoteAddr:     "127.0.0.1:9999",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.1"},
			want:           "198.51.100.1",
		},
		{
			name:           "malformed trusted proxy entry skipped",
			trustedProxies: []string{"banana", "10.0.0.0/8"},
			remoteAddr:     "10.0.0.5:443",
			headers:        map[string]string{"X-Forwarded-For": "198.51.100.1"},
			want:           "198.51.100.1",
		},
		{
			name:           "IPv6 trusted peer with IPv6 XFF entry",
			trustedProxies: []string{"2001:db8::/32"},
			remoteAddr:     "[2001:db8::5]:443",
			headers:        map[string]string{"X-Forwarded-For": "2606:4700::99"},
			want:           "2606:4700::99",
		},
		{
			name:           "IPv6 untrusted peer keeps bracket-stripped host",
			trustedProxies: []string{"10.0.0.0/8"},
			remoteAddr:     "[2001:db8::5]:443",
			want:           "2001:db8::5",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signer, _ := testSigner(t)
			s := New(Config{Signer: signer, TrustedProxies: tc.trustedProxies})
			r := &http.Request{RemoteAddr: tc.remoteAddr, Header: http.Header{}}
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := s.clientIP(r); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHostFromAddr(t *testing.T) {
	if got := hostFromAddr("192.0.2.1:8080"); got != "192.0.2.1" {
		t.Fatalf("hostFromAddr = %q, want 192.0.2.1", got)
	}
	if got := hostFromAddr("[2001:db8::1]:80"); got != "2001:db8::1" {
		t.Fatalf("hostFromAddr = %q, want 2001:db8::1", got)
	}
	if got := hostFromAddr("noport"); got != "noport" {
		t.Fatalf("hostFromAddr = %q, want noport", got)
	}
}
