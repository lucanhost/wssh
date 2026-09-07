package server

import (
	"net"
	"net/http"
	"strings"
)

func (s *Server) clientIP(r *http.Request) string {
	peer := hostFromAddr(r.RemoteAddr)
	if len(s.trustedProxies) == 0 {
		return peer
	}
	ip := net.ParseIP(peer)
	if ip == nil || !s.peerTrusted(ip) {
		return peer
	}
	if v := r.Header.Get("CF-Connecting-IP"); v != "" {
		if pip := net.ParseIP(strings.TrimSpace(v)); pip != nil {
			return pip.String()
		}
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		if pip := net.ParseIP(strings.TrimSpace(v)); pip != nil {
			return pip.String()
		}
	}
	if pip := xffClientIP(r.Header.Get("X-Forwarded-For"), s); pip != nil {
		return pip.String()
	}
	return peer
}

func hostFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func (s *Server) peerTrusted(ip net.IP) bool {
	for _, cidr := range s.trustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func xffClientIP(xff string, s *Server) net.IP {
	if xff == "" {
		return nil
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		pip := net.ParseIP(strings.TrimSpace(parts[i]))
		if pip == nil {
			continue
		}
		if !s.peerTrusted(pip) {
			return pip
		}
	}
	for _, p := range parts {
		if pip := net.ParseIP(strings.TrimSpace(p)); pip != nil {
			return pip
		}
	}
	return nil
}
