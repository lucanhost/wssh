// Package config implements wsshd configuration loading and merging.
//
// Configuration starts from Defaults, is overlaid by an optional TOML file
// (Load), and then by explicitly set CLI flags, producing a final Config via
// Merge. Overlay uses pointer fields so "unset" is distinguishable from a
// zero value: rate = 0 in the TOML file disables rate limiting rather than
// falling back to the default.
package config

import (
	"errors"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Overlay is a partially-specified configuration: unset fields are left
// untouched by Merge. Pointer fields make zero values distinguishable from
// absence — for example, rate = 0 in the TOML file disables rate limiting
// rather than restoring the default.
type Overlay struct {
	// Addr overrides the HTTP listen address.
	Addr *string `toml:"addr"`
	// Path overrides the WebSocket endpoint path.
	Path *string `toml:"path"`
	// HostKey overrides the SSH host key file path.
	HostKey *string `toml:"hostkey"`
	// Cert overrides the TLS certificate file.
	Cert *string `toml:"cert"`
	// Key overrides the TLS private key file.
	Key *string `toml:"key"`
	// Rate overrides the per-IP upgrade rate; 0 disables rate limiting.
	Rate *float64 `toml:"rate"`
	// TrustedProxies overrides the trusted proxy CIDR list; nil leaves the
	// previous value in place.
	TrustedProxies []string `toml:"trusted_proxies"`
}

// Config is the fully-resolved daemon configuration.
type Config struct {
	// Addr is the HTTP listen address.
	Addr string
	// Path is the WebSocket endpoint path.
	Path string
	// HostKey is the SSH host key file path.
	HostKey string
	// Cert is the TLS certificate file; empty disables TLS.
	Cert string
	// Key is the TLS private key file; empty disables TLS.
	Key string
	// Rate is the per-IP WebSocket upgrade rate; 0 disables rate limiting.
	Rate float64
	// TrustedProxies lists CIDRs (or bare IPs) trusted to send client-IP
	// forwarding headers.
	TrustedProxies []string
}

// Defaults returns the built-in configuration: addr ":8080", path "/ws",
// host key "/etc/wssh/host_key", rate 1, TLS disabled, no trusted proxies.
func Defaults() Config {
	return Config{
		Addr:    ":8080",
		Path:    "/ws",
		HostKey: "/etc/wssh/host_key",
		Rate:    1,
	}
}

// Load reads and parses the TOML config file at path. A missing or
// malformed file is an error.
func Load(path string) (*Overlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
		return nil, fmt.Errorf("cannot read config file %s: %w", path, err)
	}
	var o Overlay
	if err := toml.Unmarshal(data, &o); err != nil {
		return nil, fmt.Errorf("cannot parse config file %s: %w", path, err)
	}
	return &o, nil
}

// Merge layers overlays over base in order: each overlay's set fields
// replace the accumulated value and unset fields are skipped. Nil overlays
// are ignored.
func Merge(base Config, overlays ...*Overlay) Config {
	c := base
	for _, o := range overlays {
		if o == nil {
			continue
		}
		if o.Addr != nil {
			c.Addr = *o.Addr
		}
		if o.Path != nil {
			c.Path = *o.Path
		}
		if o.HostKey != nil {
			c.HostKey = *o.HostKey
		}
		if o.Cert != nil {
			c.Cert = *o.Cert
		}
		if o.Key != nil {
			c.Key = *o.Key
		}
		if o.Rate != nil {
			c.Rate = *o.Rate
		}
		if o.TrustedProxies != nil {
			c.TrustedProxies = o.TrustedProxies
		}
	}
	return c
}

// Validate reports whether the configuration is self-consistent: cert and
// key must be provided together.
func (c Config) Validate() error {
	if (c.Cert == "") != (c.Key == "") {
		return errors.New("-cert and -key must be given together")
	}
	return nil
}
