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

type Overlay struct {
	Addr           *string  `toml:"addr"`
	Path           *string  `toml:"path"`
	HostKey        *string  `toml:"hostkey"`
	Cert           *string  `toml:"cert"`
	Key            *string  `toml:"key"`
	Rate           *float64 `toml:"rate"`
	TrustedProxies []string `toml:"trusted_proxies"`
}

type Config struct {
	Addr           string
	Path           string
	HostKey        string
	Cert           string
	Key            string
	Rate           float64
	TrustedProxies []string
}

func Defaults() Config {
	return Config{
		Addr:    ":8080",
		Path:    "/ws",
		HostKey: "/etc/wssh/host_key",
		Rate:    1,
	}
}

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

func (c Config) Validate() error {
	if (c.Cert == "") != (c.Key == "") {
		return errors.New("-cert and -key must be given together")
	}
	return nil
}
