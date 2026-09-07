package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func writeTOML(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wsshd.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValidTOML(t *testing.T) {
	path := writeTOML(t, `
addr = ":9090"
path = "/ssh"
hostkey = "/tmp/host_key"
cert = "/tmp/cert.pem"
key = "/tmp/key.pem"
rate = 0
trusted_proxies = ["10.0.0.0/8", "192.168.0.0/16"]
`)
	o, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if o.Addr == nil || *o.Addr != ":9090" {
		t.Fatalf("addr = %v, want :9090", o.Addr)
	}
	if o.Path == nil || *o.Path != "/ssh" {
		t.Fatalf("path = %v, want /ssh", o.Path)
	}
	if o.HostKey == nil || *o.HostKey != "/tmp/host_key" {
		t.Fatalf("hostkey = %v, want /tmp/host_key", o.HostKey)
	}
	if o.Cert == nil || *o.Cert != "/tmp/cert.pem" {
		t.Fatalf("cert = %v, want /tmp/cert.pem", o.Cert)
	}
	if o.Key == nil || *o.Key != "/tmp/key.pem" {
		t.Fatalf("key = %v, want /tmp/key.pem", o.Key)
	}
	if o.Rate == nil || *o.Rate != 0 {
		t.Fatalf("rate = %v, want pointer to 0", o.Rate)
	}
	want := []string{"10.0.0.0/8", "192.168.0.0/16"}
	if !slices.Equal(o.TrustedProxies, want) {
		t.Fatalf("trusted_proxies = %v, want %v", o.TrustedProxies, want)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err == nil {
		t.Fatal("missing file: want error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing file error = %v, want 'not found'", err)
	}
}

func TestLoadMalformedTOML(t *testing.T) {
	path := writeTOML(t, "addr = [unclosed")
	if _, err := Load(path); err == nil {
		t.Fatal("malformed TOML: want error")
	}
}

func TestMergeRateZeroIsDisableNotAbsent(t *testing.T) {
	zero := 0.0
	got := Merge(Defaults(), &Overlay{Rate: &zero})
	if got.Rate != 0 {
		t.Fatalf("Rate = %v, want 0 (rate=0 must disable, not fall back to default)", got.Rate)
	}
}

func TestMergePrecedence(t *testing.T) {
	fileAddr, cliAddr := ":1111", ":2222"
	got := Merge(Defaults(), &Overlay{Addr: &fileAddr}, &Overlay{Addr: &cliAddr})
	if got.Addr != ":2222" {
		t.Fatalf("CLI overlay should win: Addr = %q, want :2222", got.Addr)
	}
	got = Merge(Defaults(), &Overlay{Addr: &fileAddr}, nil)
	if got.Addr != ":1111" {
		t.Fatalf("file overlay should beat default: Addr = %q, want :1111", got.Addr)
	}
	got = Merge(Defaults(), nil, nil)
	if got.Addr != ":8080" {
		t.Fatalf("absent should keep default: Addr = %q, want :8080", got.Addr)
	}
}

func TestMergeTrustedProxies(t *testing.T) {
	tp := []string{"fd00::/8"}
	got := Merge(Defaults(), &Overlay{TrustedProxies: tp})
	if !slices.Equal(got.TrustedProxies, tp) {
		t.Fatalf("TrustedProxies = %v, want %v", got.TrustedProxies, tp)
	}
	if got := Merge(Defaults(), nil); got.TrustedProxies != nil {
		t.Fatalf("absent TrustedProxies = %v, want nil", got.TrustedProxies)
	}
}

func TestValidateCertKeyPairing(t *testing.T) {
	if err := (Config{Cert: "/c", Key: "/k"}).Validate(); err != nil {
		t.Fatalf("cert+key should validate: %v", err)
	}
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("neither should validate: %v", err)
	}
	if err := (Config{Cert: "/c"}).Validate(); err == nil {
		t.Fatal("cert without key should fail validation")
	}
	if err := (Config{Key: "/k"}).Validate(); err == nil {
		t.Fatal("key without cert should fail validation")
	}
}
