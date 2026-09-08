# Changelog

See [GitHub Releases](https://github.com/lucanhost/wssh/releases) for
auto-generated release notes from commit history.

## [Unreleased]

## [0.1.0] - 2026-09-08

Initial release.

- `wsshd`: SSH-over-WebSocket daemon — public-key auth, root/non-root modes
  with privilege drop, PTY + exec sessions, per-IP rate limiting with
  reverse-proxy-aware client IP extraction, TOML config file, handshake caps,
  StrictModes permission checks
- `wssh`: CLI client — interactive shell (raw terminal, SIGWINCH resize) and
  one-shot exec mode, known_hosts verification with TOFU prompt, exit-code
  propagation
- `-version` flag on both binaries; release binaries stamped via
  `-ldflags -X main.version`
- Release artifacts for linux/darwin on amd64/arm64

[Unreleased]: https://github.com/lucanhost/wssh/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lucanhost/wssh/releases/tag/v0.1.0
