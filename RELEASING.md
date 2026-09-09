# Releasing wssh

## Versioning

wssh uses [Semantic Versioning](https://semver.org/). The project is pre-v1
(unstable API); breaking changes may occur in any `v0.x` release.

## Creating a release

1. Land code changes first. Every behavior-changing commit updates
   `CHANGELOG.md` under `[Unreleased]` in the same commit.
2. Cut the release as a separate commit: move the `[Unreleased]` entries
   into a new versioned section (with date and compare links), commit only
   the changelog, then tag:

   ```bash
   git tag -a v0.1.0 -m "v0.1.0: initial release"
   git push origin v0.1.0
   ```

   Never bundle code changes and the release-changelog commit together.

3. The `release` workflow builds cross-platform binaries and publishes a
   GitHub release automatically.
4. Verify the release at https://github.com/lucanhost/wssh/releases.

## Pre-release

Use a hyphenated suffix: `v0.2.0-rc.1`. The release workflow marks these as
pre-release automatically.
