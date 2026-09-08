# Releasing wssh

## Versioning

wssh uses [Semantic Versioning](https://semver.org/). The project is pre-v1
(unstable API); breaking changes may occur in any `v0.x` release.

## Creating a release

1. Ensure `main` is green (CI passing).
2. Tag the release:

   ```bash
   git tag -a v0.1.0 -m "v0.1.0: initial release"
   git push origin v0.1.0
   ```

3. The `release` workflow builds cross-platform binaries and publishes a
   GitHub release automatically.
4. Verify the release at https://github.com/lucanhost/wssh/releases.

## Pre-release

Use a hyphenated suffix: `v0.2.0-rc.1`. The release workflow marks these as
pre-release automatically.
