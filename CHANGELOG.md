# Changelog

All notable changes to Glassbox are documented in this file. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-07-26

### Added

- Apache License 2.0 licensing and package metadata
- Public security-reporting and contribution policies
- Reproducible GitHub Actions quality, test, and build checks
- Dependabot configuration for Python and GitHub Actions dependencies
- Package author, SPDX license, classifier, and project URL metadata

### Changed

- Public repository and installation links now point to `jckm14/glassbox`
- Development tools are locked in the `dev` dependency group

### Security

- Updated `cryptography` to 48.0.1 or newer to exclude wheels affected by the bundled OpenSSL vulnerability reported in GHSA-537c-gmf6-5ccf

## [0.1.0] - 2026-07-26

### Added

- Local-first HMAC-chained action receipts with recursive secret redaction
- Encrypted snapshots and guarded atomic rollback for eligible UTF-8 regular-file writes
- Descriptor-pinned workspace and protected copy-on-write database publication
- UID, GID, mode, inode, hard-link, POSIX ACL, and newer-work conflict checks
- Loopback-only API, self-contained dashboard, CLI, synthetic demo, and release packaging

[Unreleased]: https://github.com/jckm14/glassbox/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/jckm14/glassbox/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jckm14/glassbox/releases/tag/v0.1.0
