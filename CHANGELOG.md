# Changelog

All notable changes to Glassbox are documented in this file. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-12

### Added

- Claude Code hook (`glassbox hook claude-code`) that records file edits with before and after text, new files, and shell commands
- CLI commands `record`, `log`, `show`, `verify`, `head`, `export`, `rollback`, and `prune`
- Rollback for `file.create` (moves the file to a private recovery directory) and `file.delete` (recreates it only where nothing exists)
- Encrypted diff stored with file receipts, shown by `glassbox show --diff` and, with `serve --show-diffs`, in the dashboard
- Signed snapshot retention: `glassbox prune` and `serve --prune-older-than-days`
- API paging and filters on `/api/events`, plus `/api/events/{id}`, `/api/events/{id}/diff`, `/api/stats`, `/api/head`, `/api/export`, and `/api/config`
- Dashboard server-side search and filters, session grouping, automatic refresh, whole-ledger metrics, and receipt metadata
- `glassbox.client.GlassboxClient`, a standard-library HTTP client
- Chain-head anchoring with `glassbox head` and `glassbox verify --expect-head`
- Release workflow that publishes to PyPI as `glassbox-agent` through trusted publishing

### Changed

- Risk labels now depend on what an action touches. Shell commands are high, medium, or low by content rather than always high, and unrecognized actions are medium rather than low. Each receipt records a `risk_reason`
- Encrypted snapshots are stored as private files instead of database rows; existing ledgers are migrated when opened and still verify
- `GET /api/events` also returns `total` and `next_before_id`
- A receipt that was rolled back or pruned is no longer reported as reversible
- The package version is defined once, in `src/glassbox/__init__.py`

### Security

- The receipt `target` is now redacted; previously a shell command line was stored as submitted
- Redaction covers GitHub, AWS, and Slack tokens, JWTs, private key blocks, URL credentials, and `--password`-style flags
- The `glassbox` agent name and the `file.rollback` and `snapshot.prune` actions are reserved, so integrations cannot forge them
- A single-writer lock prevents two processes from publishing the same ledger
- Rollback refuses a receipt recorded for a different workspace

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

[Unreleased]: https://github.com/jckm14/glassbox/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jckm14/glassbox/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/jckm14/glassbox/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jckm14/glassbox/releases/tag/v0.1.0
