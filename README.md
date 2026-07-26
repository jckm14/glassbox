# Glassbox

**Receipts and safe undo for AI agents.**

Glassbox is a local-first action ledger for AI agents. It records what an agent changed, explains the action in plain language, redacts common secret formats, labels risk, and chains every receipt with HMAC-SHA256 so later tampering is detectable.

Eligible file writes can be restored from encrypted snapshots. Rollback is restricted to a configured workspace and refuses to overwrite files that changed after the recorded action.

[![CI](https://github.com/jckm14/glassbox/actions/workflows/ci.yml/badge.svg)](https://github.com/jckm14/glassbox/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/jckm14/glassbox)](https://github.com/jckm14/glassbox/releases) [![Python](https://img.shields.io/badge/python-3.11%2B-3776ab)](https://www.python.org/) [![License](https://img.shields.io/badge/license-Apache--2.0-10b981)](LICENSE)

## Why this exists

AI agents are becoming capable of editing files, executing commands, and communicating on a user's behalf. Conventional chat history is not an operational audit trail. Glassbox gives every action a durable receipt:

- **What happened?** Agent, action, target, summary, timestamp, and metadata.
- **Was it dangerous?** Deterministic low, medium, or high risk labels.
- **Was the log changed later?** A keyed hash chain identifies the first broken receipt.
- **Can I undo it?** Encrypted pre-change snapshots for eligible file writes.
- **Will undo destroy newer work?** No—current content must match the recorded post-change hash.

## MVP features

- FastAPI ingestion and query API
- Responsive local dashboard with search and risk filters
- HMAC-SHA256 chained receipt log
- Automatic redaction for common API keys, bearer tokens, passwords, and secrets
- SHA-256 before/after fingerprints
- Fernet-encrypted rollback snapshots
- Workspace boundary and path-traversal protection
- Conflict-protected rollback with Linux atomic filesystem exchange
- Exportable signed receipt JSON from the dashboard
- Safe four-event demo timeline

## Quick start

```bash
git clone https://github.com/jckm14/glassbox.git
cd glassbox
uv sync --locked --group dev
```

Create a populated local demo:

```bash
uv run glassbox demo \
  --workspace ./demo-workspace \
  --data-dir ./.glassbox-data
```

Demo generation uses exclusive file creation and refuses to overwrite an existing `launch-plan.md`. Actions that are not actually executed by the generator are explicitly labeled as synthetic sample receipts.

Start the dashboard:

```bash
uv run glassbox serve \
  --host 127.0.0.1 \
  --port 8765 \
  --workspace ./demo-workspace \
  --data-dir ./.glassbox-data
```

Open <http://127.0.0.1:8765>. Because the MVP has no remote authentication, the CLI accepts only `127.0.0.1` or `localhost` as bind hosts and refuses wildcard or non-loopback addresses.

## Record an action

```bash
curl -X POST http://127.0.0.1:8765/api/events \
  -H 'Content-Type: application/json' \
  -d '{
    "agent": "my-agent",
    "action": "file.write",
    "target": "notes/plan.md",
    "summary": "Updated the project plan",
    "before_text": "old content",
    "after_text": "new content",
    "metadata": {"tool": "write_file"}
  }'
```

The API returns the receipt ID, risk label, content hashes, previous receipt hash, and receipt hash. Raw snapshots are never returned by the API.

### Supported action conventions

Glassbox accepts arbitrary action names. The MVP recognizes these for deterministic risk labels:

| Risk | Actions |
|---|---|
| High | `shell.exec`, `outbound.send`, `account.delete` |
| Medium | `file.write`, `file.delete`, `config.change` |
| Low | Reads and any other action |

A `file.write` is reversible only when both `before_text` and `after_text` are supplied. Glassbox encrypts the former for restoration and hashes the latter for conflict detection.

## Verify receipts

```bash
curl http://127.0.0.1:8765/api/verify
```

Example:

```json
{"valid": true, "event_count": 4, "broken_at": null}
```

If an authenticated receipt field or encrypted snapshot is modified so that its signed semantics change, `valid` becomes `false` and `broken_at` identifies the first affected receipt. Semantically equivalent JSON reformatting is normalized during verification and is not treated as tampering.

## Safe rollback

```bash
curl -X POST http://127.0.0.1:8765/api/events/3/rollback \
  -H 'Content-Type: application/json' \
  -d '{"confirm": true}'
```

Rollback succeeds only when all of these are true:

1. The receipt represents a reversible `file.write`.
2. Every parent component is opened beneath the configured workspace with directory descriptors and no-follow semantics.
3. The final target is an existing UTF-8 regular file opened without following symlinks.
4. Its current SHA-256, inode identity, owner UID/GID, file mode, and POSIX access ACL remain stable through the exchange boundary.
5. The encrypted snapshot passes its own integrity check and decrypts correctly.

Rollback uses an atomic directory-fd-relative filesystem exchange, then validates both the installed restore-candidate inode and the displaced inode identity, type, content, owner UID/GID, file mode, and POSIX access ACL. It also rechecks workspace/parent identities against the no-follow workspace descriptor held from application startup. If the candidate, target entry, ownership/access policy, parent, or configured workspace identity changed—or synchronous validation fails after exchange—Glassbox exchanges the displaced entry back and returns HTTP `409`. Restore candidates preserve the target owner UID/GID, mode, and POSIX access ACL while stripping inherited ACLs from the private recovery directory. Preservation intent is set before each exchange so an exception immediately after the syscall cannot trigger destructive cleanup. Restore candidates and retained inodes live inside a newly created mode-`0700` recovery directory in the target's parent filesystem. The retained inode keeps its original ownership and file mode rather than being chmodded or chowned, avoiding metadata changes through hard-link aliases outside the workspace; access is restricted by the private directory. Once an exchange has occurred, Glassbox retains that inode—on success, conflict, or compensation—and reports its path, so late writes through a descriptor opened before exchange remain linked and recoverable. Rollback receipts carry a unique operation identifier generated before filesystem mutation: if persistence raises after commit, Glassbox reconciles the committed receipt rather than compensating the filesystem into a contradictory state. Review and remove recovery directories only after external writers are quiescent. A successful rollback produces a new receipt; Glassbox never silently rewrites history.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Dashboard |
| `GET` | `/api/events` | Newest-first public receipt timeline |
| `POST` | `/api/events` | Record an agent action |
| `POST` | `/api/events/{id}/rollback` | Confirm and apply a safe file rollback |
| `GET` | `/api/verify` | Verify the complete receipt chain |
| `GET` | `/docs` | Interactive OpenAPI documentation |

## Security model

- Glassbox binds to `127.0.0.1` by default.
- The CLI refuses wildcard and non-loopback bind addresses; requests are restricted to loopback Host headers, and browser-originated mutations require a canonical same-origin `http`/`https` Origin when that header is present.
- The dashboard has no CDN, analytics, or external font requests.
- A restrictive Content Security Policy, frame protection, MIME sniffing protection, and no-referrer policy are applied to every response.
- The data directory must be an owned mode-`0700` real directory; existing symlinks or differently protected directories are rejected without chmodding their referents. The signing key and published database are owned, single-link mode-`0600` regular files pinned by descriptors. Receipt readers and writers share a store lock so publication cannot close or recycle a descriptor while a reader is using it. Receipt writes occur in a serialized in-memory SQLite copy, are serialized into an unnamed mode-`0600` file, and publish a finalized database snapshot with an atomic exchange. The previously published database inode is never mutated, so a hard link introduced at the commit boundary remains an unchanged historical snapshot rather than an alias Glassbox writes through.
- Before snapshots are encrypted at rest with a key derived from the local receipt key.
- Receipt responses expose hashes, not raw before/after content.
- Common credential patterns are redacted before summaries and metadata are stored.
- At application startup Glassbox opens the configured workspace component-by-component from the filesystem root without following symlinks and holds that descriptor for the application lifetime. Rollback traverses from the held descriptor, opens each parent directory without following symlinks, requires a no-follow regular-file target, and performs the Linux atomic exchange relative to pinned directory descriptors.
- Newer human or agent edits cause rollback to fail safely with HTTP `409`.

### MVP limitations

- It records events submitted by integrations; it does not yet intercept agent tools automatically.
- Redaction is defense in depth, not a substitute for avoiding secrets in telemetry.
- The signing key is local. Third-party attestation and public-key signatures are future work.
- Rollback currently supports UTF-8 text-file writes only.
- Glassbox currently requires Linux: store initialization and database publication use directory descriptors, `O_TMPFILE`, and `renameat2(..., RENAME_EXCHANGE)`, while rollback also requires a workspace filesystem supporting atomic exchange. Glassbox fails closed rather than falling back to unsafe pathname or replacement operations.
- SQLite and an arbitrary workspace filesystem cannot share one crash-atomic transaction. Glassbox compensates detected receipt-write failures and reconciles post-commit exceptions, but it does not fsync every affected directory into a cross-filesystem durability protocol; a process or power failure in the file-to-ledger interval may require manual reconciliation.
- Rollback exchanges intentionally retain private mode-`0700` recovery directories containing plaintext workspace content. Retained inodes keep their original file mode to avoid mutating hard-link aliases; the directory supplies access protection. Integrations should review and remove the entire recovery directory once external writers are quiescent; the MVP does not garbage-collect it automatically.
- Receipt HMACs do not authenticate SQLite row IDs and, without an external chain-head anchor, cannot detect deletion of a valid suffix. Public-key attestation and external anchoring are future work.
- Authentication is intentionally omitted. The bundled CLI therefore refuses non-loopback binding. Any separately engineered remote deployment requires authentication, CSRF protection, transport security, and explicit trusted-host configuration.

## Development

```bash
uv sync --locked --group dev
uv run ruff format --check src tests
uv run ruff check src tests
uv run mypy src
uv run python -m compileall -q src tests
uv run pytest -q
uv build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md), not through public issues.

## License

Glassbox is licensed under the [Apache License 2.0](LICENSE).

The API and rollback behavior are developed test-first. The suite covers recursive and compound sensitive-key redaction, valid and tampered receipt chains, malformed database values, encrypted-snapshot tampering, protected single-link key/database handling, complete rollback eligibility, atomic-exchange conflicts, same-content inode substitution, post-exchange interruption, post-commit receipt reconciliation, pinned-workspace identity, parent-directory and final-symlink substitution, hard-link alias safety, POSIX ACL preservation, private recovery directories, chain-gated rollback, receipt-failure compensation races, workspace escape attempts, concurrent receipt writers, DNS-rebinding/canonical-Origin defenses, non-loopback bind refusal, dashboard security, and safe CLI demo generation.
