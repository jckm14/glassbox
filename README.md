# Glassbox

<p align="center"><strong>Your AI agent changed a file. Glassbox shows what happened—and gives you a guarded way back.</strong></p>

<p align="center">
  <a href="https://github.com/jckm14/glassbox/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jckm14/glassbox/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/jckm14/glassbox/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/jckm14/glassbox"></a>
  <a href="https://pypi.org/project/glassbox-agent/"><img alt="PyPI version" src="https://img.shields.io/pypi/v/glassbox-agent"></a>
  <a href="https://www.python.org/"><img alt="Python 3.11 or newer" src="https://img.shields.io/badge/python-3.11%2B-3776ab"></a>
  <a href="LICENSE"><img alt="Apache 2.0 license" src="https://img.shields.io/badge/license-Apache--2.0-10b981"></a>
</p>

<p align="center">
  <a href="#quick-start">Run the demo</a> ·
  <a href="#security-model">Read the security model</a> ·
  <a href="https://github.com/jckm14/glassbox/releases/latest">Download the latest release</a> ·
  <a href="https://github.com/jckm14/glassbox/issues/8">Share feedback</a>
</p>

![Glassbox dashboard showing a verified receipt chain, risk labels, and rollback eligibility](https://raw.githubusercontent.com/jckm14/glassbox/main/docs/assets/launch/dashboard.png)

Glassbox is a local-first action ledger for AI agents—a flight recorder with guarded rollback for eligible text-file changes. A bundled Claude Code hook, a command-line tool, or any integration submits actions to Glassbox after execution. Glassbox records a plain-language receipt, redacts common secret formats, assigns deterministic risk, and chains the receipt with HMAC-SHA256 so later tampering is detectable.

For file edits, creations, and deletions, integrations can submit the previous and resulting text. Glassbox encrypts the previous state and the diff locally and will undo the change only if the complete receipt chain verifies and live filesystem checks show that rollback will not overwrite newer work.

> [!IMPORTANT]
> Glassbox is alpha software for Linux. It records only what an integration or hook submits, and its rollback guarantees have explicit platform and durability limits. Read the [security model](#security-model) and [MVP limitations](#mvp-limitations) before protecting important work.

## See it in action

![Two-step Glassbox walkthrough: record an agent action, then restore the file while preserving history](https://raw.githubusercontent.com/jckm14/glassbox/main/docs/assets/launch/walkthrough.gif)

1. An integration records a `file.write` receipt with before and after text.
2. Glassbox marks the receipt rollback-eligible and encrypts the previous state.
3. A confirmed rollback runs live workspace, path, inode, ownership, mode, ACL, content, and chain checks.
4. The renderer verifies the restored file bytes; the dashboard shows a new rollback receipt and a valid chain.

## What you get

- **Readable receipts:** agent, action, target, summary, timestamp, risk, and redacted metadata.
- **Tamper evidence:** canonical HMAC-SHA256 chaining identifies the first broken receipt.
- **Guarded rollback:** encrypted snapshots and conflict checks for eligible UTF-8 file edits, creations, and deletions.
- **Works with your agent:** a Claude Code hook that records edits and shell commands with no code, plus a CLI and a dependency-free Python client.
- **Local operation:** SQLite, local keys, a loopback-only API, and no required cloud service.
- **Inspectable behavior:** an Apache-2.0 codebase, documented limitations, and security-focused tests.

## Why this exists

AI agents can edit files, execute commands, and communicate on a user's behalf. Chat history is not an operational audit trail, and a generic backup does not answer whether a particular agent action is still safe to reverse. Glassbox gives each submitted action a durable receipt:

- **What happened?** Agent, action, target, summary, timestamp, and metadata.
- **Was it dangerous?** Deterministic low, medium, or high risk labels.
- **Was the log changed later?** A keyed hash chain identifies the first broken receipt.
- **Can I undo it?** Encrypted pre-change snapshots for eligible file writes.
- **Will undo destroy newer work?** Current content and object identity must still match the recorded action.

## Current capabilities

- Claude Code hook that records file edits (with before and after text) and shell commands
- Command-line recording, listing, verification, rollback, export, and retention
- FastAPI ingestion and query API with paging and filters
- Local dashboard with search, filters, session grouping, live updates, and an opt-in diff view
- HMAC-SHA256 chained receipt log
- Automatic redaction of common credential formats in summaries, targets, and metadata
- Risk labels based on what an action touches, each with a recorded reason
- SHA-256 before/after fingerprints
- Fernet-encrypted rollback snapshots and diffs, stored as private files
- Workspace boundary and path-traversal protection
- Conflict-protected rollback of edits, creations, and deletions using Linux atomic filesystem operations
- Signed retention: prune stored content without breaking verification
- Exportable signed receipt JSON
- Safe four-event demo timeline

## Quick start

Install the released package on Linux with Python 3.11 or newer:

```bash
pip install glassbox-agent    # or: uv tool install glassbox-agent
glassbox --help
```

Or work from a clone, as the rest of this section does:

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

Useful `serve` options:

- `--show-diffs` lets the dashboard display the recorded change for a receipt. It is off by default, so the API serves hashes only.
- `--prune-older-than-days DAYS` deletes stored snapshots and diffs older than `DAYS` at startup and every six hours. Receipts are kept.

## Use it with Claude Code

Glassbox ships a [Claude Code hook](https://code.claude.com/docs/en/hooks). Print the settings and merge them into `.claude/settings.json` in your project (or `~/.claude/settings.json` for every project):

```bash
glassbox hook claude-code --print-config
```

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [{ "type": "command", "command": "glassbox hook claude-code", "timeout": 15 }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
        "hooks": [{ "type": "command", "command": "glassbox hook claude-code", "timeout": 15 }]
      }
    ],
    "PostToolUseFailure": [
      {
        "matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
        "hooks": [{ "type": "command", "command": "glassbox hook claude-code", "timeout": 15 }]
      }
    ]
  }
}
```

`glassbox` must be on the `PATH` Claude Code uses; otherwise put the absolute path to the executable in `command`. From then on:

- Each file edit becomes a `file.write` receipt, and each new file a `file.create` receipt, with the text before and after. Both can be undone.
- Each shell command becomes a `shell.exec` receipt labeled by what the command does. Command output is not recorded.
- Receipts carry the Claude Code session ID, so the dashboard and `glassbox log --session` can group them.
- Widen the `PostToolUse` matcher (for example to `*`) to record other tools as well.

The hook works with or without a running server: it writes to the ledger directly, or hands the receipt to `glassbox serve` when the server owns the ledger. It never blocks or fails a tool call; problems are printed to stderr. The ledger defaults to `~/.glassbox`; pass `--data-dir` (or set `GLASSBOX_DATA_DIR`) to keep one per project, and start `glassbox serve` with the same directory and the project as `--workspace`.

Before an edit runs, the hook holds the file's current text, unencrypted, in `<data-dir>/pending/` (a mode-`0700` directory). It is removed when the edit succeeds or fails; text left behind by an edit that never ran, such as one you denied, is removed by the next edit hook once it is an hour old. Content is recorded only for UTF-8 files up to 1 MB inside the workspace; other files get a receipt without content.

## Command line

Every command takes `--data-dir`. Read commands work while the server is running; `record` and `rollback` are handed to the server when it owns the ledger.

| Command | Purpose |
|---|---|
| `glassbox log` | List receipts; filter with `--risk`, `--agent`, `--action`, `--session`, `--search`, `--reversible` |
| `glassbox show ID --diff` | Show one receipt and its recorded change |
| `glassbox record` | Record an action from a script |
| `glassbox verify` | Verify the chain; exit status 1 when it is broken |
| `glassbox head` | Print the latest receipt hash |
| `glassbox rollback ID` | Undo one eligible file change in `--workspace` |
| `glassbox export -o receipts.json` | Write every receipt as JSON |
| `glassbox prune` | Delete stored snapshots and diffs (`--keep-last N`, `--older-than-days DAYS`) |

Receipt HMACs cannot show that the newest receipts were deleted. To detect that, save the output of `glassbox head` somewhere the agent cannot write, and later run `glassbox verify --expect-head HASH`: it fails if that receipt is no longer in the chain.

From Python, `glassbox.client.GlassboxClient` wraps the HTTP API using only the standard library:

```python
from glassbox.client import GlassboxClient

GlassboxClient().record(
    agent="my-agent",
    action="file.write",
    target="notes/plan.md",
    summary="Updated the project plan",
    before_text=old_text,
    after_text=new_text,
)
```

## Record an action

Want a runnable tool example first? [Try the file-tool integration demo](examples/README.md)
to verify a successful rollback and a refused rollback after a newer edit, using
disposable files and no model credentials.

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

### Risk labels

Glassbox accepts arbitrary action names and labels each receipt from the words in the action name and from the target. The same submission always gets the same label, and the receipt records the reason.

| Risk | Examples |
|---|---|
| High | Shell commands that delete recursively, escalate privileges, pipe a download into a shell, rewrite git history, change infrastructure, send data to a remote host, or touch credential files; sending, publishing, payment, and non-file delete actions; file changes to credential files or paths outside the workspace |
| Medium | Other shell commands; file writes, creations, and deletions inside the workspace; configuration changes; any action Glassbox does not recognize |
| Low | Read, search, and list actions; shell commands made only of read-only programs such as `ls`, `grep`, or `git status` |

For a shell action, the command is read from `metadata.command` when present, otherwise from `target`. Labels are a triage aid based on pattern matching, not a sandbox: a command Glassbox labels medium can still be destructive. Commands longer than 20,000 characters, or with a single statement longer than 2,000, are labeled high without analysis.

### Reversible actions

| Action | Supply | Rollback does |
|---|---|---|
| `file.write` | `before_text` and `after_text` | Restores the previous text |
| `file.create` | `after_text` only | Moves the created file into a private recovery directory |
| `file.delete` | `before_text` only | Recreates the file, only if nothing exists at that path |

Glassbox encrypts `before_text` for restoration, hashes `after_text` for conflict detection, and stores an encrypted diff. A recreated file gets mode `0600` unless the receipt's `metadata.mode` records the original permission bits (for example `"0644"`); group and other write bits and setuid bits are never restored. If `metadata.workspace` is present, rollback refuses to run in any other workspace.

The agent name `glassbox` and the actions `file.rollback` and `snapshot.prune` are reserved for receipts Glassbox writes itself; the API and CLI reject submissions that use them.

## Verify receipts

```bash
curl http://127.0.0.1:8765/api/verify
```

Example:

```json
{"valid": true, "event_count": 4, "broken_at": null}
```

If an authenticated receipt field or encrypted snapshot is modified so that its signed semantics change, or a snapshot file is missing without a signed prune receipt that names it, `valid` becomes `false` and `broken_at` identifies the first affected receipt. Semantically equivalent JSON reformatting is normalized during verification and is not treated as tampering.

## Safe rollback

```bash
curl -X POST http://127.0.0.1:8765/api/events/3/rollback \
  -H 'Content-Type: application/json' \
  -d '{"confirm": true}'
```

Rollback succeeds only when all of these are true:

1. The receipt represents a reversible `file.write` whose snapshot has not been pruned.
2. Every parent component is opened beneath the configured workspace with directory descriptors and no-follow semantics.
3. The final target is an existing UTF-8 regular file opened without following symlinks.
4. Its current SHA-256, inode identity, owner UID/GID, file mode, and POSIX access ACL remain stable through the exchange boundary.
5. The encrypted snapshot passes its own integrity check and decrypts correctly.

Rollback uses an atomic directory-fd-relative filesystem exchange, then validates both the installed restore-candidate inode and the displaced inode identity, type, content, owner UID/GID, file mode, and POSIX access ACL. It also rechecks workspace/parent identities against the no-follow workspace descriptor held from application startup. If the candidate, target entry, ownership/access policy, parent, or configured workspace identity changed—or synchronous validation fails after exchange—Glassbox exchanges the displaced entry back and returns HTTP `409`. Restore candidates preserve the target owner UID/GID, mode, and POSIX access ACL while stripping inherited ACLs from the private recovery directory. Preservation intent is set before each exchange so an exception immediately after the syscall cannot trigger destructive cleanup. Restore candidates and retained inodes live inside a newly created mode-`0700` recovery directory in the target's parent filesystem. The retained inode keeps its original ownership and file mode rather than being chmodded or chowned, avoiding metadata changes through hard-link aliases outside the workspace; access is restricted by the private directory. Once an exchange has occurred, Glassbox retains that inode—on success, conflict, or compensation—and reports its path, so late writes through a descriptor opened before exchange remain linked and recoverable. Rollback receipts carry a unique operation identifier generated before filesystem mutation: if persistence raises after commit, Glassbox reconciles the committed receipt rather than compensating the filesystem into a contradictory state. Review and remove recovery directories only after external writers are quiescent. A successful rollback produces a new receipt; Glassbox never silently rewrites history.

Rolling back a `file.create` or `file.delete` receipt applies the same chain, workspace, parent-directory, and no-follow checks, and uses an atomic no-replace rename instead of an exchange:

- **Created file:** the file must still be a UTF-8 regular file whose content matches the receipt. Glassbox moves it into a new mode-`0700` recovery directory beside it rather than unlinking it, then validates the moved inode and content. If validation or the rollback receipt fails, the file is moved back, unless something new already occupies its name, in which case it stays in the recovery directory and the response says where.
- **Deleted file:** nothing may exist at the target path, including a directory or symlink. Glassbox writes the restored text to a private candidate, renames it into place without replacing anything, and validates the result. If a file appears at the path first, rollback returns HTTP `409` and leaves it untouched; if the rollback receipt cannot be written, the restored file is withdrawn.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Dashboard |
| `GET` | `/api/events` | Newest-first receipt page; `limit`, `before_id`, `risk`, `agent`, `action`, `session`, `q`, `reversible` |
| `POST` | `/api/events` | Record an agent action |
| `GET` | `/api/events/{id}` | One receipt |
| `GET` | `/api/events/{id}/diff` | Recorded change; `403` unless the server runs with `--show-diffs` |
| `POST` | `/api/events/{id}/rollback` | Confirm and apply a safe file rollback |
| `GET` | `/api/verify` | Verify the complete receipt chain |
| `GET` | `/api/stats` | Whole-ledger counts, agents, sessions, and chain head |
| `GET` | `/api/head` | Latest receipt hash |
| `GET` | `/api/export` | Every receipt with the verification result |
| `GET` | `/api/config` | Server version, workspace, and whether diffs are served |
| `GET` | `/docs` | Interactive OpenAPI documentation |

`GET /api/events` returns `events`, the `total` number of matching receipts, and `next_before_id` to pass as `before_id` for the next page.

## Security model

- Glassbox binds to `127.0.0.1` by default.
- The CLI refuses wildcard and non-loopback bind addresses; requests are restricted to loopback Host headers, and browser-originated mutations require a canonical same-origin `http`/`https` Origin when that header is present.
- The dashboard has no CDN, analytics, or external font requests.
- A restrictive Content Security Policy, frame protection, MIME sniffing protection, and no-referrer policy are applied to every response.
- The data directory must be an owned mode-`0700` real directory; existing symlinks or differently protected directories are rejected without chmodding their referents. The signing key and published database are owned, single-link mode-`0600` regular files pinned by descriptors. Receipt readers and writers share a store lock so publication cannot close or recycle a descriptor while a reader is using it. Receipt writes occur in a serialized in-memory SQLite copy, are serialized into an unnamed mode-`0600` file, and publish a finalized database snapshot with an atomic exchange. The previously published database inode is never mutated, so a hard link introduced at the commit boundary remains an unchanged historical snapshot rather than an alias Glassbox writes through.
- Before snapshots and diffs are encrypted at rest with a key derived from the local receipt key. Each is stored as a mode-`0600` file named by the SHA-256 of its ciphertext in a pinned mode-`0700` `snapshots/` directory; files are created exclusively and never rewritten, and a file that is missing, relinked, re-permissioned, or altered fails verification. Only a signed `snapshot.prune` receipt written by Glassbox excuses a missing file. Prune and rollback receipts name the receipts they affect by receipt hash, not row ID, so renumbering rows cannot move them onto another receipt.
- Receipt responses expose hashes, not raw before/after content. Diffs are served only when the server is started with `--show-diffs`, and common credential patterns are redacted from them.
- Common credential patterns are redacted before summaries, targets, and metadata are stored. A file receipt whose target was changed by redaction is not reversible.
- Only one process writes to a data directory at a time. The server holds an advisory lock on `writer.lock` for its lifetime; one-shot commands take it briefly or send the write to the server. Read commands open the ledger read-only and never republish it.
- Integrations cannot submit receipts under the reserved `glassbox` agent or the `file.rollback` and `snapshot.prune` actions, which decide whether a receipt counts as rolled back or pruned.
- At application startup Glassbox opens the configured workspace component-by-component from the filesystem root without following symlinks and holds that descriptor for the application lifetime. Rollback traverses from the held descriptor, opens each parent directory without following symlinks, requires a no-follow regular-file target, and performs the Linux atomic exchange relative to pinned directory descriptors.
- Newer human or agent edits cause rollback to fail safely with HTTP `409`.

### MVP limitations

- It records events submitted by integrations and hooks. The Claude Code hook sees tool calls, not their side effects: a file changed or deleted by a shell command gets a `shell.exec` receipt with no snapshot.
- Risk labels come from pattern matching on action names and command text. They can be wrong in both directions and are not an enforcement mechanism.
- Redaction is defense in depth, not a substitute for avoiding secrets in telemetry.
- The signing key is local. Third-party attestation and public-key signatures are future work.
- Rollback currently supports UTF-8 text files only, up to 1 MB per snapshot. Diffs are not stored when the two texts together exceed 400,000 characters.
- Every write still republishes the receipt database, so write cost grows with the number of receipts, though no longer with snapshot size.
- Glassbox currently requires Linux: store initialization and database publication use directory descriptors, `O_TMPFILE`, and `renameat2(..., RENAME_EXCHANGE)`, while rollback also requires a workspace filesystem supporting atomic exchange. Glassbox fails closed rather than falling back to unsafe pathname or replacement operations.
- SQLite and an arbitrary workspace filesystem cannot share one crash-atomic transaction. Glassbox compensates detected receipt-write failures and reconciles post-commit exceptions, but it does not fsync every affected directory into a cross-filesystem durability protocol; a process or power failure in the file-to-ledger interval may require manual reconciliation.
- Rollback exchanges intentionally retain private mode-`0700` recovery directories containing plaintext workspace content. Retained inodes keep their original file mode to avoid mutating hard-link aliases; the directory supplies access protection. Integrations should review and remove the entire recovery directory once external writers are quiescent; the MVP does not garbage-collect it automatically, and `glassbox prune` does not touch it.
- Receipt HMACs do not authenticate SQLite row IDs and, without an external chain-head anchor, cannot detect deletion of a valid suffix. `glassbox head` and `glassbox verify --expect-head` let you keep and check such an anchor by hand; public-key attestation and automatic external anchoring are future work.
- Authentication is intentionally omitted. The bundled CLI therefore refuses non-loopback binding. Any separately engineered remote deployment requires authentication, CSRF protection, transport security, and explicit trusted-host configuration.

## Development

```bash
uv sync --locked --group dev
uv run ruff format --check src tests scripts/render-launch-server.py scripts/validate-launch-assets.py scripts/publish-launch-assets.py
uv run ruff check src tests scripts/render-launch-server.py scripts/validate-launch-assets.py scripts/publish-launch-assets.py
shellcheck scripts/render-launch-assets.sh
uv run mypy src scripts/render-launch-server.py scripts/validate-launch-assets.py scripts/publish-launch-assets.py
uv run python -m compileall -q src tests scripts/render-launch-server.py scripts/validate-launch-assets.py scripts/publish-launch-assets.py
uv run pytest -q
uv build
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Report suspected vulnerabilities privately according to [SECURITY.md](SECURITY.md), not through public issues.

## Support Glassbox

If Glassbox is useful to you or your team, [sponsor its development](https://github.com/sponsors/jckm14). Your support helps fund maintenance, security-focused testing, documentation, and integration examples.

Read [how sponsorship supports Glassbox](SPONSORSHIP.md). Bug reports, documentation improvements, and code contributions are welcome too.

## License

Glassbox is licensed under the [Apache License 2.0](LICENSE).

The API and rollback behavior are developed test-first. The suite covers recursive and compound sensitive-key redaction, valid and tampered receipt chains, malformed database values, encrypted-snapshot tampering, protected single-link key/database handling, complete rollback eligibility, atomic-exchange conflicts, same-content inode substitution, post-exchange interruption, post-commit receipt reconciliation, creation and deletion rollback races, snapshot-file substitution, signed pruning, legacy-ledger migration, reserved-name rejection, content-aware risk labels, the Claude Code hook, the single-writer lock, pinned-workspace identity, parent-directory and final-symlink substitution, hard-link alias safety, POSIX ACL preservation, private recovery directories, chain-gated rollback, receipt-failure compensation races, workspace escape attempts, concurrent receipt writers, DNS-rebinding/canonical-Origin defenses, non-loopback bind refusal, dashboard security, and safe CLI demo generation.
