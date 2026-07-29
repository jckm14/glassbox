# Why “Undo” Is Hard for AI Agents—and How Glassbox Approaches It

An AI agent edits a deployment manifest, rewrites a project plan, or changes a configuration file. A minute later, you realize the action was wrong.

“Undo it” sounds simple. It is not.

The agent may remember what it intended to do, but intent is not a transaction log. A chat transcript may describe the change, but it does not prove which bytes reached disk. Even if you captured the old content, restoring it blindly could erase work written after the agent finished.

I built [Glassbox](https://github.com/jckm14/glassbox) to explore a narrower question:

> What evidence and live checks would make one specific agent file write eligible for rollback?

Glassbox is an Apache-2.0, local-first receipt ledger for submitted agent actions. It is alpha software, currently limited to Linux, and deliberately explicit about what it cannot guarantee.

## An audit log is necessary, but not sufficient

A useful action receipt needs more than “the agent edited a file.” Glassbox records the agent, action, target, summary, timestamp, risk label, and redacted metadata. For a reversible text-file write, the integration also supplies the content before and after the action.

Glassbox hashes both states and encrypts the previous text locally. API responses expose the fingerprints rather than returning raw snapshots. If either text state is missing, the event can still be recorded, but it is not rollback-eligible.

This matters because a pathname alone is not a reversible operation. A useful rollback record must answer at least three questions:

1. What state existed before the action?
2. What state did the action claim to install?
3. Does the same file object still contain that resulting state now?

The third question is where a backup and an undo mechanism diverge. A backup can restore old bytes on request. A guarded rollback must first decide whether doing so would destroy newer work or replace the wrong object.

## Receipts are chained, not merely listed

Each Glassbox receipt includes the authenticated hash of the preceding receipt. Glassbox serializes signed fields into canonical JSON and authenticates them with HMAC-SHA256 using a local key.

Verification walks the complete chain and reports the first broken receipt. This detects changes to authenticated receipt semantics and encrypted snapshots. Equivalent JSON formatting is normalized, so adding whitespace does not count as tampering.

HMAC chaining has boundaries. It is local-key authentication, not public-key attestation. Receipt IDs are not authenticated, and without an external chain-head anchor, deletion of a valid suffix is not detectable. Glassbox documents those limits rather than describing the ledger as “tamper-proof.”

Rollback is gated on complete-chain verification. If the ledger no longer verifies, Glassbox refuses to restore from it.

## “The file still has the same content” is not enough

Suppose an agent wrote `config.toml`, and the current bytes still match the recorded post-action hash. That sounds safe to undo.

But the pathname may now refer to a different inode. A parent directory may have been swapped. The final component may have become a symbolic link. Ownership, permissions, or POSIX ACLs may have changed. Another process may still hold an old file descriptor and write through it after a replacement.

Glassbox therefore treats content equality as one condition, not proof of object identity.

At startup, it opens the configured workspace component by component from the filesystem root without following symlinks, then retains that workspace descriptor. During rollback it traverses from the held descriptor, opens parent directories with no-follow semantics, and requires the target to be an existing UTF-8 regular file.

Before and around the exchange boundary, Glassbox checks the target’s content, inode identity, owner, mode, POSIX ACL, parent identity, workspace identity, and restore candidate. If those checks no longer agree with the receipt and current policy, rollback fails closed.

## Replacement should be atomic—and recoverable

A pathname-based “check, then overwrite” sequence leaves a race between validation and replacement. Glassbox instead requires Linux `renameat2(..., RENAME_EXCHANGE)` support and performs a directory-descriptor-relative atomic exchange.

The old file is not immediately deleted. Glassbox retains the displaced inode inside a newly created mode-`0700` recovery directory on the same filesystem. This matters when another process opened the file before the exchange: late writes through that descriptor remain linked to recoverable data rather than disappearing with an unlinked inode.

A successful rollback creates a new receipt. Glassbox never edits or removes the original action from history. The timeline shows both the original write and the later rollback.

If synchronous validation fails after the exchange, Glassbox attempts a guarded reverse exchange. Operation identifiers are generated before filesystem mutation so that, if receipt persistence raises after a commit, Glassbox can reconcile the committed rollback receipt instead of blindly reversing the filesystem into a contradictory state.

## The 60-second demo

The current demo runs locally and uses synthetic sample data:

```bash
git clone https://github.com/jckm14/glassbox.git
cd glassbox
uv sync --locked --group dev
uv run glassbox demo \
  --workspace ./demo-workspace \
  --data-dir ./.glassbox-data
uv run glassbox serve \
  --host 127.0.0.1 \
  --port 8765 \
  --workspace ./demo-workspace \
  --data-dir ./.glassbox-data
```

Open <http://127.0.0.1:8765>. The dashboard shows four receipts, deterministic risk labels, complete-chain verification, and one rollback-eligible file write.

Open receipt #3 and request rollback. Glassbox asks for confirmation, runs its live checks, restores the prior file state, and appends receipt #5 for the rollback. The verified event count increases rather than history being rewritten.

The bundled server accepts only `127.0.0.1` or `localhost`. There is no remote authentication in the alpha, so it refuses wildcard and non-loopback bind addresses.

## What Glassbox does not solve

The largest limitation is integration. Glassbox records events submitted after execution; it does not automatically intercept agent tools. If an integration omits an action, submits incorrect before or after content, or crashes between a file write and receipt submission, Glassbox cannot reconstruct missing truth.

Rollback currently covers eligible UTF-8 `file.write` actions. It does not reverse arbitrary shell commands, restore binary files, recreate deleted accounts, or retract outbound messages.

The project is Linux-only today. Store initialization and publication rely on directory descriptors and `O_TMPFILE`; rollback requires a filesystem supporting atomic exchange. Glassbox fails closed rather than falling back to a less safe replacement sequence.

SQLite and an arbitrary workspace filesystem cannot participate in one crash-atomic transaction. Glassbox compensates failures it observes and reconciles known post-commit exceptions, but a process or power failure in the file-to-ledger interval may require manual recovery.

Successful rollback also retains protected recovery directories containing displaced plaintext workspace content. An operator must remove them after external writers are quiescent; the alpha does not garbage-collect them automatically.

These are not footnotes. They define where the current trust model ends.

## Who should try it

Glassbox is most useful today for developers who:

- run agents locally on Linux;
- can add a small HTTP call after a tool action;
- care about inspecting exactly what an agent changed;
- want to experiment with evidence-based rollback rather than unconditional restoration; and
- are comfortable evaluating alpha security infrastructure in a non-critical workspace.

The next product decisions should come from real workflows rather than a longer feature list. Which agent actions need receipts? Which actions must be reversible? What evidence would make an operator trust—or reject—a rollback?

If those questions match a system you are building, run the demo and add your workflow to the [alpha feedback issue](https://github.com/jckm14/glassbox/issues/8). Integration requests have their own structured issue form, and suspected vulnerabilities should go through [private security reporting](https://github.com/jckm14/glassbox/security/advisories/new).

Glassbox is available at <https://github.com/jckm14/glassbox>.
