# Glassbox launch kit

This directory contains source material for introducing Glassbox to agent developers, security engineers, and self-hosters without overstating what the alpha does.

## Assets

- [`../assets/launch/dashboard.png`](../assets/launch/dashboard.png) — clean dashboard screenshot generated from synthetic demo data
- [`../assets/launch/walkthrough.gif`](../assets/launch/walkthrough.gif) — before/after walkthrough of a real guarded rollback
- [`../assets/launch/social-card.png`](../assets/launch/social-card.png) — 1280×640 sharing card for posts and repository social preview
- [`DEMO.md`](DEMO.md) — 60-second recording and narration script
- [`ARTICLE.md`](ARTICLE.md) — long-form technical launch article
- [`POSTS.md`](POSTS.md) — Show HN, social, Reddit, and outreach copy
- [`LAUNCH-CHECKLIST.md`](LAUNCH-CHECKLIST.md) — sequencing, community etiquette, and metrics

Regenerate the visual assets on Linux with Chromium and ImageMagick installed:

```bash
scripts/render-launch-assets.sh
```

The renderer creates isolated demo state under `/tmp`, binds a run-specific readiness endpoint to a pre-opened loopback socket, performs and verifies one real rollback, and uses explicit fail-closed checks that remain active under optimized Python to validate the exact file set, encoded formats, PNG/GIF container structure, logical canvases, raster dimensions, GIF frame count, and decoded private-data markers. It keeps same-parent staging mode `0700` through validation, binds the validated bytes to publication with a SHA-256 manifest, and applies public permissions immediately before atomically publishing the complete set. Publication refuses symbolic-link destinations, pins the publication parent, verifies the manifest before and after the rename boundary, and reverses or quarantines entries when identities or bytes changed. Normal completion and pre-publication failures remove staging through descriptor-relative identity-checked cleanup; an uncertain publication boundary preserves recovery entries rather than risking deletion. It fixes the receipt timestamp, timezone, and browser locale so repeated runs with the same local toolchain are stable.

Output is **not guaranteed byte-for-byte across different rendering toolchains**. Chromium, ImageMagick, and installed DejaVu font versions can alter pixels or encoding. Review generated diffs after any toolchain update rather than treating historical hashes as a release invariant.

## Canonical product facts

Keep public descriptions consistent with the current README and source:

- Glassbox is an Apache-2.0, local-first receipt ledger for submitted agent actions.
- Integrations post events to Glassbox; the alpha does not automatically intercept agent tools.
- HMAC chaining provides local tamper evidence but not public-key attestation or suffix-deletion detection without an external anchor.
- Rollback currently covers eligible UTF-8 regular-file writes on supported Linux filesystems.
- Rollback uses live chain, content, path, inode, ownership, mode, ACL, workspace, and restore-candidate checks.
- SQLite and arbitrary workspace filesystems do not share a crash-atomic transaction.
- The bundled server is loopback-only and has no remote authentication.

Do not claim customers, integrations, cross-platform support, remote deployment safety, automatic interception, complete crash atomicity, or adoption that does not yet exist.
