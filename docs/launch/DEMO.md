# 60-second Glassbox demo

## Goal

Show one complete idea: an agent action gets a receipt, the receipt is eligible for rollback, and Glassbox restores the file without erasing history.

## Recording setup

Use a fresh clone on Linux. Keep the terminal and browser large enough that text is readable at 1080p. Do not use real workspaces, credentials, or receipt stores.

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

Open <http://127.0.0.1:8765>.

## Shot list and narration

| Time | Picture | Narration |
|---|---|---|
| 0–7s | Dashboard hero and verified-chain indicator | “Agents can change files faster than we can review them. Glassbox gives each submitted action a local receipt.” |
| 7–16s | Summary cards and risk labels | “Receipts are redacted, risk-labeled, and joined into a keyed chain so later tampering is detectable.” |
| 16–28s | Open receipt #3 | “This file write includes before and after text, so Glassbox encrypted the previous state and marked it rollback-eligible.” |
| 28–38s | Point to hashes and the undo control | “Undo is not automatic. Glassbox verifies the full chain and rechecks the live file, path, workspace, inode, ownership, mode, and ACL.” |
| 38–49s | Confirm **Safely undo this change** | “If anything changed after the recorded action, rollback fails closed instead of overwriting newer work.” |
| 49–56s | Timeline with receipt #5 | “A successful rollback restores the file and adds a new receipt. History is never silently rewritten.” |
| 56–60s | Repository URL and quick-start commands | “Glassbox is local-first, Apache-2.0, and available now as an alpha for Linux.” |

## On-screen closing card

```text
Glassbox
Receipts and guarded rollback for AI agents

github.com/jckm14/glassbox
```

## Accuracy checklist

- Say “submitted action,” not “automatically intercepted action.”
- Say “tamper-evident,” not “tamper-proof.”
- Say “guarded rollback,” not “guaranteed safe undo.”
- Keep the Linux and alpha labels visible in the description.
- Do not show real receipt exports, signing keys, recovery paths, or workspace content.
