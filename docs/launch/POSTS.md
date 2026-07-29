# Glassbox launch posts

Replace only bracketed personalization before posting. Recheck community rules and every product claim against the current README on launch day.

## Show HN

### Submission

**Title:** Show HN: Glassbox – a local action ledger and guarded rollback for AI agents

**URL:** <https://github.com/jckm14/glassbox>

Link directly to the working repository, not to the launch article. This follows the Show HN requirement that readers can try the project without a signup barrier.

### First comment

Hi HN — I built Glassbox because an agent’s chat history does not tell me whether a specific action is still safe to reverse.

Glassbox is a local-first action ledger for AI agents. Integrations submit events after execution, and Glassbox records readable receipts with the agent, action, target, summary, timestamp, deterministic risk, and redacted metadata. Receipts are authenticated in an HMAC-SHA256 chain so later changes are detectable.

For eligible UTF-8 file writes, the integration supplies before and after text. Glassbox encrypts the previous state locally. A confirmed rollback proceeds only if the complete chain verifies and live filesystem checks still agree on the workspace, path, file identity, content, ownership, mode, and POSIX ACL. Successful rollback adds a new receipt instead of rewriting history.

The main limitations are intentional and documented: it is alpha, Linux-only, loopback-only, and does not automatically intercept agent tools. SQLite and arbitrary workspace filesystems also cannot share one crash-atomic transaction.

The demo takes a few commands and uses synthetic data:

```bash
git clone https://github.com/jckm14/glassbox.git
cd glassbox
uv sync --locked --group dev
uv run glassbox demo --workspace ./demo-workspace --data-dir ./.glassbox-data
uv run glassbox serve --workspace ./demo-workspace --data-dir ./.glassbox-data
```

I would especially value feedback on the trust boundary: what evidence would make you permit or reject rollback in an agent system?

## X

### Standalone post

I built Glassbox: a local-first receipt ledger for AI agents, with tamper evidence and guarded rollback for eligible text-file writes. It’s an Apache-2.0 Linux alpha; integrations submit events explicitly. Demo and security model: https://github.com/jckm14/glassbox

Attach [`../assets/launch/social-card.png`](../assets/launch/social-card.png) or the walkthrough GIF.

### Five-post thread

**1/5**

An agent’s chat history is not an operational audit trail. I built Glassbox to record submitted agent actions as local, readable receipts—and to ask whether one specific file write is still eligible for rollback.

**2/5**

Receipts include the agent, action, target, summary, timestamp, deterministic risk, and redacted metadata. HMAC-SHA256 chaining makes later changes detectable and identifies the first broken receipt.

**3/5**

For an eligible text write, the integration supplies before and after content. Glassbox encrypts the previous state, then checks the live content, inode, workspace, ownership, mode, ACL, and chain before rollback.

**4/5**

Rollback never deletes the original action. It restores through a Linux atomic exchange, retains displaced content for recovery, and appends a new receipt. If the file or its surroundings changed, it fails closed.

**5/5**

Glassbox is alpha, Linux-only, loopback-only, and does not intercept tools automatically. I’m looking for agent developers willing to run the demo and challenge the trust model: https://github.com/jckm14/glassbox

## LinkedIn

I have been working on a narrow trust problem in agent systems: what would it take to undo one file write without silently overwriting newer work?

The result is Glassbox, an Apache-2.0, local-first action ledger for AI agents.

Integrations submit completed actions to Glassbox. It creates readable receipts with deterministic risk labels, redacts common credential patterns, and authenticates receipt history with an HMAC-SHA256 chain.

For eligible UTF-8 file writes, the integration can submit before and after text. Glassbox encrypts the previous state and permits rollback only after the complete chain and live filesystem checks pass. A successful rollback creates a new receipt rather than erasing history.

The project is intentionally candid about its current boundaries: Linux only, local loopback operation, no automatic tool interception, and no claim of cross-filesystem crash atomicity.

I’m looking for developers who run agents against real files and can answer three questions:

1. Which actions need receipts?
2. Which actions must be reversible?
3. What evidence would make you trust—or reject—a rollback?

Repository and demo: <https://github.com/jckm14/glassbox>

#AIAgents #OpenSource #SecurityEngineering

## Reddit: r/LocalLLaMA

**Suggested title:** I built a local receipt ledger and guarded rollback experiment for AI agents

I have been experimenting with a problem that becomes more visible as local agents gain tool access: chat history tells me what the model said, but not necessarily what reached disk or whether restoring the old bytes would overwrite newer work.

Glassbox is an Apache-2.0 Linux alpha that runs locally. An integration posts completed actions to a loopback API. Glassbox records readable receipts with risk labels and redacted metadata, then authenticates them in an HMAC chain.

For eligible UTF-8 file writes, the integration supplies before and after text. Glassbox stores the previous state encrypted and performs rollback only when the full chain and live file, path, inode, workspace, ownership, mode, and ACL checks still agree. Rollback adds another receipt instead of removing the original action.

Important limits: it does not intercept tools automatically, it is not cross-platform, and it is not a general reversal mechanism for shell commands or outbound messages.

The demo uses synthetic data and takes a few commands: <https://github.com/jckm14/glassbox>

I would value practical feedback from people running local agents: where would you place the event-submission hook, and which tool actions would actually need rollback?

Before posting, check the community’s current self-promotion and flair rules. Disclose that you built the project and do not ask for votes.

## Reddit: r/selfhosted

**Suggested title:** Glassbox: a loopback-only receipt ledger for local AI-agent actions

I built Glassbox to explore a self-hosting question: if an agent can edit files on a machine, can its action history and rollback material stay on that same machine?

Glassbox runs locally on Linux with SQLite, a local signing key, and a loopback-only FastAPI dashboard. There is no required cloud service, analytics, CDN, or remote database. The bundled CLI refuses non-loopback bind addresses because the alpha has no remote authentication.

Integrations submit completed actions. Glassbox records readable HMAC-chained receipts, deterministic risk labels, and redacted metadata. Eligible text-file writes can include an encrypted previous state; rollback proceeds only after chain and live filesystem checks pass.

This is not ready to expose remotely, and it is not a replacement for backups. The documented limitations include Linux-only filesystem requirements, protected recovery directories that need operator cleanup, and the lack of a crash-atomic transaction spanning SQLite and an arbitrary workspace filesystem.

Repository and local demo: <https://github.com/jckm14/glassbox>

For people operating agents at home: would a same-host ledger be useful, or would you need containers, retention controls, authenticated remote access, or a specific agent integration first?

Before posting, check the community’s current self-promotion and flair rules. Do not reuse the LocalLLaMA post verbatim.

## Design-partner outreach

### Subject

Could I learn how you audit local agent actions?

### Email or DM

Hi [Name],

I’m building Glassbox, an alpha Linux tool that keeps a local receipt ledger for submitted AI-agent actions and offers guarded rollback for eligible text-file writes.

I’m reaching out because [one specific sentence about their public project or workflow]. I’m not looking for an endorsement. I would like to understand how you currently inspect agent changes, which actions need evidence, and what would make you refuse an automated rollback.

Would you be open to a 20–30 minute conversation? If it is relevant, I can also send the four-command synthetic demo first: <https://github.com/jckm14/glassbox>

Thanks,
Chris

Send no more than one brief follow-up. Do not add contacts to a mailing list without permission.

## Thirty-minute interview guide

### 0–3 minutes: context and consent

- Explain that this is product research, not a sales call.
- Ask permission before taking notes or recording.
- Confirm that no confidential workspace content or credentials should be shared.

### 3–10 minutes: current workflow

- Which agent or automation do you run?
- What tools can it call, and where does it run?
- How do you review what it changed today?
- Tell me about the last agent action you wanted to reverse.

### 10–18 minutes: receipts

- Which actions need durable receipts?
- What fields would make a receipt useful during an incident?
- Who needs to read or verify it?
- How long should receipt and recovery material remain?

### 18–25 minutes: rollback trust

- Which actions should never be automatically reversible?
- What live conflicts must block a file rollback?
- What evidence would make you approve one?
- What would you inspect after a rollback?

Use this neutral description only after learning the current workflow:

> Glassbox runs locally on Linux. Integrations submit completed actions. It records readable, HMAC-chained receipts with deterministic risk and redacted metadata. Eligible text writes can include an encrypted previous state, and rollback proceeds only when the chain and live filesystem checks pass.

### 25–28 minutes: reaction

- What maps to your workflow?
- What does not?
- Which limitation prevents a trial?
- Which integration would remove the most friction?

### 28–30 minutes: close

- Ask whether they want the demo link.
- Ask whether a follow-up after a prototype is welcome.
- Ask permission before quoting or naming them publicly.
- Record the next step; do not imply a commitment they did not make.
