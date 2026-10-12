# Support Glassbox

Glassbox helps answer two practical questions: what did my AI agent change, and can I safely undo it?

It is an open-source, local-first action ledger for AI agents. Integrations submit actions after execution; Glassbox records readable receipts, redacts common secret formats, and uses a keyed hash chain to make later changes to recorded receipts detectable. For eligible text-file writes, encrypted snapshots and live filesystem checks provide a guarded path back.

[Sponsor Glassbox on GitHub](https://github.com/sponsors/jckm14)

## What your support helps fund

- Maintenance and bug fixes for the receipt ledger and rollback workflow.
- Security-focused tests for conflicts, filesystem edge cases, and receipt integrity.
- Clearer documentation, practical examples, and easier integration with agent workflows.
- Dashboard improvements that make recorded actions easier to inspect.

Glassbox is alpha software for Linux. It records actions submitted by integrations; it does not automatically intercept agent tools or reverse arbitrary actions. Sponsorship supports development, not a guarantee of security, production readiness, or recovery. See the [security model and limitations](README.md#security-model).

## Individuals and teams

If Glassbox helps you understand an agent's behavior, a small recurring contribution helps sustain its maintenance. If your team benefits from it, business sponsorship is a way to support the open-source work you rely on.

Available amounts and benefits are listed on the GitHub Sponsors profile. Sponsorship does not include a support SLA, guaranteed response times, custom development, or control over the roadmap. Any separate services would require a separate agreement.

## Other ways to help

Try the demo, report reproducible bugs, improve the docs, share a useful integration, or contribute a fix. See [CONTRIBUTING.md](CONTRIBUTING.md). Please report suspected vulnerabilities privately using [SECURITY.md](SECURITY.md).
