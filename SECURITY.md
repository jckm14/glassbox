# Security Policy

## Supported versions

Glassbox is an early-stage security-sensitive project. Security fixes are provided for the latest released `0.1.x` version only. Users should upgrade to the newest patch release before reporting an issue.

| Version | Supported |
| --- | --- |
| Latest `0.1.x` | Yes |
| Earlier releases | No |

## Reporting a vulnerability

Please **do not open a public issue** for a suspected vulnerability.

Use [GitHub private vulnerability reporting](https://github.com/jckm14/glassbox/security/advisories/new) to submit a confidential report. Include:

- The affected version and operating system
- A minimal reproduction or proof of concept
- The expected and observed behavior
- Potential impact, including any workspace escape, alias mutation, data loss, plaintext disclosure, receipt-chain bypass, or rollback inconsistency
- Any suggested remediation, if available

You should receive an acknowledgement within three business days. We will coordinate validation, remediation, disclosure, and release timing through the private advisory. Glassbox does not currently operate a paid bug-bounty program.

## Security boundaries

Glassbox is local-first and deliberately refuses remote binding through its bundled CLI. It does not provide authentication for separately engineered remote deployments.

Rollback recovery directories can intentionally contain displaced plaintext workspace content. They are private mode-`0700` directories and remain until an operator removes them after external writers are quiescent.

SQLite and an arbitrary workspace filesystem cannot participate in one crash-atomic transaction. See the limitations documented in the README before relying on rollback in critical workflows.
