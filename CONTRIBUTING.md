# Contributing to Glassbox

Thanks for helping improve Glassbox. The project treats receipt integrity, path confinement, rollback consistency, and recovery-data protection as product behavior rather than optional hardening.

## Development setup

Glassbox currently requires Linux. Install `uv` and the POSIX ACL utilities, then run:

```bash
sudo apt-get install acl
uv sync --locked --group dev
```

## Quality checks

Before opening a pull request, run the same checks as CI:

```bash
uv run ruff format --check src tests scripts/render-launch-server.py scripts/validate-launch-assets.py scripts/publish-launch-assets.py
uv run ruff check src tests scripts/render-launch-server.py scripts/validate-launch-assets.py scripts/publish-launch-assets.py
shellcheck scripts/render-launch-assets.sh
uv run mypy src scripts/render-launch-server.py scripts/validate-launch-assets.py scripts/publish-launch-assets.py
uv run python -m compileall -q src tests scripts/render-launch-server.py scripts/validate-launch-assets.py scripts/publish-launch-assets.py
uv run pytest -q
uv build
```

## Security-sensitive changes

Changes to receipt signing, database publication, filesystem traversal, rollback, recovery, redaction, browser mutation protection, or security-file handling must follow this sequence:

1. Add a focused regression that fails against the vulnerable behavior.
2. Confirm the regression fails for the expected reason.
3. Implement the smallest safe correction.
4. Run the focused regression.
5. Run the complete quality and build checks.
6. Exercise a clean wheel installation when packaging or runtime behavior changes.
7. Request an independent adversarial review before making release claims.

Do not weaken a fail-closed check merely to support a filesystem or platform that lacks the required Linux facilities.

## Pull requests

Keep pull requests focused and describe:

- The problem and user-visible behavior
- Security assumptions and failure boundaries
- Tests added or changed
- Verification commands and actual results
- Known limitations or follow-up work

By submitting a contribution, you agree that it is licensed under the Apache License 2.0.

## Vulnerabilities

Do not disclose suspected vulnerabilities in public issues or pull requests. Follow [SECURITY.md](SECURITY.md) instead.
