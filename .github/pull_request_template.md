## Summary

<!-- What changes, and why? -->

## Security and failure boundaries

<!-- Describe effects on receipt integrity, confinement, rollback, recovery, browser security, or protected files. Write "No security-boundary change" when applicable. -->

## Verification

<!-- List the commands run and their actual results. -->

- [ ] Focused regression added or updated when behavior changed
- [ ] `uv run ruff format --check src tests`
- [ ] `uv run ruff check src tests`
- [ ] `uv run mypy src`
- [ ] `uv run python -m compileall -q src tests`
- [ ] `uv run pytest -q`
- [ ] `uv build`
- [ ] Clean-wheel smoke completed when packaging or runtime behavior changed

## Limitations and recovery impact

<!-- Note retained recovery plaintext, migration concerns, compatibility changes, or follow-up work. -->
