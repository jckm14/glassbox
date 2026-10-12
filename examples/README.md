# Try a recorded file tool

This framework-neutral example shows where a file-writing agent tool can submit
a receipt. It uses the real Glassbox API through FastAPI's in-process TestClient,
not a live HTTP server. No model, API key, or external service is needed.

From the repository root on supported Linux:

```bash
uv sync --locked --group dev
uv run python examples/file_tool_demo.py
```

The script creates a private temporary workspace, makes a real synthetic file
edit, records it, and requests rollback. It checks the restored bytes. Next it
records another edit, simulates a newer human edit, and checks that rollback
returns HTTP 409 without replacing that newer text. Finally it verifies the
receipt chain and that all three receipts remain. Temporary demo files,
including retained recovery content, are removed after the client shuts down.

Expected output:

```text
1. Demo tool changed plan.txt and recorded a receipt.
2. Confirmed rollback restored the original file bytes.
3. Newer edit detected: rollback refused with HTTP 409.
4. Receipt chain verified; both writes and the rollback remain.
PASS: disposable demo files removed; no real workspace touched.
```

## Adapt the pattern to your agent

Read `recorded_demo_write` in [file_tool_demo.py](file_tool_demo.py). The integration
captures the previous text, executes the tool, and explicitly submits the
completed action with before/after text. For a separately running local Glassbox
server, use the same JSON with `POST http://127.0.0.1:8765/api/events`.

This demo wrapper assumes one trusted writer and a fixed disposable target. It
does not implement production path confinement, concurrent-write coordination,
retry deduplication, or recovery from interrupted receipt submission. Those are
integration responsibilities; do not expose this wrapper as an unrestricted
agent file tool. A write and its receipt are not one atomic transaction. If
submission fails, the write has already happened; inspect the result rather than
blindly retrying. Capture actual tool results, not just model intentions.

The demo confirms rollback programmatically because its files are disposable.
In a real workflow, require a deliberate user decision before requesting it.
Keep sensitive content out of telemetry: common-pattern redaction does not make
arbitrary file content safe to share. Follow the [security model and alpha
limitations](../README.md#security-model). This is not a supported integration
with any named agent framework, and it does not automatically intercept tools.

## Tell us what happened

We are looking for five early testers who run file-editing agents on Linux.
Try this example, then [share feedback](https://github.com/jckm14/glassbox/issues/8):

- Did all four steps pass? If not, what non-sensitive error appeared?
- Which agent framework or tool interface would you connect?
- What would prevent you from trying it in a disposable agent workspace?
- Would receipts, guarded rollback, or both help your workflow?

Do not paste receipt stores, file contents, keys, or private logs. Report suspected
vulnerabilities through [SECURITY.md](../SECURITY.md).

Testing is free and does not require sponsorship. If the project is useful,
[sponsor maintenance and testing](https://github.com/sponsors/jckm14).
