from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import urlsplit

from .client import DEFAULT_URL, GlassboxClient, GlassboxError
from .hooks import handle_claude_code_hook, hook_settings
from .lock import WriterLock, read_holder_info
from .store import EventStore, RollbackError, validate_external_event

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}
_T = TypeVar("_T")


def __getattr__(name: str) -> Any:
    # uvicorn and FastAPI are imported only by ``serve`` so that one-shot
    # commands such as the Claude Code hook start quickly.
    if name == "uvicorn":
        import uvicorn

        return uvicorn
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


class CommandError(Exception):
    """A user-facing failure: printed without a traceback, exit status 1."""


def _loopback_host(value: str) -> str:
    if value not in _LOOPBACK_HOSTS:
        raise argparse.ArgumentTypeError(
            "Glassbox has no remote authentication; --host must be 127.0.0.1 or localhost"
        )
    return value


def _default_data_dir() -> Path:
    return Path(os.environ.get("GLASSBOX_DATA_DIR") or "~/.glassbox").expanduser()


def _add_data_dir(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=_default_data_dir(),
        help="Ledger directory (default: $GLASSBOX_DATA_DIR or ~/.glassbox)",
    )


def _add_url(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--url",
        default=os.environ.get("GLASSBOX_URL"),
        help="Running Glassbox server to use when it owns the data directory "
        f"(default: the server's published address, else {DEFAULT_URL})",
    )


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Print JSON")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glassbox", description="Receipts and safe undo for AI agents"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="Run the local Glassbox dashboard")
    serve.add_argument(
        "--host",
        default="127.0.0.1",
        type=_loopback_host,
        help="Loopback bind address: 127.0.0.1 or localhost",
    )
    serve.add_argument("--port", default=8765, type=int)
    serve.add_argument("--workspace", type=Path, default=Path.cwd())
    _add_data_dir(serve)
    serve.add_argument(
        "--show-diffs",
        action="store_true",
        help="Let the dashboard display decrypted file changes",
    )
    serve.add_argument(
        "--prune-older-than-days",
        type=float,
        default=None,
        metavar="DAYS",
        help="Delete stored snapshots and diffs older than DAYS while serving",
    )

    demo = commands.add_parser("demo", help="Create a safe sample receipt timeline")
    demo.add_argument(
        "--workspace", type=Path, default=Path.cwd() / "glassbox-demo-workspace"
    )
    _add_data_dir(demo)

    record = commands.add_parser("record", help="Record one agent action")
    record.add_argument("--agent", required=True)
    record.add_argument("--action", required=True, help="For example file.write")
    record.add_argument("--target", required=True)
    record.add_argument("--summary", required=True)
    record.add_argument("--before-text")
    record.add_argument("--after-text")
    record.add_argument("--before-file", type=Path, help="Read the previous text")
    record.add_argument("--after-file", type=Path, help="Read the resulting text")
    record.add_argument(
        "--metadata", default=None, help="JSON object stored with the receipt"
    )
    _add_data_dir(record)
    _add_url(record)
    _add_json(record)

    log = commands.add_parser("log", help="List receipts, newest first")
    log.add_argument("-n", "--limit", type=int, default=20)
    log.add_argument("--risk", choices=["low", "medium", "high"])
    log.add_argument("--agent")
    log.add_argument("--action")
    log.add_argument("--session", help="Only receipts with this metadata.session_id")
    log.add_argument("--search", help="Match summary, target, agent, or action")
    log.add_argument(
        "--reversible", action="store_true", help="Only receipts that can be undone"
    )
    _add_data_dir(log)
    _add_json(log)

    show = commands.add_parser("show", help="Show one receipt")
    show.add_argument("id", type=int)
    show.add_argument("--diff", action="store_true", help="Print the recorded change")
    _add_data_dir(show)
    _add_json(show)

    verify = commands.add_parser(
        "verify", help="Verify the receipt chain (exit status 1 when broken)"
    )
    verify.add_argument(
        "--expect-head",
        metavar="HASH",
        help="Also require this earlier `glassbox head` hash to still be in the chain",
    )
    _add_data_dir(verify)
    _add_json(verify)

    head = commands.add_parser(
        "head", help="Print the latest receipt hash to store outside this machine"
    )
    _add_data_dir(head)
    _add_json(head)

    export = commands.add_parser("export", help="Write every receipt as JSON")
    export.add_argument(
        "-o", "--output", type=Path, help="File to write (default: stdout)"
    )
    _add_data_dir(export)

    rollback = commands.add_parser("rollback", help="Undo one eligible file change")
    rollback.add_argument("id", type=int)
    rollback.add_argument("--workspace", type=Path, default=Path.cwd())
    rollback.add_argument("-y", "--yes", action="store_true", help="Do not prompt")
    _add_data_dir(rollback)
    _add_url(rollback)
    _add_json(rollback)

    prune = commands.add_parser(
        "prune", help="Delete stored snapshots and diffs; receipts are kept"
    )
    prune.add_argument("--keep-last", type=int, metavar="N")
    prune.add_argument("--older-than-days", type=float, metavar="DAYS")
    _add_data_dir(prune)
    _add_json(prune)

    hook = commands.add_parser("hook", help="Agent integrations")
    hook_commands = hook.add_subparsers(dest="hook_command", required=True)
    claude = hook_commands.add_parser(
        "claude-code", help="Claude Code hook: reads the hook payload from stdin"
    )
    claude.add_argument(
        "--print-config",
        action="store_true",
        help="Print the settings.json snippet that enables the hook and exit",
    )
    claude.add_argument("--agent", default="claude-code", help="Agent name to record")
    claude.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Workspace root (default: $CLAUDE_PROJECT_DIR, else the session cwd)",
    )
    _add_data_dir(claude)
    _add_url(claude)
    return parser


def seed_demo(workspace: Path, data_dir: Path) -> None:
    workspace = workspace.expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    plan = "# Launch plan\n\n- Publish the first Glassbox receipt\n- Invite three design partners\n"
    target = workspace / "launch-plan.md"
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"Refusing to overwrite existing demo file: {target}")
    store = EventStore(data_dir.expanduser().resolve())
    store.append(
        {
            "agent": "research-agent",
            "action": "tool.read",
            "target": "market-notes.md",
            "summary": "Sample: read product research notes before drafting the launch plan",
            "metadata": {
                "tool": "read_file",
                "duration_ms": 42,
                "synthetic": True,
            },
        }
    )
    store.append(
        {
            "agent": "build-agent",
            "action": "shell.exec",
            "target": "pytest",
            "summary": "Recorded a sample successful test run for the demo timeline",
            "metadata": {
                "exit_code": 0,
                "tests": 38,
                "synthetic": True,
            },
        }
    )
    try:
        with target.open("x", encoding="utf-8") as plan_file:
            plan_file.write(plan)
    except FileExistsError as exc:
        raise FileExistsError(
            f"Refusing to overwrite existing demo file: {target}"
        ) from exc
    store.append(
        {
            "agent": "planning-agent",
            "action": "file.write",
            "target": "launch-plan.md",
            "summary": "Created the initial launch plan",
            "before_text": "",
            "after_text": plan,
            "metadata": {"lines_added": 4},
        }
    )
    store.append(
        {
            "agent": "communications-agent",
            "action": "outbound.send",
            "target": "email:design-partners",
            "summary": "Sample: sent the launch draft to three reviewers",
            "metadata": {"recipients": 3, "approved": True, "synthetic": True},
        }
    )
    store.close()


# --- Opening the ledger -----------------------------------------------------------


def _resolve(data_dir: Path) -> Path:
    return data_dir.expanduser().resolve()


def _read(data_dir: Path, operation: Callable[[EventStore], _T]) -> _T:
    """Run a read against the ledger without disturbing a running server.

    The store is opened read-only. A server may publish a new database while
    the read is in flight, which the store reports as a changed entry; the
    read is then simply repeated against the new snapshot.
    """
    data_dir = _resolve(data_dir)
    if not (data_dir / "glassbox.db").exists():
        raise CommandError(f"No Glassbox ledger found in {data_dir}")
    last_error: Exception | None = None
    for attempt in range(6):
        try:
            store = EventStore(data_dir, read_only=True)
            try:
                return operation(store)
            finally:
                store.close()
        except RuntimeError as exc:
            if "changed" not in str(exc):
                raise CommandError(str(exc)) from exc
            last_error = exc
            time.sleep(0.05 * (attempt + 1))
    raise CommandError(f"Ledger kept changing while it was read: {last_error}")


def _server_url(data_dir: Path, explicit: str | None) -> str:
    url = explicit or read_holder_info(data_dir).get("url") or DEFAULT_URL
    if not isinstance(url, str):
        url = DEFAULT_URL
    host = urlsplit(url).hostname
    if explicit is None and host not in {"127.0.0.1", "localhost", "::1"}:
        raise CommandError("Refusing to use a non-loopback server address")
    return url


@contextmanager
def _writer(
    data_dir: Path, url: str | None
) -> Iterator[tuple[EventStore | None, GlassboxClient | None]]:
    """Yield ``(store, None)`` to write directly, or ``(None, client)``.

    When a server already holds the data directory's writer lock, writes go
    through its API; otherwise this process takes the lock for the duration.
    """
    data_dir = _resolve(data_dir)
    lock = WriterLock(data_dir)
    try:
        acquired = lock.acquire(timeout=0.0)
        if not acquired:
            info = read_holder_info(data_dir)
            if url is None and not info.get("url"):
                # Probably another one-shot command; wait for it to finish.
                acquired = lock.acquire(timeout=5.0)
        if not acquired:
            yield None, GlassboxClient(_server_url(data_dir, url))
            return
        store = EventStore(data_dir)
        try:
            yield store, None
        finally:
            store.close()
    except RuntimeError as exc:
        raise CommandError(str(exc)) from exc
    finally:
        lock.release()


def record_event(
    event: dict[str, Any], data_dir: Path, url: str | None
) -> dict[str, Any]:
    """Record one event, directly or through the server that owns the ledger."""
    try:
        validate_external_event(
            str(event.get("agent", "")), str(event.get("action", ""))
        )
    except ValueError as exc:
        raise CommandError(str(exc)) from exc
    with _writer(data_dir, url) as (store, client):
        if store is not None:
            return store.append(event)
        assert client is not None
        try:
            return client.record(**event)
        except GlassboxError as exc:
            raise CommandError(str(exc)) from exc


# --- Output -----------------------------------------------------------------------


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _short_time(value: Any) -> str:
    return str(value)[:19].replace("T", " ")


def _receipt_line(event: dict[str, Any]) -> str:
    flags = ""
    if event.get("rolled_back_by"):
        flags = f"  [rolled back by #{event['rolled_back_by']}]"
    elif event.get("reversible"):
        flags = "  [undo]"
    target = str(event["target"])
    if len(target) > 60:
        target = f"{target[:59]}…"
    return (
        f"#{event['id']:<5} {_short_time(event['created_at'])}  "
        f"{event['risk']:<6} {event['agent']:<18} {event['action']:<14} {target}{flags}"
    )


def _print_receipt(event: dict[str, Any]) -> None:
    rows = [
        ("Receipt", f"#{event['id']}"),
        ("Recorded", event["created_at"]),
        ("Agent", event["agent"]),
        ("Action", event["action"]),
        ("Target", event["target"]),
        ("Summary", event["summary"]),
        (
            "Risk",
            f"{event['risk']} — {event['risk_reason']}"
            if event.get("risk_reason")
            else event["risk"],
        ),
        (
            "Undo",
            f"rolled back by #{event['rolled_back_by']}"
            if event.get("rolled_back_by")
            else "eligible"
            if event.get("reversible")
            else "snapshot pruned"
            if event.get("snapshot_pruned")
            else "not available",
        ),
        ("Before", event.get("before_sha256") or "—"),
        ("After", event.get("after_sha256") or "—"),
        ("Previous", event["previous_hash"]),
        ("Hash", event["receipt_hash"]),
    ]
    for label, value in rows:
        print(f"{label + ':':<10} {value}")
    if event.get("metadata"):
        print("Metadata:")
        print(json.dumps(event["metadata"], indent=2, ensure_ascii=False))


# --- Commands ---------------------------------------------------------------------


def _text_argument(text: str | None, path: Path | None, label: str) -> str | None:
    if text is not None and path is not None:
        raise CommandError(f"Give --{label}-text or --{label}-file, not both")
    if path is None:
        return text
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CommandError(f"Could not read {path} as UTF-8 text: {exc}") from exc


def _command_record(args: argparse.Namespace) -> int:
    metadata: Any = {}
    if args.metadata is not None:
        try:
            metadata = json.loads(args.metadata)
        except ValueError as exc:
            raise CommandError(f"--metadata is not valid JSON: {exc}") from exc
        if not isinstance(metadata, dict):
            raise CommandError("--metadata must be a JSON object")
    event: dict[str, Any] = {
        "agent": args.agent,
        "action": args.action,
        "target": args.target,
        "summary": args.summary,
        "metadata": metadata,
    }
    before_text = _text_argument(args.before_text, args.before_file, "before")
    after_text = _text_argument(args.after_text, args.after_file, "after")
    if before_text is not None:
        event["before_text"] = before_text
    if after_text is not None:
        event["after_text"] = after_text
    receipt = record_event(event, args.data_dir, args.url)
    if args.json:
        _print_json(receipt)
    else:
        undo = ", undo eligible" if receipt.get("reversible") else ""
        print(
            f"Recorded receipt #{receipt['id']} ({receipt['risk']} risk{undo}) "
            f"{receipt['receipt_hash']}"
        )
    return 0


def _command_log(args: argparse.Namespace) -> int:
    page = _read(
        args.data_dir,
        lambda store: store.page_events(
            max(1, args.limit),
            risk=args.risk,
            agent=args.agent,
            action=args.action,
            session=args.session,
            query=args.search,
            reversible=True if args.reversible else None,
        ),
    )
    if args.json:
        _print_json(page)
        return 0
    for event in page["events"]:
        print(_receipt_line(event))
    shown = len(page["events"])
    print(f"{shown} of {page['total']} matching receipts")
    return 0


def _command_show(args: argparse.Namespace) -> int:
    def load(store: EventStore) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        event = store.get_event(args.id)
        diff = store.read_diff(args.id) if args.diff and event is not None else None
        return event, diff

    event, diff = _read(args.data_dir, load)
    if event is None:
        raise CommandError(f"Receipt #{args.id} not found")
    if args.json:
        _print_json({**event, "diff": diff} if args.diff else event)
        return 0
    _print_receipt(event)
    if diff is not None:
        print()
        print(diff["diff"] if diff["available"] else f"No diff: {diff['reason']}")
    return 0


def _command_verify(args: argparse.Namespace) -> int:
    def check(store: EventStore) -> dict[str, Any]:
        result = store.verify()
        if args.expect_head:
            result["anchor_found"] = store.has_receipt(args.expect_head)
        return result

    result = _read(args.data_dir, check)
    anchor_ok = result.get("anchor_found", True)
    if args.json:
        _print_json(result)
    elif not result["valid"]:
        print(
            f"BROKEN: receipt chain fails at #{result['broken_at']} "
            f"({result['event_count']} receipts)"
        )
    elif not anchor_ok:
        print(
            "BROKEN: the expected head hash is no longer in the chain; "
            "receipts were removed or replaced"
        )
    else:
        print(f"OK: {result['event_count']} receipts verified")
    return 0 if result["valid"] and anchor_ok else 1


def _command_head(args: argparse.Namespace) -> int:
    head = _read(args.data_dir, lambda store: store.head())
    if args.json:
        _print_json(head)
    elif head["head_hash"] is None:
        print("The ledger is empty")
    else:
        print(
            f"{head['head_hash']}  receipt #{head['head_id']} of {head['event_count']}"
        )
    return 0


def _command_export(args: argparse.Namespace) -> int:
    payload = json.dumps(
        _read(args.data_dir, lambda store: store.export()),
        indent=2,
        ensure_ascii=False,
    )
    if args.output is None:
        print(payload)
    else:
        args.output.write_text(f"{payload}\n", encoding="utf-8")
        print(f"Exported receipts to {args.output}", file=sys.stderr)
    return 0


def _command_rollback(args: argparse.Namespace) -> int:
    if not args.yes:
        event = _read(args.data_dir, lambda store: store.get_event(args.id))
        if event is None:
            raise CommandError(f"Receipt #{args.id} not found")
        print(_receipt_line(event))
        answer = input(f"Undo receipt #{args.id}? [y/N] ")
        if answer.strip().lower() not in {"y", "yes"}:
            print("Nothing changed")
            return 1
    with _writer(args.data_dir, args.url) as (store, client):
        try:
            if store is not None:
                workspace, workspace_fd = EventStore.open_workspace(args.workspace)
                try:
                    identity = os.fstat(workspace_fd)
                    result = store.rollback(
                        args.id,
                        workspace,
                        (identity.st_dev, identity.st_ino),
                        workspace_fd,
                    )
                finally:
                    os.close(workspace_fd)
            else:
                assert client is not None
                result = client.rollback(args.id)
        except (RollbackError, GlassboxError) as exc:
            raise CommandError(f"Rollback refused: {exc}") from exc
        except OSError as exc:
            raise CommandError(
                "Workspace must be a real directory with no symlink components"
            ) from exc
    if args.json:
        _print_json(result)
        return 0
    print(
        f"Rolled back receipt #{args.id}; rollback receipt #{result['rollback_receipt_id']}"
    )
    if result.get("displaced_path"):
        print(f"Displaced content retained at {result['displaced_path']}")
    if result.get("restored_path"):
        print(f"Restored {result['restored_path']}")
    return 0


def _command_prune(args: argparse.Namespace) -> int:
    if args.keep_last is None and args.older_than_days is None:
        raise CommandError("Give --keep-last, --older-than-days, or both")
    with _writer(args.data_dir, None) as (store, _client):
        if store is None:
            raise CommandError(
                "A Glassbox server owns this ledger; stop it or run it with "
                "--prune-older-than-days"
            )
        try:
            result = store.prune_snapshots(
                keep_last=args.keep_last,
                older_than=timedelta(days=args.older_than_days)
                if args.older_than_days is not None
                else None,
            )
        except (ValueError, RuntimeError) as exc:
            raise CommandError(str(exc)) from exc
    if args.json:
        _print_json(result)
    else:
        print(
            f"Pruned stored content for {result['pruned']} receipts; "
            f"freed {result['bytes_freed']} bytes"
        )
    return 0


def _command_hook(args: argparse.Namespace) -> int:
    if args.print_config:
        _print_json(hook_settings())
        return 0
    # A hook must never block or fail the agent's tool call, so every problem
    # is reported on stderr and the exit status stays 0.
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise TypeError("hook payload must be a JSON object")
        handle_claude_code_hook(
            payload,
            data_dir=_resolve(args.data_dir),
            record=lambda event: record_event(event, args.data_dir, args.url),
            workspace=args.workspace,
            agent=args.agent,
        )
    except Exception as exc:  # noqa: BLE001 - see comment above
        print(f"glassbox hook: {exc}", file=sys.stderr)
    return 0


def _command_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .app import create_app

    host = "127.0.0.1" if args.host == "localhost" else args.host
    try:
        app = create_app(
            data_dir=args.data_dir,
            workspace=args.workspace,
            show_diffs=args.show_diffs,
            server_url=f"http://{host}:{args.port}",
            prune_older_than_days=args.prune_older_than_days,
        )
    except RuntimeError as exc:
        raise CommandError(str(exc)) from exc
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def _command_demo(args: argparse.Namespace) -> int:
    lock = WriterLock(_resolve(args.data_dir))
    try:
        if not lock.acquire(timeout=5.0):
            raise CommandError("A Glassbox server owns this ledger; stop it first")
    except RuntimeError as exc:
        raise CommandError(str(exc)) from exc
    try:
        seed_demo(args.workspace, args.data_dir)
    finally:
        lock.release()
    print(f"Demo timeline created in {_resolve(args.data_dir)}")
    return 0


_COMMANDS: dict[str, Callable[[argparse.Namespace], int]] = {
    "serve": _command_serve,
    "demo": _command_demo,
    "record": _command_record,
    "log": _command_log,
    "show": _command_show,
    "verify": _command_verify,
    "head": _command_head,
    "export": _command_export,
    "rollback": _command_rollback,
    "prune": _command_prune,
    "hook": _command_hook,
}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handler = _COMMANDS.get(args.command)
    if handler is None:
        return 2
    try:
        return handler(args)
    except CommandError as exc:
        print(f"glassbox: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
