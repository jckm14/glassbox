from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

import uvicorn

from .app import create_app
from .store import EventStore

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}


def _loopback_host(value: str) -> str:
    if value not in _LOOPBACK_HOSTS:
        raise argparse.ArgumentTypeError(
            "Glassbox has no remote authentication; --host must be 127.0.0.1 or localhost"
        )
    return value


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
    serve.add_argument(
        "--data-dir", type=Path, default=Path("~/.glassbox").expanduser()
    )

    demo = commands.add_parser("demo", help="Create a safe sample receipt timeline")
    demo.add_argument(
        "--workspace", type=Path, default=Path.cwd() / "glassbox-demo-workspace"
    )
    demo.add_argument("--data-dir", type=Path, default=Path("~/.glassbox").expanduser())
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


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        seed_demo(args.workspace, args.data_dir)
        print(f"Demo timeline created in {args.data_dir.expanduser().resolve()}")
        return 0
    if args.command == "serve":
        app = create_app(data_dir=args.data_dir, workspace=args.workspace)
        uvicorn.run(app, host=args.host, port=args.port)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
