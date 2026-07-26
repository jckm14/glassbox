#!/usr/bin/env python3
"""Start the launch-asset server on an atomically bound loopback socket."""

from __future__ import annotations

import argparse
import os
import socket
from datetime import UTC, tzinfo
from datetime import datetime as RealDateTime
from pathlib import Path
from typing import Any, Self

import uvicorn

from glassbox import store as store_module
from glassbox.app import create_app
from glassbox.cli import seed_demo

_FIXED_TIME = RealDateTime(2026, 7, 26, 16, 0, 0, tzinfo=UTC)


class FrozenDateTime(RealDateTime):
    """Provide stable receipt timestamps for generated public demo assets."""

    @classmethod
    def now(cls, tz: tzinfo | None = None) -> Self:
        value = (
            _FIXED_TIME.replace(tzinfo=None)
            if tz is None
            else _FIXED_TIME.astimezone(tz)
        )
        return cls(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            tzinfo=value.tzinfo,
            fold=value.fold,
        )


class LaunchIdentityApp:
    """Expose a run-specific readiness endpoint around the real Glassbox app."""

    def __init__(self, app: Any, nonce: str) -> None:
        self.app = app
        self.nonce = nonce
        self.ready_path = f"/__glassbox_launch_ready__/{nonce}"
        self.rollback_path = f"/__glassbox_launch_rollback__/{nonce}/3"

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http" and scope["path"] == self.ready_path:
            body = self.nonce.encode("ascii")
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [
                        (b"content-type", b"text/plain; charset=ascii"),
                        (b"cache-control", b"no-store"),
                        (b"content-length", str(len(body)).encode("ascii")),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        if (
            scope["type"] == "http"
            and scope["method"] == "POST"
            and scope["path"] == self.rollback_path
        ):
            delegated_scope = dict(scope)
            delegated_scope["path"] = "/api/events/3/rollback"
            delegated_scope["raw_path"] = b"/api/events/3/rollback"
            await self.app(delegated_scope, receive, send)
            return
        await self.app(scope, receive, send)


def _publish_port(path: Path, port: int) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, f"{port}\n".encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--port-file", type=Path, required=True)
    args = parser.parse_args()

    if not args.nonce.isascii() or len(args.nonce) < 32:
        raise ValueError("launch nonce must be at least 32 ASCII characters")

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        port = int(listener.getsockname()[1])

        store_module.datetime = FrozenDateTime  # type: ignore[misc]
        seed_demo(args.workspace, args.data_dir)
        app = LaunchIdentityApp(
            create_app(data_dir=args.data_dir, workspace=args.workspace), args.nonce
        )
        _publish_port(args.port_file, port)

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            access_log=False,
        )
        server = uvicorn.Server(config)
        server.run(sockets=[listener])
        return 0
    finally:
        listener.close()


if __name__ == "__main__":
    raise SystemExit(main())
