from __future__ import annotations

import json
import logging
import math
import os
import threading
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .lock import WriterLock
from .store import EventStore, RollbackError, validate_external_event

_PRUNE_INTERVAL_SECONDS = 6 * 60 * 60
_LOGGER = logging.getLogger(__name__)


class EventCreate(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)

    agent: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=120)
    target: str = Field(min_length=1, max_length=1000)
    summary: str = Field(min_length=1, max_length=4000)
    before_text: str | None = Field(default=None, max_length=1_000_000)
    after_text: str | None = Field(default=None, max_length=1_000_000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        def validate_node(node: Any, depth: int) -> None:
            if depth > 16:
                raise ValueError("metadata nesting exceeds 16 levels")
            if isinstance(node, float) and not math.isfinite(node):
                raise ValueError("metadata contains a non-finite number")
            if isinstance(node, dict):
                for key, child in node.items():
                    if len(key) > 1000:
                        raise ValueError("metadata key exceeds 1000 characters")
                    validate_node(child, depth + 1)
            elif isinstance(node, list):
                for child in node:
                    validate_node(child, depth + 1)

        validate_node(value, 0)
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(encoded) > 65_536:
            raise ValueError("metadata exceeds 65536 UTF-8 bytes")
        return value

    @model_validator(mode="after")
    def reject_reserved_names(self) -> EventCreate:
        validate_external_event(self.agent, self.action)
        return self


class RollbackRequest(BaseModel):
    confirm: bool


def create_app(
    *,
    data_dir: str | Path,
    workspace: str | Path,
    show_diffs: bool = False,
    server_url: str | None = None,
    prune_older_than_days: float | None = None,
) -> FastAPI:
    """Build the Glassbox application.

    ``show_diffs`` lets the API return decrypted file changes; it is off by
    default so receipts expose hashes only. ``server_url`` is published to
    one-shot commands so they can hand writes to this process. With
    ``prune_older_than_days`` the server deletes older stored snapshots and
    diffs at startup and every few hours.
    """
    writer_lock = WriterLock(Path(data_dir))
    if not writer_lock.acquire(timeout=5.0, info={"url": server_url}):
        raise RuntimeError(
            "Another Glassbox process is already writing to this data directory"
        )
    try:
        return _build_app(
            writer_lock=writer_lock,
            data_dir=data_dir,
            workspace=workspace,
            show_diffs=show_diffs,
            prune_older_than_days=prune_older_than_days,
        )
    except BaseException:
        writer_lock.release()
        raise


def _build_app(
    *,
    writer_lock: WriterLock,
    data_dir: str | Path,
    workspace: str | Path,
    show_diffs: bool,
    prune_older_than_days: float | None,
) -> FastAPI:
    app = FastAPI(title="Glassbox", version=__version__)

    @app.exception_handler(RequestValidationError)
    async def validation_error_response(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        del request
        details = [
            {
                "type": error.get("type", "validation_error"),
                "loc": error.get("loc", ()),
                "msg": error.get("msg", "Request validation failed"),
            }
            for error in exc.errors()
        ]
        return JSONResponse(status_code=422, content={"detail": details})

    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "[::1]"],
    )

    @app.middleware("http")
    async def reject_cross_origin_mutations(request: Request, call_next: Any) -> Any:
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            fetch_site = request.headers.get("sec-fetch-site")
            same_origin = True
            if origin:
                try:
                    parsed_origin = urlsplit(origin)
                    canonical_origin = (
                        parsed_origin.scheme.lower() in {"http", "https"}
                        and parsed_origin.hostname is not None
                        and parsed_origin.username is None
                        and parsed_origin.password is None
                        and parsed_origin.path == ""
                        and parsed_origin.query == ""
                        and parsed_origin.fragment == ""
                        and not parsed_origin.netloc.endswith(":")
                    )
                    origin_port = parsed_origin.port or (
                        443 if parsed_origin.scheme == "https" else 80
                    )
                    request_port = request.url.port or (
                        443 if request.url.scheme == "https" else 80
                    )
                    same_origin = (
                        canonical_origin
                        and parsed_origin.scheme.lower() == request.url.scheme.lower()
                        and (parsed_origin.hostname or "").lower()
                        == (request.url.hostname or "").lower()
                        and origin_port == request_port
                    )
                except ValueError:
                    same_origin = False
            if (origin and not same_origin) or fetch_site == "cross-site":
                return JSONResponse(
                    status_code=status.HTTP_403_FORBIDDEN,
                    content={"detail": "Cross-origin mutations are not allowed"},
                )
        return await call_next(request)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'none'; img-src 'self' data:; script-src 'self'; "
            "style-src 'self'; connect-src 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        return response

    app.state.store = EventStore(Path(data_dir))
    try:
        app.state.workspace, app.state.workspace_fd = EventStore.open_workspace(
            workspace
        )
    except OSError as exc:
        app.state.store.close()
        raise RuntimeError(
            "Configured workspace must be a real directory with no symlink components"
        ) from exc
    workspace_stat = os.fstat(app.state.workspace_fd)
    app.state.workspace_identity = (workspace_stat.st_dev, workspace_stat.st_ino)

    stop_pruning = threading.Event()

    def prune_periodically(days: float) -> None:
        while True:
            try:
                app.state.store.prune_snapshots(older_than=timedelta(days=days))
            except Exception:
                # Retention is best effort and must never stop the server.
                _LOGGER.exception("Glassbox snapshot retention failed")
            if stop_pruning.wait(_PRUNE_INTERVAL_SECONDS):
                return

    if prune_older_than_days is not None:
        threading.Thread(
            target=prune_periodically,
            args=(prune_older_than_days,),
            name="glassbox-retention",
            daemon=True,
        ).start()

    def close_resources() -> None:
        stop_pruning.set()
        workspace_descriptor = getattr(app.state, "workspace_fd", -1)
        if workspace_descriptor >= 0:
            try:
                os.close(workspace_descriptor)
            except OSError:
                pass
            app.state.workspace_fd = -1
        app.state.store.close()
        writer_lock.release()

    app.state.writer_lock = writer_lock

    app.router.add_event_handler("shutdown", close_resources)
    static_dir = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        return {
            "version": __version__,
            "workspace": str(app.state.workspace),
            "show_diffs": show_diffs,
        }

    @app.get("/api/events")
    def list_events(
        limit: int = 100,
        before_id: Annotated[int | None, Query(ge=1)] = None,
        risk: Literal["low", "medium", "high"] | None = None,
        agent: Annotated[str | None, Query(max_length=120)] = None,
        action: Annotated[str | None, Query(max_length=120)] = None,
        session: Annotated[str | None, Query(max_length=200)] = None,
        q: Annotated[str | None, Query(max_length=200)] = None,
        reversible: bool | None = None,
    ) -> dict[str, Any]:
        safe_limit = max(1, min(limit, 500))
        page: dict[str, Any] = app.state.store.page_events(
            safe_limit,
            before_id=before_id,
            risk=risk,
            agent=agent,
            action=action,
            session=session,
            query=q,
            reversible=reversible,
        )
        return page

    @app.post("/api/events", status_code=status.HTTP_201_CREATED)
    def record_event(event: EventCreate) -> dict[str, Any]:
        return app.state.store.append(event.model_dump())

    @app.get("/api/events/{event_id}")
    def get_event(event_id: int) -> dict[str, Any]:
        event: dict[str, Any] | None = app.state.store.get_event(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return event

    @app.get("/api/events/{event_id}/diff")
    def get_event_diff(event_id: int) -> dict[str, Any]:
        if not show_diffs:
            raise HTTPException(
                status_code=403,
                detail="File contents are not served; start Glassbox with --show-diffs",
            )
        diff: dict[str, Any] | None = app.state.store.read_diff(event_id)
        if diff is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return diff

    @app.get("/api/stats")
    def stats() -> dict[str, Any]:
        result: dict[str, Any] = app.state.store.stats()
        return result

    @app.get("/api/head")
    def head() -> dict[str, Any]:
        result: dict[str, Any] = app.state.store.head()
        return result

    @app.get("/api/export")
    def export() -> dict[str, Any]:
        result: dict[str, Any] = app.state.store.export()
        return result

    @app.post("/api/events/{event_id}/rollback")
    def rollback_event(event_id: int, request: RollbackRequest) -> dict[str, Any]:
        if not request.confirm:
            raise HTTPException(
                status_code=400, detail="Explicit confirmation is required"
            )
        try:
            return app.state.store.rollback(
                event_id,
                app.state.workspace,
                app.state.workspace_identity,
                app.state.workspace_fd,
            )
        except RollbackError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc

    @app.get("/api/verify")
    def verify_receipts() -> dict[str, Any]:
        return app.state.store.verify()

    return app
