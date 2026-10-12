"""Minimal HTTP client for a local Glassbox server.

Uses only the standard library so integrations can vendor or import it
without extra dependencies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_URL = "http://127.0.0.1:8765"


class GlassboxError(Exception):
    """The server rejected a request or could not be reached."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class GlassboxClient:
    """Record and inspect receipts through the Glassbox HTTP API.

    >>> client = GlassboxClient()
    >>> client.record(
    ...     agent="my-agent",
    ...     action="file.write",
    ...     target="notes/plan.md",
    ...     summary="Updated the project plan",
    ...     before_text=old,
    ...     after_text=new,
    ... )  # doctest: +SKIP
    """

    def __init__(self, base_url: str = DEFAULT_URL, *, timeout: float = 5.0):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("base_url must be an http(s) URL")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        # Never route requests for the local server through an environment proxy.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        if query:
            pairs = {
                key: ("true" if value is True else "false" if value is False else value)
                for key, value in query.items()
                if value is not None
            }
            if pairs:
                url = f"{url}?{urllib.parse.urlencode(pairs)}"
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail: Any = exc.reason
            try:
                detail = json.loads(exc.read().decode("utf-8")).get("detail", detail)
            except (ValueError, AttributeError, UnicodeDecodeError):
                pass
            raise GlassboxError(
                f"Glassbox returned HTTP {exc.code}: {detail}", exc.code
            ) from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise GlassboxError(
                f"Could not reach Glassbox at {self.base_url}: {exc}"
            ) from exc

    def record(
        self,
        *,
        agent: str,
        action: str,
        target: str,
        summary: str,
        before_text: str | None = None,
        after_text: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Record one action and return its receipt."""
        payload: dict[str, Any] = {
            "agent": agent,
            "action": action,
            "target": target,
            "summary": summary,
            "metadata": metadata or {},
        }
        if before_text is not None:
            payload["before_text"] = before_text
        if after_text is not None:
            payload["after_text"] = after_text
        receipt: dict[str, Any] = self._request("POST", "/api/events", body=payload)
        return receipt

    def events(self, **filters: Any) -> dict[str, Any]:
        """Return one page of receipts; accepts the ``/api/events`` query filters."""
        page: dict[str, Any] = self._request("GET", "/api/events", query=filters)
        return page

    def event(self, event_id: int) -> dict[str, Any]:
        receipt: dict[str, Any] = self._request("GET", f"/api/events/{event_id}")
        return receipt

    def diff(self, event_id: int) -> dict[str, Any]:
        result: dict[str, Any] = self._request("GET", f"/api/events/{event_id}/diff")
        return result

    def rollback(self, event_id: int) -> dict[str, Any]:
        result: dict[str, Any] = self._request(
            "POST", f"/api/events/{event_id}/rollback", body={"confirm": True}
        )
        return result

    def verify(self) -> dict[str, Any]:
        result: dict[str, Any] = self._request("GET", "/api/verify")
        return result

    def head(self) -> dict[str, Any]:
        result: dict[str, Any] = self._request("GET", "/api/head")
        return result

    def stats(self) -> dict[str, Any]:
        result: dict[str, Any] = self._request("GET", "/api/stats")
        return result
