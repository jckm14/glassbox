from __future__ import annotations

import re
from typing import Any

_SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"(?i)\b(api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+"),
)


_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|password|passwd|secret|authorization|credentials?)(?:$|[_-])"
)


def redact_text(value: str) -> str:
    redacted = value
    redacted = _SECRET_PATTERNS[0].sub("[REDACTED]", redacted)
    redacted = _SECRET_PATTERNS[1].sub(r"\1[REDACTED]", redacted)
    redacted = _SECRET_PATTERNS[2].sub(lambda m: f"{m.group(1)}=[REDACTED]", redacted)
    return redacted


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SENSITIVE_KEY.search(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def classify_risk(action: str) -> str:
    normalized = action.lower()
    if normalized in {"shell.exec", "outbound.send", "account.delete"}:
        return "high"
    if normalized in {"file.write", "file.delete", "config.change"}:
        return "medium"
    return "low"
