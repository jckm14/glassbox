"""Turn Claude Code hook payloads into Glassbox receipts.

Claude Code runs ``glassbox hook claude-code`` before and after tool calls and
passes a JSON description of the call on standard input. Before a file tool
runs, the file's current text is stashed in the private data directory; after
it runs, the stash and the new text become one ``file.write`` or
``file.create`` receipt that Glassbox can show as a diff and roll back.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .lock import open_private_dir

FILE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})
SHELL_TOOLS = frozenset({"Bash"})
MAX_TEXT_CHARS = 1_000_000
_MAX_TARGET_CHARS = 1000
_MAX_SUMMARY_CHARS = 400
_MAX_COMMAND_CHARS = 20_000
# The server caps receipt metadata at 64 KiB of UTF-8.
_MAX_COMMAND_BYTES = 48_000
_PENDING_DIR = "pending"
_PENDING_MAX_AGE_SECONDS = 60 * 60

_READ_ACTIONS = {
    "Read": "file.read",
    "Glob": "file.glob",
    "Grep": "file.grep",
    "LS": "file.list",
    "NotebookRead": "file.read",
    "WebFetch": "web.fetch",
    "WebSearch": "web.search",
}
_TARGET_KEYS = (
    "file_path",
    "notebook_path",
    "path",
    "url",
    "query",
    "pattern",
    "command",
    "description",
    "prompt",
)

Recorder = Callable[[dict[str, Any]], Any]


def hook_settings(command: str = "glassbox hook claude-code") -> dict[str, Any]:
    """Claude Code settings that send file edits and shell commands to Glassbox."""
    hook = {"type": "command", "command": command, "timeout": 15}
    file_matcher = "Write|Edit|MultiEdit|NotebookEdit"
    after = [{"matcher": f"{file_matcher}|Bash", "hooks": [hook]}]
    return {
        "hooks": {
            "PreToolUse": [{"matcher": file_matcher, "hooks": [hook]}],
            "PostToolUse": after,
            # A failed edit must still clear the text held for it.
            "PostToolUseFailure": after,
        }
    }


def _clip(value: str, limit: int) -> str:
    return value if len(value) <= limit else f"{value[: limit - 1]}…"


def _clip_bytes(value: str, limit: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return f"{encoded[: limit - 3].decode('utf-8', errors='ignore')}…"


def _read_text(path: Path) -> tuple[bool, str | None]:
    """Return ``(exists, text)``; text is ``None`` unless it is modest UTF-8."""
    try:
        descriptor = os.open(
            path,
            # Non-blocking so a FIFO at the path cannot hang the hook.
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
        )
    except FileNotFoundError:
        return False, None
    except OSError:
        return True, None
    try:
        identity = os.fstat(descriptor)
        if not stat.S_ISREG(identity.st_mode) or identity.st_size > MAX_TEXT_CHARS * 4:
            return True, None
        with os.fdopen(os.dup(descriptor), "rb") as source:
            raw = source.read()
    finally:
        os.close(descriptor)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return True, None
    return True, text if len(text) <= MAX_TEXT_CHARS else None


def _workspace_target(path: Path, workspace: Path) -> tuple[str, bool]:
    """Workspace-relative target when the path is inside the workspace."""
    try:
        relative = path.resolve().relative_to(workspace.resolve())
    except (ValueError, OSError):
        return str(path), False
    if not relative.parts:
        return str(path), False
    return relative.as_posix(), True


def _pending_name(session_id: str, tool_use_id: str, path: Path) -> str:
    key = "\0".join((session_id, tool_use_id, str(path)))
    return f"{hashlib.sha256(key.encode('utf-8')).hexdigest()}.json"


def _open_pending_dir(data_dir: Path) -> int:
    directory_fd = open_private_dir(data_dir, create=True)
    try:
        try:
            os.mkdir(_PENDING_DIR, mode=0o700, dir_fd=directory_fd)
        except FileExistsError:
            pass
        descriptor = os.open(
            _PENDING_DIR,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)
    identity = os.fstat(descriptor)
    if identity.st_uid != os.geteuid() or stat.S_IMODE(identity.st_mode) != 0o700:
        os.close(descriptor)
        raise RuntimeError("Glassbox pending directory must be private")
    return descriptor


def _stash_before(data_dir: Path, name: str, state: dict[str, Any]) -> None:
    pending_fd = _open_pending_dir(data_dir)
    try:
        now = time.time()
        for entry in os.listdir(pending_fd):
            try:
                age = (
                    now
                    - os.stat(entry, dir_fd=pending_fd, follow_symlinks=False).st_mtime
                )
                if age > _PENDING_MAX_AGE_SECONDS:
                    os.unlink(entry, dir_fd=pending_fd)
            except OSError:
                continue
        try:
            os.unlink(name, dir_fd=pending_fd)
        except FileNotFoundError:
            pass
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=pending_fd,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as stash:
            json.dump(state, stash)
    finally:
        os.close(pending_fd)


def _take_stash(data_dir: Path, name: str) -> dict[str, Any] | None:
    try:
        pending_fd = _open_pending_dir(data_dir)
    except (OSError, RuntimeError):
        return None
    try:
        try:
            descriptor = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pending_fd
            )
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                os.close(descriptor)
                return None
        except OSError:
            return None
        try:
            with os.fdopen(descriptor, "r", encoding="utf-8") as stash:
                state = json.load(stash)
        except (OSError, ValueError):
            state = None
        try:
            os.unlink(name, dir_fd=pending_fd)
        except OSError:
            pass
    finally:
        os.close(pending_fd)
    return state if isinstance(state, dict) else None


def _base_metadata(
    payload: Mapping[str, Any], tool: str, workspace: Path
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "source": "claude-code",
        "tool": tool,
        "workspace": str(workspace),
    }
    for key in ("session_id", "tool_use_id", "agent_type", "permission_mode"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            metadata[key] = value
    return metadata


def _file_event(
    payload: Mapping[str, Any],
    *,
    tool: str,
    path: Path,
    workspace: Path,
    data_dir: Path,
    agent: str,
) -> dict[str, Any] | None:
    session_id = str(payload.get("session_id") or "")
    tool_use_id = str(payload.get("tool_use_id") or "")
    stash = _take_stash(data_dir, _pending_name(session_id, tool_use_id, path))
    exists, after_text = _read_text(path)
    if not exists:
        return None
    target, inside = _workspace_target(path, workspace)
    metadata = _base_metadata(payload, tool, workspace)
    event: dict[str, Any] = {
        "agent": agent,
        "target": _clip(target, _MAX_TARGET_CHARS),
        "metadata": metadata,
    }
    existed_before = stash.get("existed") if stash else None
    before_text = stash.get("text") if stash else None
    if existed_before is False:
        event["action"] = "file.create"
        event["summary"] = f"{tool} created {target}"
        if inside and after_text is not None:
            event["after_text"] = after_text
    else:
        if isinstance(before_text, str) and before_text == after_text:
            return None
        event["action"] = "file.write"
        event["summary"] = f"{tool} changed {target}"
        if inside and after_text is not None:
            event["after_text"] = after_text
            if isinstance(before_text, str):
                event["before_text"] = before_text
    if not inside:
        metadata["outside_workspace"] = True
    elif "after_text" not in event:
        metadata["content_not_recorded"] = "not UTF-8 text or larger than 1 MB"
    elif event["action"] == "file.write" and "before_text" not in event:
        metadata["content_not_recorded"] = "previous content was not captured"
    event["summary"] = _clip(event["summary"], _MAX_SUMMARY_CHARS)
    return event


def _shell_event(
    payload: Mapping[str, Any],
    *,
    tool: str,
    tool_input: Mapping[str, Any],
    workspace: Path,
    agent: str,
    failed: bool,
) -> dict[str, Any] | None:
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    metadata = _base_metadata(payload, tool, workspace)
    metadata["command"] = _clip_bytes(
        _clip(command, _MAX_COMMAND_CHARS), _MAX_COMMAND_BYTES
    )
    if failed:
        metadata["failed"] = True
    response = payload.get("tool_response")
    if isinstance(response, Mapping) and isinstance(response.get("interrupted"), bool):
        metadata["interrupted"] = response["interrupted"]
    description = tool_input.get("description")
    first_line = command.strip().splitlines()[0]
    summary = (
        description.strip()
        if isinstance(description, str) and description.strip()
        else f"Ran {first_line}"
    )
    if failed:
        summary = f"{summary} (failed)"
    return {
        "agent": agent,
        "action": "shell.exec",
        "target": _clip(first_line, _MAX_TARGET_CHARS),
        "summary": _clip(summary, _MAX_SUMMARY_CHARS),
        "metadata": metadata,
    }


def _generic_event(
    payload: Mapping[str, Any],
    *,
    tool: str,
    tool_input: Mapping[str, Any],
    workspace: Path,
    agent: str,
) -> dict[str, Any]:
    if tool.startswith("mcp__"):
        action = ".".join(["mcp", *[part for part in tool.split("__")[1:] if part]])
    else:
        action = _READ_ACTIONS.get(tool, f"tool.{tool.lower()}")
    target = tool
    for key in _TARGET_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            target = value.strip().splitlines()[0]
            break
    return {
        "agent": agent,
        "action": _clip(action, 120),
        "target": _clip(target, _MAX_TARGET_CHARS),
        "summary": _clip(f"{tool} called", _MAX_SUMMARY_CHARS),
        "metadata": _base_metadata(payload, tool, workspace),
    }


def handle_claude_code_hook(
    payload: Mapping[str, Any],
    *,
    data_dir: Path,
    record: Recorder,
    workspace: Path | None = None,
    agent: str = "claude-code",
) -> dict[str, Any] | None:
    """Process one hook payload; return the event that was recorded, if any."""
    event_name = payload.get("hook_event_name")
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input")
    if not isinstance(tool, str) or not isinstance(tool_input, Mapping):
        return None
    if workspace is None:
        root = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()
        workspace = Path(str(root))
    workspace = Path(os.path.realpath(workspace))
    agent_type = payload.get("agent_type")
    if isinstance(agent_type, str) and agent_type:
        agent = _clip(f"{agent}/{agent_type}", 120)

    file_path: Path | None = None
    if tool in FILE_TOOLS:
        raw_path = tool_input.get("file_path") or tool_input.get("notebook_path")
        if not isinstance(raw_path, str) or not raw_path:
            return None
        file_path = Path(raw_path)
        if not file_path.is_absolute():
            file_path = Path(str(payload.get("cwd") or workspace)) / file_path

    if event_name == "PreToolUse":
        if file_path is not None:
            exists, text = _read_text(file_path)
            _, inside = _workspace_target(file_path, workspace)
            _stash_before(
                data_dir,
                _pending_name(
                    str(payload.get("session_id") or ""),
                    str(payload.get("tool_use_id") or ""),
                    file_path,
                ),
                {"existed": exists, "text": text if inside else None},
            )
        return None
    if event_name not in {"PostToolUse", "PostToolUseFailure"}:
        return None

    failed = event_name == "PostToolUseFailure"
    event: dict[str, Any] | None
    if file_path is not None:
        event = _file_event(
            payload,
            tool=tool,
            path=file_path,
            workspace=workspace,
            data_dir=data_dir,
            agent=agent,
        )
    elif tool in SHELL_TOOLS:
        event = _shell_event(
            payload,
            tool=tool,
            tool_input=tool_input,
            workspace=workspace,
            agent=agent,
            failed=failed,
        )
    elif failed:
        event = None
    else:
        event = _generic_event(
            payload, tool=tool, tool_input=tool_input, workspace=workspace, agent=agent
        )
    if event is not None:
        record(event)
    return event
