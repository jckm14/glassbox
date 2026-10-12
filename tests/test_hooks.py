import io
import json
import os
import stat
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from glassbox.app import create_app
from glassbox.cli import main
from glassbox.hooks import handle_claude_code_hook, hook_settings
from glassbox.store import EventStore


def _payload(event: str, tool: str, tool_input: dict, **extra) -> dict:
    return {
        "session_id": "session-1",
        "hook_event_name": event,
        "tool_name": tool,
        "tool_use_id": extra.pop("tool_use_id", "toolu_1"),
        "tool_input": tool_input,
        **extra,
    }


@pytest.fixture
def project(tmp_path):
    workspace = tmp_path / "project"
    (workspace / "src").mkdir(parents=True)
    return workspace, tmp_path / "data"


def _run(payload: dict, workspace: Path, data_dir: Path) -> list[dict]:
    recorded: list[dict] = []
    handle_claude_code_hook(
        {"cwd": str(workspace), **payload},
        data_dir=data_dir,
        record=recorded.append,
        workspace=workspace,
    )
    return recorded


def test_edit_becomes_one_reversible_receipt_with_before_and_after(project):
    workspace, data_dir = project
    target = workspace / "src" / "app.py"
    target.write_text("print('old')\n", encoding="utf-8")
    tool_input = {"file_path": str(target), "old_string": "old", "new_string": "new"}

    before = _run(_payload("PreToolUse", "Edit", tool_input), workspace, data_dir)
    target.write_text("print('new')\n", encoding="utf-8")
    after = _run(_payload("PostToolUse", "Edit", tool_input), workspace, data_dir)

    assert before == []
    assert len(after) == 1
    event = after[0]
    assert event["action"] == "file.write"
    assert event["target"] == "src/app.py"
    assert event["before_text"] == "print('old')\n"
    assert event["after_text"] == "print('new')\n"
    assert event["metadata"]["session_id"] == "session-1"
    assert event["metadata"]["workspace"] == os.path.realpath(workspace)
    pending = data_dir / "pending"
    assert stat.S_IMODE(pending.stat().st_mode) == 0o700
    assert list(pending.iterdir()) == []


def test_new_file_becomes_a_reversible_create_receipt(project):
    workspace, data_dir = project
    target = workspace / "notes.md"
    tool_input = {"file_path": str(target), "content": "hello\n"}

    _run(_payload("PreToolUse", "Write", tool_input), workspace, data_dir)
    target.write_text("hello\n", encoding="utf-8")
    recorded = _run(_payload("PostToolUse", "Write", tool_input), workspace, data_dir)

    assert recorded[0]["action"] == "file.create"
    assert recorded[0]["after_text"] == "hello\n"
    assert "before_text" not in recorded[0]


def test_unchanged_file_and_failed_write_record_nothing(project):
    workspace, data_dir = project
    target = workspace / "same.txt"
    target.write_text("same\n", encoding="utf-8")
    tool_input = {"file_path": str(target)}

    _run(_payload("PreToolUse", "Edit", tool_input), workspace, data_dir)
    unchanged = _run(_payload("PostToolUse", "Edit", tool_input), workspace, data_dir)
    never_created = _run(
        _payload("PostToolUse", "Write", {"file_path": str(workspace / "absent.txt")}),
        workspace,
        data_dir,
    )

    assert unchanged == []
    assert never_created == []


def test_file_outside_the_workspace_is_recorded_without_content(project, tmp_path):
    workspace, data_dir = project
    outside = tmp_path / "elsewhere.txt"
    outside.write_text("old\n", encoding="utf-8")
    tool_input = {"file_path": str(outside)}

    _run(_payload("PreToolUse", "Write", tool_input), workspace, data_dir)
    stash = next((data_dir / "pending").iterdir()).read_text(encoding="utf-8")
    outside.write_text("new\n", encoding="utf-8")
    recorded = _run(_payload("PostToolUse", "Write", tool_input), workspace, data_dir)

    assert "old" not in stash
    event = recorded[0]
    assert event["target"] == str(outside)
    assert "before_text" not in event and "after_text" not in event
    assert event["metadata"]["outside_workspace"] is True


def test_binary_or_missing_pre_hook_content_is_not_reversible(project):
    workspace, data_dir = project
    binary = workspace / "image.bin"
    binary.write_bytes(b"\xff\xfe\x00binary")
    no_pre = workspace / "late.txt"
    no_pre.write_text("after only\n", encoding="utf-8")

    _run(
        _payload("PreToolUse", "Write", {"file_path": str(binary)}), workspace, data_dir
    )
    binary.write_bytes(b"\xff\xfe\x00changed")
    first = _run(
        _payload("PostToolUse", "Write", {"file_path": str(binary)}),
        workspace,
        data_dir,
    )
    second = _run(
        _payload("PostToolUse", "Write", {"file_path": str(no_pre)}, tool_use_id="t2"),
        workspace,
        data_dir,
    )

    assert "after_text" not in first[0]
    assert first[0]["metadata"]["content_not_recorded"]
    assert second[0]["after_text"] == "after only\n"
    assert "before_text" not in second[0]
    assert second[0]["metadata"]["content_not_recorded"]


def test_shell_command_and_other_tools_are_recorded(project):
    workspace, data_dir = project
    command = "pytest -q\n# trailing comment"

    shell = _run(
        _payload(
            "PostToolUse",
            "Bash",
            {"command": command, "description": "Run the tests"},
            tool_response={"interrupted": False, "stdout": "secret output"},
        ),
        workspace,
        data_dir,
    )
    failed = _run(
        _payload("PostToolUseFailure", "Bash", {"command": "false"}),
        workspace,
        data_dir,
    )
    mcp = _run(
        _payload("PostToolUse", "mcp__slack__send_message", {"channel": "general"}),
        workspace,
        data_dir,
    )
    read = _run(
        _payload("PostToolUse", "Read", {"file_path": "/etc/hosts"}),
        workspace,
        data_dir,
    )
    subagent = _run(
        _payload("PostToolUse", "Bash", {"command": "ls"}, agent_type="Explore"),
        workspace,
        data_dir,
    )

    assert shell[0]["action"] == "shell.exec"
    assert shell[0]["target"] == "pytest -q"
    assert shell[0]["summary"] == "Run the tests"
    assert shell[0]["metadata"]["command"] == command
    assert shell[0]["metadata"]["interrupted"] is False
    assert "secret output" not in json.dumps(shell[0])
    assert failed[0]["metadata"]["failed"] is True
    assert failed[0]["summary"].endswith("(failed)")
    assert mcp[0]["action"] == "mcp.slack.send_message"
    assert read[0]["action"] == "file.read"
    assert read[0]["target"] == "/etc/hosts"
    assert subagent[0]["agent"] == "claude-code/Explore"


def test_unrelated_or_malformed_payloads_are_ignored(project):
    workspace, data_dir = project

    assert _run({"hook_event_name": "Stop"}, workspace, data_dir) == []
    assert (
        _run(_payload("PostToolUse", "Bash", {"command": "  "}), workspace, data_dir)
        == []
    )
    assert _run(_payload("PostToolUse", "Edit", {}), workspace, data_dir) == []
    assert (
        _run(
            {"hook_event_name": "PostToolUse", "tool_name": "Bash"}, workspace, data_dir
        )
        == []
    )


def test_printed_config_registers_the_hook_for_file_and_shell_tools(capsys):
    assert main(["hook", "claude-code", "--print-config"]) == 0

    printed = json.loads(capsys.readouterr().out)
    assert printed == hook_settings()
    assert (
        printed["hooks"]["PreToolUse"][0]["matcher"]
        == "Write|Edit|MultiEdit|NotebookEdit"
    )
    assert "Bash" in printed["hooks"]["PostToolUse"][0]["matcher"]
    assert printed["hooks"]["PostToolUse"][0]["hooks"][0]["command"] == (
        "glassbox hook claude-code"
    )


def _hook(monkeypatch, payload: dict, data_dir: Path, workspace: Path) -> int:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(payload)))
    return main(
        [
            "hook",
            "claude-code",
            "--data-dir",
            str(data_dir),
            "--workspace",
            str(workspace),
        ]
    )


def test_hook_command_records_without_a_server_and_undo_round_trips(
    project, monkeypatch, capsys
):
    workspace, data_dir = project
    target = workspace / "src" / "app.py"
    target.write_text("old\n", encoding="utf-8")
    tool_input = {"file_path": str(target)}
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)

    assert (
        _hook(
            monkeypatch, _payload("PreToolUse", "Edit", tool_input), data_dir, workspace
        )
        == 0
    )
    target.write_text("new\n", encoding="utf-8")
    assert (
        _hook(
            monkeypatch,
            _payload("PostToolUse", "Edit", tool_input),
            data_dir,
            workspace,
        )
        == 0
    )
    assert (
        _hook(
            monkeypatch,
            _payload(
                "PostToolUse", "Bash", {"command": "rm -rf build"}, tool_use_id="t2"
            ),
            data_dir,
            workspace,
        )
        == 0
    )

    store = EventStore(data_dir)
    events = store.list_events()
    assert [event["action"] for event in events] == ["shell.exec", "file.write"]
    assert events[0]["risk"] == "high"
    assert events[1]["reversible"] is True
    assert store.verify()["valid"] is True
    store.close()

    assert (
        main(
            [
                "rollback",
                "1",
                "--yes",
                "--data-dir",
                str(data_dir),
                "--workspace",
                str(workspace),
            ]
        )
        == 0
    )
    assert target.read_text(encoding="utf-8") == "old\n"
    assert "Rolled back receipt #1" in capsys.readouterr().out


def test_hook_command_never_fails_the_tool_call(project, monkeypatch, capsys):
    workspace, data_dir = project

    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert main(["hook", "claude-code", "--data-dir", str(data_dir)]) == 0
    monkeypatch.setattr("sys.stdin", io.StringIO("[]"))
    assert main(["hook", "claude-code", "--data-dir", str(data_dir)]) == 0
    data_dir.mkdir(mode=0o755)
    data_dir.chmod(0o755)
    assert (
        _hook(
            monkeypatch,
            _payload("PostToolUse", "Bash", {"command": "ls"}),
            data_dir,
            workspace,
        )
        == 0
    )

    assert capsys.readouterr().err.count("glassbox hook:") == 3


@pytest.fixture
def running_server(tmp_path):
    import socket

    workspace = tmp_path / "project"
    workspace.mkdir()
    data_dir = tmp_path / "data"
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    app = create_app(
        data_dir=data_dir,
        workspace=workspace,
        server_url=f"http://127.0.0.1:{port}",
    )
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started
    try:
        yield workspace, data_dir, app
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def test_writes_are_handed_to_the_server_that_owns_the_ledger(
    running_server, monkeypatch, capsys
):
    workspace, data_dir, app = running_server
    target = workspace / "app.py"
    target.write_text("old\n", encoding="utf-8")
    tool_input = {"file_path": str(target)}
    monkeypatch.delenv("GLASSBOX_URL", raising=False)

    _hook(monkeypatch, _payload("PreToolUse", "Edit", tool_input), data_dir, workspace)
    target.write_text("new\n", encoding="utf-8")
    _hook(monkeypatch, _payload("PostToolUse", "Edit", tool_input), data_dir, workspace)
    recorded = main(
        [
            "record",
            "--data-dir",
            str(data_dir),
            "--agent",
            "me",
            "--action",
            "tool.read",
            "--target",
            "x",
            "--summary",
            "Through the server",
        ]
    )
    listed = main(["log", "--data-dir", str(data_dir)])
    verified = main(["verify", "--data-dir", str(data_dir)])
    pruned = main(["prune", "--keep-last", "0", "--data-dir", str(data_dir)])
    undone = main(["rollback", "1", "--yes", "--data-dir", str(data_dir)])

    output = capsys.readouterr()
    assert (recorded, listed, verified, undone) == (0, 0, 0, 0)
    assert pruned == 1
    assert "server owns this ledger" in output.err
    assert "OK: 2 receipts verified" in output.out
    assert target.read_text(encoding="utf-8") == "old\n"
    # The server's pinned database was never replaced behind its back.
    events = app.state.store.list_events()
    assert [event["action"] for event in events] == [
        "file.rollback",
        "tool.read",
        "file.write",
    ]
    assert app.state.store.verify()["valid"] is True


def test_fifo_paths_do_not_hang_the_hook(project):
    workspace, data_dir = project
    fifo = workspace / "pipe"
    os.mkfifo(fifo)

    before = _run(
        _payload("PreToolUse", "Write", {"file_path": str(fifo)}), workspace, data_dir
    )
    after = _run(
        _payload("PostToolUse", "Write", {"file_path": str(fifo)}), workspace, data_dir
    )

    assert before == []
    assert "after_text" not in after[0]


def test_failed_edit_clears_the_text_held_for_it(project):
    workspace, data_dir = project
    target = workspace / "config.txt"
    target.write_text("API_KEY=plaintext-secret-value\n", encoding="utf-8")
    tool_input = {"file_path": str(target)}

    _run(_payload("PreToolUse", "Edit", tool_input), workspace, data_dir)
    assert len(list((data_dir / "pending").iterdir())) == 1
    recorded = _run(
        _payload("PostToolUseFailure", "Edit", tool_input), workspace, data_dir
    )

    assert recorded == []
    assert list((data_dir / "pending").iterdir()) == []
    failure = hook_settings()["hooks"]["PostToolUseFailure"][0]["matcher"]
    assert "Edit" in failure and "Write" in failure


def test_long_multibyte_command_still_fits_the_server_metadata_limit(project):
    workspace, data_dir = project
    command = "rm -rf build # " + "\U0001f600" * 17_000

    recorded = _run(
        _payload("PostToolUse", "Bash", {"command": command}), workspace, data_dir
    )

    encoded = json.dumps(recorded[0]["metadata"], ensure_ascii=False).encode("utf-8")
    assert len(encoded) < 65_536
    assert recorded[0]["metadata"]["command"].startswith("rm -rf build")
