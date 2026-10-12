import pytest

import glassbox.cli as cli_module
from glassbox.cli import main
from glassbox.store import EventStore


def test_demo_command_creates_a_verified_sample_timeline(tmp_path):
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "data"

    result = main(["demo", "--workspace", str(workspace), "--data-dir", str(data_dir)])

    store = EventStore(data_dir)
    events = store.list_events()
    assert result == 0
    assert len(events) == 4
    assert store.verify() == {"valid": True, "event_count": 4, "broken_at": None}
    synthetic_actions = {"tool.read", "shell.exec", "outbound.send"}
    synthetic_events = [
        event for event in events if event["action"] in synthetic_actions
    ]
    assert len(synthetic_events) == 3
    assert all("sample" in event["summary"].lower() for event in synthetic_events)
    assert all(event["metadata"]["synthetic"] is True for event in synthetic_events)
    assert (
        (workspace / "launch-plan.md")
        .read_text(encoding="utf-8")
        .startswith("# Launch plan")
    )


def test_demo_refuses_to_overwrite_an_existing_workspace_file(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "launch-plan.md"
    target.write_text("important user work", encoding="utf-8")

    with pytest.raises(FileExistsError):
        main(
            [
                "demo",
                "--workspace",
                str(workspace),
                "--data-dir",
                str(tmp_path / "data"),
            ]
        )

    assert target.read_text(encoding="utf-8") == "important user work"


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.10"])
def test_serve_refuses_non_loopback_bind_addresses(tmp_path, monkeypatch, host):
    def unexpected_run(*args, **kwargs):
        raise AssertionError("uvicorn must not start for a non-loopback bind address")

    monkeypatch.setattr(cli_module.uvicorn, "run", unexpected_run)

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                "serve",
                "--host",
                host,
                "--workspace",
                str(tmp_path / "workspace"),
                "--data-dir",
                str(tmp_path / "data"),
            ]
        )

    assert exc_info.value.code == 2


def _record(data_dir, *extra):
    return main(
        [
            "record",
            "--data-dir",
            str(data_dir),
            "--agent",
            "cli-agent",
            "--summary",
            "Recorded from the command line",
            *extra,
        ]
    )


def test_record_log_show_verify_head_and_export_round_trip(tmp_path, capsys):
    import json

    data_dir = tmp_path / "data"
    before = tmp_path / "before.txt"
    after = tmp_path / "after.txt"
    before.write_text("old line\n", encoding="utf-8")
    after.write_text("new line\n", encoding="utf-8")

    assert (
        _record(
            data_dir,
            "--action",
            "file.write",
            "--target",
            "notes.txt",
            "--before-file",
            str(before),
            "--after-file",
            str(after),
            "--metadata",
            '{"session_id": "s1"}',
        )
        == 0
    )
    assert _record(data_dir, "--action", "shell.exec", "--target", "rm -rf build") == 0
    capsys.readouterr()

    assert main(["log", "--data-dir", str(data_dir), "--risk", "high"]) == 0
    log = capsys.readouterr().out
    assert "rm -rf build" in log and "notes.txt" not in log
    assert "1 of 1 matching receipts" in log

    assert main(["log", "--data-dir", str(data_dir), "--json", "--reversible"]) == 0
    assert [e["id"] for e in json.loads(capsys.readouterr().out)["events"]] == [1]

    assert main(["show", "1", "--diff", "--data-dir", str(data_dir)]) == 0
    shown = capsys.readouterr().out
    assert "-old line" in shown and "+new line" in shown and "eligible" in shown
    assert main(["show", "9", "--data-dir", str(data_dir)]) == 1

    assert main(["head", "--data-dir", str(data_dir), "--json"]) == 0
    head = json.loads(capsys.readouterr().out)
    assert head["event_count"] == 2

    assert main(["verify", "--data-dir", str(data_dir)]) == 0
    assert "OK: 2 receipts verified" in capsys.readouterr().out
    assert (
        main(
            ["verify", "--data-dir", str(data_dir), "--expect-head", head["head_hash"]]
        )
        == 0
    )
    assert main(["verify", "--data-dir", str(data_dir), "--expect-head", "f" * 64]) == 1
    capsys.readouterr()

    output = tmp_path / "export.json"
    assert main(["export", "--data-dir", str(data_dir), "-o", str(output)]) == 0
    exported = json.loads(output.read_text(encoding="utf-8"))
    assert [event["id"] for event in exported["events"]] == [1, 2]
    assert exported["head"]["head_hash"] == head["head_hash"]


def test_verify_exits_nonzero_for_a_tampered_ledger(tmp_path, capsys):
    import sqlite3

    data_dir = tmp_path / "data"
    _record(data_dir, "--action", "tool.read", "--target", "a")
    with sqlite3.connect(data_dir / "glassbox.db") as conn:
        conn.execute("UPDATE events SET summary = 'Altered'")

    assert main(["verify", "--data-dir", str(data_dir)]) == 1
    assert "BROKEN" in capsys.readouterr().out


def test_read_commands_report_a_missing_ledger_without_creating_it(tmp_path, capsys):
    data_dir = tmp_path / "nothing-here"

    assert main(["log", "--data-dir", str(data_dir)]) == 1
    assert main(["verify", "--data-dir", str(data_dir)]) == 1
    assert "No Glassbox ledger" in capsys.readouterr().err
    assert not data_dir.exists()


def test_record_rejects_reserved_names_and_bad_input(tmp_path, capsys):
    data_dir = tmp_path / "data"

    assert (
        main(
            [
                "record",
                "--data-dir",
                str(data_dir),
                "--agent",
                "glassbox",
                "--action",
                "tool.read",
                "--target",
                "x",
                "--summary",
                "Impersonation",
            ]
        )
        == 1
    )
    assert _record(data_dir, "--action", "snapshot.prune", "--target", "x") == 1
    assert (
        _record(data_dir, "--action", "tool.read", "--target", "x", "--metadata", "[1]")
        == 1
    )
    assert "reserved" in capsys.readouterr().err


def test_rollback_prompts_unless_confirmed(tmp_path, monkeypatch, capsys):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "notes.txt"
    target.write_text("new\n", encoding="utf-8")
    data_dir = tmp_path / "data"
    _record(
        data_dir,
        "--action",
        "file.write",
        "--target",
        "notes.txt",
        "--before-text",
        "old\n",
        "--after-text",
        "new\n",
    )
    arguments = [
        "rollback",
        "1",
        "--data-dir",
        str(data_dir),
        "--workspace",
        str(workspace),
    ]

    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert main(arguments) == 1
    assert target.read_text(encoding="utf-8") == "new\n"

    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert main(arguments) == 0
    assert target.read_text(encoding="utf-8") == "old\n"

    assert main([*arguments, "--yes"]) == 1
    assert "Rollback refused" in capsys.readouterr().err


def test_prune_command_frees_stored_content(tmp_path, capsys):
    data_dir = tmp_path / "data"
    for name in ("a.txt", "b.txt"):
        _record(
            data_dir,
            "--action",
            "file.write",
            "--target",
            name,
            "--before-text",
            "old",
            "--after-text",
            "new",
        )

    assert main(["prune", "--data-dir", str(data_dir)]) == 1
    assert main(["prune", "--data-dir", str(data_dir), "--keep-last", "1"]) == 0
    assert "Pruned stored content for 1 receipts" in capsys.readouterr().out
    assert main(["verify", "--data-dir", str(data_dir)]) == 0
