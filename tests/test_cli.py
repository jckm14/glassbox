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
