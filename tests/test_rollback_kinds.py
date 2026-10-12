import os
import sqlite3
import stat
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import glassbox.store as store_module
from glassbox.app import create_app


def _app(tmp_path: Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    return workspace, create_app(data_dir=tmp_path / "data", workspace=workspace)


def _record(client: TestClient, action: str, target: str = "notes/demo.txt", **texts):
    response = client.post(
        "/api/events",
        json={
            "agent": "agent",
            "action": action,
            "target": target,
            "summary": f"{action} {target}",
            **texts,
        },
    )
    assert response.status_code == 201
    return response.json()


def _rollback(client: TestClient, event_id: int):
    return client.post(f"/api/events/{event_id}/rollback", json={"confirm": True})


def _recovery_dirs(workspace: Path) -> list[Path]:
    return sorted(workspace.rglob(".*.glassbox-recovery-*"))


def test_rollback_of_a_created_file_moves_it_to_a_private_recovery_directory(
    tmp_path,
):
    workspace, app = _app(tmp_path)
    target = workspace / "notes" / "demo.txt"
    target.parent.mkdir()
    target.write_text("created by the agent", encoding="utf-8")

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = _record(client, "file.create", after_text="created by the agent")
        response = _rollback(client, event["id"])
        again = _rollback(client, event["id"])
        events = client.get("/api/events").json()["events"]
        verification = client.get("/api/verify").json()

    assert event["reversible"] is True
    assert response.status_code == 200
    body = response.json()
    assert not target.exists()
    retained = Path(body["displaced_path"])
    assert retained.read_text(encoding="utf-8") == "created by the agent"
    assert stat.S_IMODE(retained.parent.stat().st_mode) == 0o700
    assert again.status_code == 409
    assert verification["valid"] is True
    by_id = {item["id"]: item for item in events}
    assert by_id[event["id"]]["rolled_back_by"] == body["rollback_receipt_id"]
    assert by_id[event["id"]]["reversible"] is False
    receipt = by_id[body["rollback_receipt_id"]]
    assert receipt["action"] == "file.rollback"
    assert receipt["metadata"]["rollback_kind"] == "remove_created_file"
    assert receipt["after_sha256"] is None


def test_rollback_of_a_created_file_refuses_when_it_was_edited_later(tmp_path):
    workspace, app = _app(tmp_path)
    target = workspace / "demo.txt"
    target.write_text("created", encoding="utf-8")

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = _record(client, "file.create", "demo.txt", after_text="created")
        target.write_text("created, then edited by a person", encoding="utf-8")
        response = _rollback(client, event["id"])

    assert response.status_code == 409
    assert "newer work" in response.json()["detail"]
    assert target.read_text(encoding="utf-8") == "created, then edited by a person"
    assert _recovery_dirs(workspace) == []


def test_rollback_of_a_created_file_refuses_a_symlink_or_missing_target(tmp_path):
    workspace, app = _app(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("created", encoding="utf-8")
    (workspace / "link.txt").symlink_to(outside)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        link = _record(client, "file.create", "link.txt", after_text="created")
        missing = _record(client, "file.create", "missing.txt", after_text="created")
        escaped = _record(client, "file.create", "../outside.txt", after_text="created")
        responses = [_rollback(client, item["id"]) for item in (link, missing, escaped)]

    assert [response.status_code for response in responses] == [409, 409, 400]
    assert outside.read_text(encoding="utf-8") == "created"
    assert (workspace / "link.txt").is_symlink()


def test_created_file_swapped_at_the_move_is_put_back(tmp_path, monkeypatch):
    workspace, app = _app(tmp_path)
    target = workspace / "demo.txt"
    target.write_text("created", encoding="utf-8")
    real_move = store_module._move_without_replacing
    calls = 0

    def swap_then_move(first, second, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            # A different file with identical content takes the name just
            # before the move: identity validation must notice.
            replacement = workspace / "replacement.txt"
            replacement.write_text("created", encoding="utf-8")
            os.replace(replacement, target)
        real_move(first, second, **kwargs)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = _record(client, "file.create", "demo.txt", after_text="created")
        monkeypatch.setattr(store_module, "_move_without_replacing", swap_then_move)
        response = _rollback(client, event["id"])
        events = client.get("/api/events").json()["events"]

    assert response.status_code == 409
    assert "put back" in response.json()["detail"]
    assert calls == 2
    assert target.read_text(encoding="utf-8") == "created"
    assert [item["action"] for item in events] == ["file.create"]
    assert _recovery_dirs(workspace) == []


def test_created_file_is_put_back_when_the_receipt_cannot_be_written(
    tmp_path, monkeypatch
):
    workspace, app = _app(tmp_path)
    target = workspace / "demo.txt"
    target.write_text("created", encoding="utf-8")

    with TestClient(
        app, base_url="http://127.0.0.1", raise_server_exceptions=False
    ) as client:
        event = _record(client, "file.create", "demo.txt", after_text="created")

        def fail_append(payload):
            raise sqlite3.OperationalError("simulated ledger failure")

        monkeypatch.setattr(app.state.store, "append", fail_append)
        response = _rollback(client, event["id"])

    assert response.status_code == 500
    assert target.read_text(encoding="utf-8") == "created"
    assert _recovery_dirs(workspace) == []


def test_file_reappearing_during_put_back_is_never_overwritten(tmp_path, monkeypatch):
    workspace, app = _app(tmp_path)
    target = workspace / "demo.txt"
    target.write_text("created", encoding="utf-8")

    with TestClient(
        app, base_url="http://127.0.0.1", raise_server_exceptions=False
    ) as client:
        event = _record(client, "file.create", "demo.txt", after_text="created")

        def fail_append(payload):
            target.write_text("written by someone else meanwhile", encoding="utf-8")
            raise sqlite3.OperationalError("simulated ledger failure")

        monkeypatch.setattr(app.state.store, "append", fail_append)
        response = _rollback(client, event["id"])

    assert response.status_code == 500
    assert "retained at" in response.json()["detail"]
    assert target.read_text(encoding="utf-8") == "written by someone else meanwhile"
    retained = list(workspace.rglob(".demo.txt.glassbox-removed-*.tmp"))
    assert len(retained) == 1
    assert retained[0].read_text(encoding="utf-8") == "created"


def test_rollback_of_a_deleted_file_recreates_it(tmp_path):
    workspace, app = _app(tmp_path)
    (workspace / "notes").mkdir()
    target = workspace / "notes" / "demo.txt"

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.delete",
                "target": "notes/demo.txt",
                "summary": "Deleted the note",
                "before_text": "important note",
                "metadata": {"mode": "0640"},
            },
        ).json()
        response = _rollback(client, event["id"])
        again = _rollback(client, event["id"])
        verification = client.get("/api/verify").json()
        events = client.get("/api/events").json()["events"]

    assert event["reversible"] is True
    assert response.status_code == 200
    body = response.json()
    assert body["displaced_path"] is None
    assert body["restored_path"] == str(target)
    assert target.read_text(encoding="utf-8") == "important note"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert again.status_code == 409
    assert verification["valid"] is True
    assert _recovery_dirs(workspace) == []
    receipt = events[0]
    assert receipt["metadata"]["rollback_kind"] == "restore_deleted_file"
    assert receipt["before_sha256"] is None


def test_restored_file_defaults_to_owner_only_permissions(tmp_path):
    workspace, app = _app(tmp_path)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = _record(client, "file.delete", "demo.txt", before_text="note")
        response = _rollback(client, event["id"])

    assert response.status_code == 200
    assert stat.S_IMODE((workspace / "demo.txt").stat().st_mode) == 0o600


@pytest.mark.parametrize("occupant", ["file", "directory", "symlink"])
def test_rollback_of_a_deleted_file_never_replaces_an_existing_entry(
    tmp_path, occupant
):
    workspace, app = _app(tmp_path)
    target = workspace / "demo.txt"
    if occupant == "file":
        target.write_text("recreated by a person", encoding="utf-8")
    elif occupant == "directory":
        target.mkdir()
    else:
        target.symlink_to(tmp_path / "elsewhere.txt")

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = _record(client, "file.delete", "demo.txt", before_text="old note")
        response = _rollback(client, event["id"])

    assert response.status_code == 409
    assert "refusing to overwrite" in response.json()["detail"]
    if occupant == "file":
        assert target.read_text(encoding="utf-8") == "recreated by a person"
    assert not (tmp_path / "elsewhere.txt").exists()
    assert _recovery_dirs(workspace) == []


def test_file_appearing_at_the_restore_move_is_not_overwritten(tmp_path, monkeypatch):
    workspace, app = _app(tmp_path)
    target = workspace / "demo.txt"
    real_move = store_module._move_without_replacing

    def create_then_move(first, second, **kwargs):
        target.write_text("arrived at the last moment", encoding="utf-8")
        real_move(first, second, **kwargs)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = _record(client, "file.delete", "demo.txt", before_text="old note")
        monkeypatch.setattr(store_module, "_move_without_replacing", create_then_move)
        response = _rollback(client, event["id"])

    assert response.status_code == 409
    assert target.read_text(encoding="utf-8") == "arrived at the last moment"
    assert _recovery_dirs(workspace) == []


def test_restored_file_is_withdrawn_when_the_receipt_cannot_be_written(
    tmp_path, monkeypatch
):
    workspace, app = _app(tmp_path)
    target = workspace / "demo.txt"

    with TestClient(
        app, base_url="http://127.0.0.1", raise_server_exceptions=False
    ) as client:
        event = _record(client, "file.delete", "demo.txt", before_text="old note")

        def fail_append(payload):
            raise sqlite3.OperationalError("simulated ledger failure")

        monkeypatch.setattr(app.state.store, "append", fail_append)
        response = _rollback(client, event["id"])

    assert response.status_code == 500
    assert not target.exists()


def test_rollback_requires_the_parent_directory_and_rejects_parent_symlinks(
    tmp_path,
):
    workspace, app = _app(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (workspace / "linked").symlink_to(outside, target_is_directory=True)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        through_link = _record(
            client, "file.delete", "linked/demo.txt", before_text="note"
        )
        no_parent = _record(client, "file.delete", "gone/demo.txt", before_text="note")
        responses = [
            _rollback(client, item["id"]) for item in (through_link, no_parent)
        ]

    assert [response.status_code for response in responses] == [409, 409]
    assert list(outside.iterdir()) == []


def test_create_and_delete_rollback_are_gated_by_chain_verification(tmp_path):
    workspace, app = _app(tmp_path)
    data_dir = tmp_path / "data"
    (workspace / "demo.txt").write_text("created", encoding="utf-8")

    with TestClient(app, base_url="http://127.0.0.1") as client:
        created = _record(client, "file.create", "demo.txt", after_text="created")
        deleted = _record(client, "file.delete", "old.txt", before_text="old")
        with sqlite3.connect(data_dir / "glassbox.db") as conn:
            conn.execute("UPDATE events SET summary = 'Altered' WHERE id = 1")
        responses = [_rollback(client, item["id"]) for item in (created, deleted)]

    assert [response.status_code for response in responses] == [409, 409]
    assert (workspace / "demo.txt").exists()
    assert not (workspace / "old.txt").exists()


def test_pruned_delete_snapshot_cannot_be_restored(tmp_path):
    workspace, app = _app(tmp_path)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = _record(client, "file.delete", "demo.txt", before_text="old note")
        app.state.store.prune_snapshots(keep_last=0)
        response = _rollback(client, event["id"])
        verification = client.get("/api/verify").json()

    assert response.status_code == 409
    assert "pruned" in response.json()["detail"]
    assert verification["valid"] is True
    assert not (workspace / "demo.txt").exists()


def test_receipt_recorded_for_another_workspace_is_not_applied(tmp_path):
    workspace, app = _app(tmp_path)
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    other = tmp_path / "other-project"
    other.mkdir()

    with TestClient(app, base_url="http://127.0.0.1") as client:
        foreign = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Edited demo.txt in another project",
                "before_text": "before",
                "after_text": "after",
                "metadata": {"workspace": str(other)},
            },
        ).json()
        local = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Edited demo.txt here",
                "before_text": "before",
                "after_text": "after",
                "metadata": {"workspace": str(workspace)},
            },
        ).json()
        refused = _rollback(client, foreign["id"])
        still_there = target.read_text(encoding="utf-8")
        applied = _rollback(client, local["id"])

    assert refused.status_code == 409
    assert "different workspace" in refused.json()["detail"]
    assert still_there == "after"
    assert applied.status_code == 200
    assert target.read_text(encoding="utf-8") == "before"


@pytest.mark.parametrize(
    ("action", "texts"),
    [
        ("file.create", {"before_text": "a", "after_text": "b"}),
        ("file.create", {}),
        ("file.delete", {"before_text": "a", "after_text": "b"}),
        ("file.delete", {"after_text": "b"}),
        ("file.write", {"after_text": "b"}),
        ("file.rename", {"before_text": "a", "after_text": "b"}),
    ],
)
def test_incomplete_or_mismatched_snapshots_are_not_reversible(tmp_path, action, texts):
    _, app = _app(tmp_path)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = _record(client, action, "demo.txt", **texts)
        response = _rollback(client, event["id"])

    assert event["reversible"] is False
    assert response.status_code == 409
