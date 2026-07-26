import errno
import os
import secrets
import shutil
import sqlite3
import stat
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import glassbox.store as store_module
from glassbox.app import create_app
from glassbox.store import EventStore


def _alternate_group() -> int:
    alternatives = [group for group in os.getgroups() if group != os.getegid()]
    if alternatives:
        return alternatives[0]
    if os.geteuid() == 0:
        return 1
    pytest.skip("ownership regression requires a supplementary group")


def _posix_acl(path: Path, *, default: bool = False) -> bytes | None:
    attribute = "system.posix_acl_default" if default else "system.posix_acl_access"
    try:
        return os.getxattr(path, attribute)
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP}:
            return None
        raise


def test_record_event_redacts_secrets_and_builds_a_valid_receipt_chain(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post(
            "/api/events",
            json={
                "agent": "hermes",
                "action": "file.write",
                "target": "notes/demo.txt",
                "summary": "Updated API token sk-test-1234567890abcdef",
                "before_text": "old value",
                "after_text": "token=sk-test-1234567890abcdef",
                "metadata": {"source": "test"},
            },
        )
        verification = client.get("/api/verify")

    assert response.status_code == 201
    event = response.json()
    assert event["summary"] == "Updated API token [REDACTED]"
    assert event["risk"] == "medium"
    assert event["reversible"] is True
    assert len(event["receipt_hash"]) == 64
    assert verification.json() == {"valid": True, "event_count": 1, "broken_at": None}


def test_metadata_values_under_sensitive_keys_are_redacted(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data_dir = tmp_path / "data"
    app = create_app(data_dir=data_dir, workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "tool.read",
                "target": "notes.txt",
                "summary": "Read notes",
                "metadata": {
                    "password": "hunter2",  # pragma: allowlist secret
                    "nested": {
                        "api_key": "short-secret",  # pragma: allowlist secret
                        "client_secret": "client-value",  # pragma: allowlist secret
                        "openai_api_key": "openai-value",  # pragma: allowlist secret
                        "safe": "visible",
                    },
                },
            },
        )

    assert response.status_code == 201
    assert response.json()["metadata"] == {
        "password": "[REDACTED]",
        "nested": {
            "api_key": "[REDACTED]",
            "client_secret": "[REDACTED]",
            "openai_api_key": "[REDACTED]",
            "safe": "visible",
        },
    }
    database_bytes = (data_dir / "glassbox.db").read_bytes()
    for secret in (b"hunter2", b"short-secret", b"client-value", b"openai-value"):
        assert secret not in database_bytes


def test_file_write_without_post_change_content_is_not_marked_reversible(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Incomplete integration event",
                "before_text": "before",
            },
        )

    assert response.status_code == 201
    assert response.json()["reversible"] is False


def test_store_rejects_a_corrupt_or_truncated_receipt_key(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o700)
    key_path = data_dir / "receipt.key"
    key_path.write_bytes(b"too-short")
    key_path.chmod(0o600)

    with pytest.raises(RuntimeError, match="exactly 32 bytes"):
        EventStore(data_dir)


@pytest.mark.parametrize("entry_name", ["receipt.key", "glassbox.db"])
def test_store_rejects_existing_hard_linked_security_files_without_chmod(
    tmp_path, entry_name
):
    data_dir = tmp_path / "data"
    data_dir.mkdir(mode=0o700)
    outside = tmp_path / f"outside-{entry_name}"
    outside.write_bytes(os.urandom(32) if entry_name == "receipt.key" else b"")
    outside.chmod(0o644)
    os.link(outside, data_dir / entry_name)
    if entry_name == "glassbox.db":
        (data_dir / "receipt.key").write_bytes(os.urandom(32))
        (data_dir / "receipt.key").chmod(0o600)

    with pytest.raises(RuntimeError, match="private regular file"):
        EventStore(data_dir)

    assert stat.S_IMODE(outside.stat().st_mode) == 0o644
    assert outside.stat().st_nlink == 2


def test_store_rejects_a_symlinked_existing_data_directory_without_chmod(tmp_path):
    actual = tmp_path / "actual-data"
    actual.mkdir(mode=0o755)
    configured = tmp_path / "configured-data"
    configured.symlink_to(actual, target_is_directory=True)

    with pytest.raises(RuntimeError, match="data directory"):
        EventStore(configured)

    assert stat.S_IMODE(actual.stat().st_mode) == 0o755


def test_database_swap_at_connect_does_not_mutate_outside_database(
    tmp_path, monkeypatch
):
    data_dir = tmp_path / "data"
    store = EventStore(data_dir)
    outside = tmp_path / "outside.db"
    shutil.copy2(store.db_path, outside)
    outside.chmod(0o600)
    real_connect = sqlite3.connect
    swapped = False

    def connect_after_swap(database, *args, **kwargs):
        nonlocal swapped
        if not swapped:
            swapped = True
            store.db_path.unlink()
            os.link(outside, store.db_path)
        return real_connect(database, *args, **kwargs)

    monkeypatch.setattr(store_module.sqlite3, "connect", connect_after_swap)
    with pytest.raises(RuntimeError, match="database.*changed|private regular file"):
        store.append(
            {
                "agent": "agent",
                "action": "tool.read",
                "target": "notes.txt",
                "summary": "Must not escape database pin",
            }
        )

    with real_connect(outside) as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_runtime_receipt_key_substitution_fails_closed(tmp_path):
    store = EventStore(tmp_path / "data")
    outside = tmp_path / "outside.key"
    outside.write_bytes(os.urandom(32))
    outside.chmod(0o600)
    store.key_path.unlink()
    os.link(outside, store.key_path)

    with pytest.raises(
        RuntimeError, match="Receipt key (entry changed|must be.*private regular file)"
    ):
        store.append(
            {
                "agent": "agent",
                "action": "tool.read",
                "target": "notes.txt",
                "summary": "Must retain the pinned signing key",
            }
        )

    with sqlite3.connect(store.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_rollback_restores_a_file_and_records_its_own_receipt(tmp_path):
    workspace = tmp_path / "workspace"
    target = workspace / "notes" / "demo.txt"
    target.parent.mkdir(parents=True)
    target.write_text("after value", encoding="utf-8")
    data_dir = tmp_path / "data"
    app = create_app(data_dir=data_dir, workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        recorded = client.post(
            "/api/events",
            json={
                "agent": "demo-agent",
                "action": "file.write",
                "target": "notes/demo.txt",
                "summary": "Changed the demo note",
                "before_text": "before secret value",
                "after_text": "after value",
            },
        ).json()
        rolled_back = client.post(
            f"/api/events/{recorded['id']}/rollback", json={"confirm": True}
        )
        verification = client.get("/api/verify")

    assert rolled_back.status_code == 200
    assert rolled_back.json()["status"] == "rolled_back"
    displaced_path = Path(rolled_back.json()["displaced_path"])
    assert target.read_text(encoding="utf-8") == "before secret value"
    assert displaced_path.read_text(encoding="utf-8") == "after value"
    assert stat.S_IMODE(displaced_path.parent.stat().st_mode) == 0o700
    assert verification.json() == {"valid": True, "event_count": 2, "broken_at": None}
    assert b"before secret value" not in (data_dir / "glassbox.db").read_bytes()


def test_rollback_retains_the_displaced_inode_for_late_open_fd_writes(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with (
        target.open("r+", encoding="utf-8") as held_file,
        TestClient(app, base_url="http://127.0.0.1") as client,
    ):
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()
        original_append = app.state.store.append

        def append_then_write_through_held_descriptor(payload):
            receipt = original_append(payload)
            held_file.seek(0)
            held_file.write("newer through held descriptor")
            held_file.truncate()
            held_file.flush()
            os.fsync(held_file.fileno())
            return receipt

        monkeypatch.setattr(
            app.state.store, "append", append_then_write_through_held_descriptor
        )
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 200
    displaced_path = Path(response.json()["displaced_path"])
    assert target.read_text(encoding="utf-8") == "before"
    assert displaced_path.read_text(encoding="utf-8") == (
        "newer through held descriptor"
    )
    assert stat.S_IMODE(displaced_path.parent.stat().st_mode) == 0o700


def test_rollback_refuses_to_overwrite_newer_work(tmp_path):
    workspace = tmp_path / "workspace"
    target = workspace / "demo.txt"
    workspace.mkdir()
    target.write_text("agent version", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "demo-agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "original",
                "after_text": "agent version",
            },
        ).json()
        target.write_text("human edited this later", encoding="utf-8")
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 409
    assert "refusing to overwrite newer work" in response.json()["detail"]
    assert target.read_text(encoding="utf-8") == "human edited this later"


def test_rollback_refuses_an_event_from_a_broken_receipt_chain(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    original_target = workspace / "original.txt"
    redirected_target = workspace / "redirected.txt"
    original_target.write_text("after", encoding="utf-8")
    redirected_target.write_text("after", encoding="utf-8")
    data_dir = tmp_path / "data"
    app = create_app(data_dir=data_dir, workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "original.txt",
                "summary": "Changed original",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()
        with sqlite3.connect(data_dir / "glassbox.db") as conn:
            conn.execute(
                "UPDATE events SET target = 'redirected.txt' WHERE id = ?",
                (event["id"],),
            )
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 409
    assert "receipt chain" in response.json()["detail"].lower()
    assert original_target.read_text(encoding="utf-8") == "after"
    assert redirected_target.read_text(encoding="utf-8") == "after"


def test_rollback_compensates_if_its_receipt_cannot_be_recorded(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(
        app, base_url="http://127.0.0.1", raise_server_exceptions=False
    ) as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()

        def fail_append(payload):
            raise sqlite3.OperationalError("simulated ledger failure")

        monkeypatch.setattr(app.state.store, "append", fail_append)
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 500
    assert target.read_text(encoding="utf-8") == "after"
    recovery_files = list(workspace.rglob(".demo.txt.glassbox-restore-*.tmp"))
    assert len(recovery_files) == 1
    assert recovery_files[0].read_text(encoding="utf-8") == "before"
    assert stat.S_IMODE(recovery_files[0].parent.stat().st_mode) == 0o700


def test_compensation_preserves_an_edit_arriving_at_its_atomic_exchange(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    original_exchange = store_module._exchange_paths
    calls = 0

    with TestClient(
        app, base_url="http://127.0.0.1", raise_server_exceptions=False
    ) as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()

        def fail_append(payload):
            raise sqlite3.OperationalError("simulated ledger failure")

        def exchange_with_compensation_race(first, second, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                target.write_text("newer during compensation", encoding="utf-8")
            original_exchange(first, second, **kwargs)

        monkeypatch.setattr(app.state.store, "append", fail_append)
        monkeypatch.setattr(
            store_module, "_exchange_paths", exchange_with_compensation_race
        )
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 500
    assert calls == 2
    assert target.read_text(encoding="utf-8") == "after"
    recovery_files = list(workspace.rglob(".demo.txt.glassbox-restore-*.tmp"))
    assert len(recovery_files) == 1
    assert recovery_files[0].read_text(encoding="utf-8") == (
        "newer during compensation"
    )


def test_rollback_rechecks_content_after_preparing_the_restore_file(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    original_write_temp = app.state.store._write_temp_text_at

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()

        def write_with_concurrent_edit(parent_fd, target_name, data, mode, *, label):
            result = original_write_temp(
                parent_fd, target_name, data, mode, label=label
            )
            if label == "restore":
                target.write_text("newer work", encoding="utf-8")
            return result

        monkeypatch.setattr(
            app.state.store, "_write_temp_text_at", write_with_concurrent_edit
        )
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 409
    assert target.read_text(encoding="utf-8") == "newer work"


def test_rollback_preserves_an_edit_arriving_at_the_atomic_exchange(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    original_exchange = store_module._exchange_paths
    calls = 0

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()

        def exchange_with_concurrent_edit(first, second, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                target.write_text("newer at exchange", encoding="utf-8")
            original_exchange(first, second, **kwargs)

        monkeypatch.setattr(
            store_module, "_exchange_paths", exchange_with_concurrent_edit
        )
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 409
    assert calls == 2
    assert target.read_text(encoding="utf-8") == "newer at exchange"
    recovery_files = list(workspace.rglob(".demo.txt.glassbox-restore-*.tmp"))
    assert len(recovery_files) == 1
    assert recovery_files[0].read_text(encoding="utf-8") == "before"
    assert stat.S_IMODE(recovery_files[0].parent.stat().st_mode) == 0o700


def test_rollback_preserves_an_edit_arriving_during_conflict_recovery(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    original_exchange = store_module._exchange_paths
    calls = 0

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()

        def exchange_with_two_concurrent_edits(first, second, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                target.write_text("newer at exchange", encoding="utf-8")
            elif calls == 2:
                target.write_text("newer during recovery", encoding="utf-8")
            original_exchange(first, second, **kwargs)

        monkeypatch.setattr(
            store_module, "_exchange_paths", exchange_with_two_concurrent_edits
        )
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 409
    assert calls == 2
    assert target.read_text(encoding="utf-8") == "newer at exchange"
    recovery_files = list(workspace.rglob(".demo.txt.glassbox-restore-*.tmp"))
    assert len(recovery_files) == 1
    assert recovery_files[0].read_text(encoding="utf-8") == "newer during recovery"


def test_rollback_preserves_displaced_content_if_interrupted_after_exchange(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    store = EventStore(tmp_path / "data")
    event = store.append(
        {
            "agent": "agent",
            "action": "file.write",
            "target": "demo.txt",
            "summary": "Changed demo",
            "before_text": "before",
            "after_text": "after",
        }
    )
    original_exchange = store_module._exchange_paths

    def exchange_then_interrupt(first, second, **kwargs):
        original_exchange(first, second, **kwargs)
        raise KeyboardInterrupt("simulated interruption after exchange")

    monkeypatch.setattr(store_module, "_exchange_paths", exchange_then_interrupt)

    with pytest.raises(KeyboardInterrupt, match="after exchange"):
        store.rollback(event["id"], workspace)

    recovery_files = list(workspace.rglob(".demo.txt.glassbox-restore-*.tmp"))
    assert target.read_text(encoding="utf-8") == "before"
    assert len(recovery_files) == 1
    assert recovery_files[0].read_text(encoding="utf-8") == "after"
    assert stat.S_IMODE(recovery_files[0].parent.stat().st_mode) == 0o700


def test_rollback_parent_swap_cannot_escape_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    parent = workspace / "notes"
    parent.mkdir(parents=True)
    target = parent / "demo.txt"
    target.write_text("after", encoding="utf-8")
    outside_parent = tmp_path / "outside"
    outside_parent.mkdir()
    outside_target = outside_parent / "demo.txt"
    outside_target.write_text("after", encoding="utf-8")
    parked_parent = tmp_path / "parked-notes"
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    original_exchange = store_module._exchange_paths
    calls = 0

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "notes/demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()

        def exchange_after_parent_swap(first, second, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                parent.rename(parked_parent)
                parent.symlink_to(outside_parent, target_is_directory=True)
                (outside_parent / Path(first).name).write_text(
                    "before", encoding="utf-8"
                )
            original_exchange(first, second, **kwargs)

        monkeypatch.setattr(store_module, "_exchange_paths", exchange_after_parent_swap)
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )
        verification = client.get("/api/verify")

    assert response.status_code == 409
    assert outside_target.read_text(encoding="utf-8") == "after"
    assert (parked_parent / "demo.txt").read_text(encoding="utf-8") == "after"
    assert verification.json() == {"valid": True, "event_count": 1, "broken_at": None}


def test_rollback_final_symlink_swap_is_recovered_without_receipt(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    original_exchange = store_module._exchange_paths
    calls = 0

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()

        def exchange_after_symlink_swap(first, second, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                target.unlink()
                target.symlink_to(outside)
            original_exchange(first, second, **kwargs)

        monkeypatch.setattr(
            store_module, "_exchange_paths", exchange_after_symlink_swap
        )
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )
        verification = client.get("/api/verify")

    recovery_files = list(workspace.rglob(".demo.txt.glassbox-restore-*.tmp"))
    assert response.status_code == 409
    assert target.is_symlink()
    assert target.resolve() == outside
    assert outside.read_text(encoding="utf-8") == "after"
    assert len(recovery_files) == 1
    assert recovery_files[0].is_file() and not recovery_files[0].is_symlink()
    assert recovery_files[0].read_text(encoding="utf-8") == "before"
    assert stat.S_IMODE(recovery_files[0].parent.stat().st_mode) == 0o700
    assert verification.json() == {"valid": True, "event_count": 1, "broken_at": None}


def test_rollback_does_not_mutate_an_outside_hard_link(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("after", encoding="utf-8")
    outside.chmod(0o755)
    target = workspace / "demo.txt"
    os.link(outside, target)
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 200
    assert target.read_text(encoding="utf-8") == "before"
    assert outside.read_text(encoding="utf-8") == "after"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o755
    recovery = Path(response.json()["displaced_path"])
    assert recovery.read_text(encoding="utf-8") == "after"
    assert stat.S_IMODE(recovery.parent.stat().st_mode) == 0o700


def test_rollback_uses_the_workspace_identity_pinned_at_app_creation(tmp_path):
    base = tmp_path / "base"
    workspace = base / "workspace"
    workspace.mkdir(parents=True)
    original = workspace / "victim.txt"
    original.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "victim.txt",
                "summary": "Changed victim",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()
        parked = tmp_path / "parked-base"
        base.rename(parked)
        attacker = tmp_path / "attacker"
        redirected_workspace = attacker / "workspace"
        redirected_workspace.mkdir(parents=True)
        redirected = redirected_workspace / "victim.txt"
        redirected.write_text("after", encoding="utf-8")
        base.symlink_to(attacker, target_is_directory=True)

        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 409
    assert (parked / "workspace" / "victim.txt").read_text(encoding="utf-8") == "after"
    assert redirected.read_text(encoding="utf-8") == "after"


def test_restore_candidate_is_private_before_the_first_exchange(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o755)
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    target.chmod(0o644)
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    original_write = app.state.store._write_temp_text_at
    observed: dict[str, int] = {}

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "historical snapshot",
                "after_text": "after",
            },
        ).json()

        def inspect_candidate(parent_fd, target_name, text, mode, *, label):
            name = original_write(parent_fd, target_name, text, mode, label=label)
            descriptor = os.open(name, os.O_RDONLY, dir_fd=parent_fd)
            try:
                observed["file"] = stat.S_IMODE(os.fstat(descriptor).st_mode)
                observed["directory"] = stat.S_IMODE(os.fstat(parent_fd).st_mode)
            finally:
                os.close(descriptor)
            return name

        monkeypatch.setattr(app.state.store, "_write_temp_text_at", inspect_candidate)
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 200
    assert observed["file"] == 0o600 or observed["directory"] == 0o700


def test_rollback_preserves_target_acl_and_strips_recovery_directory_acl(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(mode=0o750)
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    target.chmod(0o640)
    initial_acl = _posix_acl(target)
    assert initial_acl is None
    subprocess.run(
        ["setfacl", "-m", "d:u:nobody:r--", str(workspace)],
        check=True,
        capture_output=True,
        text=True,
    )
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed ACL-protected file",
                "before_text": "historical plaintext",
                "after_text": "after",
            },
        ).json()
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 200
    recovery = Path(response.json()["displaced_path"])
    assert target.read_text(encoding="utf-8") == "historical plaintext"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert _posix_acl(target) is initial_acl
    assert _posix_acl(recovery.parent) is None
    assert _posix_acl(recovery.parent, default=True) is None


@pytest.mark.parametrize("post_commit_error", [MemoryError, KeyboardInterrupt])
def test_post_commit_rollback_receipt_exception_does_not_compensate_filesystem(
    tmp_path, monkeypatch, post_commit_error
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(
        app, base_url="http://127.0.0.1", raise_server_exceptions=False
    ) as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()
        original_append = app.state.store.append

        def append_then_raise(payload):
            original_append(payload)
            raise post_commit_error("simulated post-commit exception")

        monkeypatch.setattr(app.state.store, "append", append_then_raise)
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )
        verification = client.get("/api/verify")

    assert response.status_code == 200
    assert target.read_text(encoding="utf-8") == "before"
    assert verification.json() == {"valid": True, "event_count": 2, "broken_at": None}


def test_rollback_rejects_same_content_inode_substitution_at_exchange(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    target.chmod(0o644)
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    original_exchange = store_module._exchange_paths
    calls = 0

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()

        def exchange_after_same_content_replacement(first, second, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                replacement = workspace / "replacement.txt"
                replacement.write_text("after", encoding="utf-8")
                replacement.chmod(0o600)
                os.replace(replacement, target)
            original_exchange(first, second, **kwargs)

        monkeypatch.setattr(
            store_module, "_exchange_paths", exchange_after_same_content_replacement
        )
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )
        verification = client.get("/api/verify")

    assert response.status_code == 409
    assert calls == 2
    assert target.read_text(encoding="utf-8") == "after"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert verification.json() == {"valid": True, "event_count": 1, "broken_at": None}


def test_rollback_operation_id_failure_happens_before_filesystem_exchange(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    store = EventStore(tmp_path / "data")
    event = store.append(
        {
            "agent": "agent",
            "action": "file.write",
            "target": "demo.txt",
            "summary": "Changed demo",
            "before_text": "before",
            "after_text": "after",
        }
    )
    real_token_hex = secrets.token_hex

    def fail_operation_id(length):
        if length == 16:
            raise MemoryError("simulated operation-id failure")
        return real_token_hex(length)

    monkeypatch.setattr(store_module.secrets, "token_hex", fail_operation_id)
    with pytest.raises(MemoryError, match="operation-id"):
        store.rollback(event["id"], workspace)

    assert target.read_text(encoding="utf-8") == "after"
    assert store.verify() == {"valid": True, "event_count": 1, "broken_at": None}
    assert not list(workspace.glob(".demo.txt.glassbox-recovery-*"))


def test_rollback_preserves_target_uid_and_gid(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    alternate_gid = _alternate_group()
    os.chown(target, os.geteuid(), alternate_gid)
    target.chmod(0o640)
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed group-owned file",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 200
    identity = target.stat()
    assert identity.st_uid == os.geteuid()
    assert identity.st_gid == alternate_gid
    assert stat.S_IMODE(identity.st_mode) == 0o640


def test_rollback_rejects_gid_change_at_atomic_exchange(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    alternate_gid = _alternate_group()
    os.chown(target, os.geteuid(), alternate_gid)
    target.chmod(0o640)
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    original_exchange = store_module._exchange_paths
    calls = 0

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed group-owned file",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()

        def exchange_after_gid_change(first, second, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                os.chown(target, os.geteuid(), os.getegid())
            original_exchange(first, second, **kwargs)

        monkeypatch.setattr(store_module, "_exchange_paths", exchange_after_gid_change)
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )
        verification = client.get("/api/verify")

    assert response.status_code == 409
    assert calls == 2
    identity = target.stat()
    assert target.read_text(encoding="utf-8") == "after"
    assert identity.st_uid == os.geteuid()
    assert identity.st_gid == os.getegid()
    assert verification.json() == {"valid": True, "event_count": 1, "broken_at": None}


def test_rollback_rejects_restore_candidate_symlink_substitution(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    original_exchange = store_module._exchange_paths
    calls = 0

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()

        def exchange_after_candidate_substitution(first, second, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 1:
                recovery_fd = kwargs["first_dir_fd"]
                os.unlink(first, dir_fd=recovery_fd)
                os.symlink(outside, first, dir_fd=recovery_fd)
            original_exchange(first, second, **kwargs)

        monkeypatch.setattr(
            store_module, "_exchange_paths", exchange_after_candidate_substitution
        )
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )
        verification = client.get("/api/verify")

    assert response.status_code == 409
    assert calls == 2
    assert target.is_file() and not target.is_symlink()
    assert target.read_text(encoding="utf-8") == "after"
    assert outside.read_text(encoding="utf-8") == "outside"
    assert verification.json() == {"valid": True, "event_count": 1, "broken_at": None}


def test_post_exchange_path_error_compensates_before_raising(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    store = EventStore(tmp_path / "data")
    event = store.append(
        {
            "agent": "agent",
            "action": "file.write",
            "target": "demo.txt",
            "summary": "Changed demo",
            "before_text": "before",
            "after_text": "after",
        }
    )
    original_parent_check = store._parent_is_current
    calls = 0

    def fail_post_exchange_parent_check(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated post-exchange validation failure")
        return original_parent_check(*args, **kwargs)

    monkeypatch.setattr(store, "_parent_is_current", fail_post_exchange_parent_check)
    with pytest.raises(store_module.RollbackError, match="compensated"):
        store.rollback(event["id"], workspace)

    assert target.read_text(encoding="utf-8") == "after"
    assert store.verify() == {"valid": True, "event_count": 1, "broken_at": None}
    recovery = list(workspace.glob(".demo.txt.glassbox-recovery-*/*"))
    assert len(recovery) == 1
    assert recovery[0].read_text(encoding="utf-8") == "before"


def test_database_hard_link_added_before_commit_is_not_mutated(tmp_path, monkeypatch):
    store = EventStore(tmp_path / "data")
    outside = tmp_path / "outside.db"
    original_validate = store._validate_security_entries
    calls = 0

    def validate_then_link():
        nonlocal calls
        original_validate()
        calls += 1
        if calls == 3:
            os.link(store.db_path, outside)

    monkeypatch.setattr(store, "_validate_security_entries", validate_then_link)
    receipt = store.append(
        {
            "agent": "agent",
            "action": "tool.read",
            "target": "notes.txt",
            "summary": "Copy-on-write database commit",
        }
    )

    assert receipt["id"] == 1
    with sqlite3.connect(outside) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    with sqlite3.connect(store.db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert outside.stat().st_ino != store.db_path.stat().st_ino


def test_database_descriptor_is_not_closed_while_a_reader_uses_it(
    tmp_path, monkeypatch
):
    store = EventStore(tmp_path / "data")
    store.append(
        {
            "agent": "real",
            "action": "tool.read",
            "target": "real.txt",
            "summary": "Original database event",
        }
    )
    wrong_store = EventStore(tmp_path / "wrong-data")
    wrong_store.append(
        {
            "agent": "WRONG_DB",
            "action": "tool.read",
            "target": "wrong.txt",
            "summary": "Descriptor reuse sentinel",
        }
    )
    old_descriptor = store._db_fd
    assert old_descriptor is not None
    original_read = store._read_database_bytes
    reader_entered = threading.Event()
    release_reader = threading.Event()
    writer_done = threading.Event()
    reader_result: list[dict[str, object]] = []
    reader_errors: list[BaseException] = []
    opened_descriptors: list[int] = []

    def paused_read(descriptor):
        if threading.current_thread().name == "glassbox-reader":
            reader_entered.set()
            assert release_reader.wait(5)
        return original_read(descriptor)

    def read_events():
        try:
            reader_result.extend(store.list_events())
        except (OSError, RuntimeError, sqlite3.Error, AssertionError) as exc:
            reader_errors.append(exc)

    def publish_event():
        try:
            store.append(
                {
                    "agent": "writer",
                    "action": "tool.read",
                    "target": "writer.txt",
                    "summary": "Concurrent database publication",
                }
            )
        finally:
            writer_done.set()

    monkeypatch.setattr(store, "_read_database_bytes", paused_read)
    reader = threading.Thread(target=read_events, name="glassbox-reader")
    writer = threading.Thread(target=publish_event, name="glassbox-writer")
    reader.start()
    assert reader_entered.wait(5)
    writer.start()

    if writer_done.wait(2):
        for _ in range(128):
            descriptor = os.open(wrong_store.db_path, os.O_RDONLY)
            opened_descriptors.append(descriptor)
            if descriptor == old_descriptor:
                break
        assert old_descriptor in opened_descriptors

    release_reader.set()
    reader.join(5)
    writer.join(5)
    for descriptor in opened_descriptors:
        os.close(descriptor)

    assert not reader_errors
    assert [event["agent"] for event in reader_result] == ["real"]
    assert writer_done.is_set()
    assert store.verify() == {"valid": True, "event_count": 2, "broken_at": None}


def test_workspace_is_pinned_before_resolve_boundary_can_redirect_it(
    tmp_path, monkeypatch
):
    configured_parent = tmp_path / "configured"
    configured_workspace = configured_parent / "workspace"
    configured_workspace.mkdir(parents=True)
    original_target = configured_workspace / "demo.txt"
    original_target.write_text("after", encoding="utf-8")
    redirected_parent = tmp_path / "redirected"
    redirected_workspace = redirected_parent / "workspace"
    redirected_workspace.mkdir(parents=True)
    redirected_target = redirected_workspace / "demo.txt"
    redirected_target.write_text("after", encoding="utf-8")
    moved_parent = tmp_path / "configured-original"
    original_resolve = Path.resolve
    swapped = False

    def resolve_then_redirect(path, *args, **kwargs):
        nonlocal swapped
        result = original_resolve(path, *args, **kwargs)
        if path == configured_workspace and not swapped:
            swapped = True
            configured_parent.rename(moved_parent)
            configured_parent.symlink_to(redirected_parent, target_is_directory=True)
        return result

    monkeypatch.setattr(Path, "resolve", resolve_then_redirect)
    app = create_app(data_dir=tmp_path / "data", workspace=configured_workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed configured workspace",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 200
    assert swapped is False
    assert original_target.read_text() == "before"
    assert redirected_target.read_text() == "after"


def test_database_publish_reconciles_exception_immediately_after_exchange(
    tmp_path, monkeypatch
):
    store = EventStore(tmp_path / "data")
    original_exchange = store_module._exchange_paths
    injected = False

    def exchange_then_interrupt(first, second, **kwargs):
        nonlocal injected
        original_exchange(first, second, **kwargs)
        if second == "glassbox.db" and not injected:
            injected = True
            raise MemoryError("simulated interruption after database publication")

    monkeypatch.setattr(store_module, "_exchange_paths", exchange_then_interrupt)
    receipt = store.append(
        {
            "agent": "agent",
            "action": "tool.read",
            "target": "notes.txt",
            "summary": "Database publication interruption probe",
        }
    )

    assert injected is True
    assert receipt["id"] == 1
    assert store.verify() == {"valid": True, "event_count": 1, "broken_at": None}


def test_event_api_rejects_nonfinite_oversized_and_deep_metadata(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    base = {
        "agent": "agent",
        "action": "tool.read",
        "target": "notes.txt",
        "summary": "Invalid metadata",
    }
    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(17):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child

    with TestClient(app, base_url="http://127.0.0.1") as client:
        nonfinite = client.post(
            "/api/events",
            content=(
                b'{"agent":"agent","action":"tool.read","target":"notes.txt",'
                b'"summary":"Invalid metadata","metadata":{"score":NaN}}'
            ),
            headers={"Content-Type": "application/json"},
        )
        oversized = client.post(
            "/api/events", json={**base, "metadata": {"value": "x" * 65_536}}
        )
        nested = client.post("/api/events", json={**base, "metadata": deep})
        verification = client.get("/api/verify")

    assert nonfinite.status_code == 422
    assert oversized.status_code == 422
    assert nested.status_code == 422
    assert verification.json() == {"valid": True, "event_count": 0, "broken_at": None}


def test_timeline_lists_newest_receipts_without_snapshot_contents(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        for summary in ("First action", "Second action"):
            client.post(
                "/api/events",
                json={
                    "agent": "demo-agent",
                    "action": "tool.read",
                    "target": "demo.txt",
                    "summary": summary,
                    "before_text": "private snapshot",
                },
            )
        response = client.get("/api/events")

    assert response.status_code == 200
    events = response.json()["events"]
    assert [event["summary"] for event in events] == ["Second action", "First action"]
    assert "before_text" not in events[0]
    assert "before_ciphertext" not in events[0]


def test_dashboard_rejects_untrusted_host_headers(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.get("/api/events", headers={"Host": "attacker.example"})
        testserver_response = client.get("/api/events", headers={"Host": "testserver"})

    assert response.status_code == 400
    assert testserver_response.status_code == 400


def test_mutations_reject_cross_origin_browser_requests(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = workspace / "demo.txt"
    target.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()
        response = client.post(
            f"/api/events/{event['id']}/rollback",
            json={"confirm": True},
            headers={"Origin": "https://attacker.example"},
        )
        local_port_response = client.post(
            f"/api/events/{event['id']}/rollback",
            json={"confirm": True},
            headers={"Host": "localhost:8765", "Origin": "http://localhost:9999"},
        )

    assert response.status_code == 403
    assert local_port_response.status_code == 403
    assert target.read_text(encoding="utf-8") == "after"


@pytest.mark.parametrize(
    "origin",
    [
        "http://user@testserver",
        "http://testserver/path",
        "http://testserver?query=yes",
        "http://testserver#fragment",
        "ftp://testserver",
        "null",
    ],
)
def test_mutations_reject_noncanonical_origin_values(tmp_path, origin):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.post(
            "/api/events",
            headers={"Origin": origin},
            json={
                "agent": "agent",
                "action": "tool.read",
                "target": "demo.txt",
                "summary": "Read demo",
            },
        )
        events = client.get("/api/events").json()["events"]

    assert response.status_code == 403
    assert events == []


def test_dashboard_is_served_as_the_product_home(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Glassbox" in response.text
    assert "Agent receipts" in response.text
    assert "/static/app.js" in response.text
    assert "fonts.googleapis.com" not in response.text
    assert "fonts.gstatic.com" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "connect-src 'self'" in response.headers["content-security-policy"]


def test_verification_identifies_the_first_tampered_receipt(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data_dir = tmp_path / "data"
    app = create_app(data_dir=data_dir, workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "tool.read",
                "target": "a",
                "summary": "Untouched",
            },
        )
        client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "tool.read",
                "target": "b",
                "summary": "Original",
            },
        )
        with sqlite3.connect(data_dir / "glassbox.db") as conn:
            conn.execute("UPDATE events SET summary = 'Altered later' WHERE id = 2")
        verification = client.get("/api/verify")

    assert verification.json() == {"valid": False, "event_count": 2, "broken_at": 2}


def test_verification_detects_tampered_encrypted_snapshot(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data_dir = tmp_path / "data"
    app = create_app(data_dir=data_dir, workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "demo.txt",
                "summary": "Changed demo",
                "before_text": "before",
                "after_text": "after",
            },
        )
        with sqlite3.connect(data_dir / "glassbox.db") as conn:
            conn.execute("UPDATE events SET before_ciphertext = X'00FF' WHERE id = 1")
        verification = client.get("/api/verify")

    assert verification.json() == {"valid": False, "event_count": 1, "broken_at": 1}


def test_verification_reports_malformed_signed_metadata_as_tampering(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data_dir = tmp_path / "data"
    app = create_app(data_dir=data_dir, workspace=workspace)

    with TestClient(
        app, base_url="http://127.0.0.1", raise_server_exceptions=False
    ) as client:
        client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "tool.read",
                "target": "demo.txt",
                "summary": "Read demo",
            },
        )
        with sqlite3.connect(data_dir / "glassbox.db") as conn:
            conn.execute("UPDATE events SET metadata_json = '{broken' WHERE id = 1")
        verification = client.get("/api/verify")

    assert verification.status_code == 200
    assert verification.json() == {"valid": False, "event_count": 1, "broken_at": 1}


@pytest.mark.parametrize(
    "mutation",
    [
        "receipt_hash = X'00'",
        "created_at = X'00'",
    ],
)
def test_verification_treats_invalid_database_types_as_tampering(tmp_path, mutation):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    data_dir = tmp_path / "data"
    app = create_app(data_dir=data_dir, workspace=workspace)

    with TestClient(
        app, base_url="http://127.0.0.1", raise_server_exceptions=False
    ) as client:
        client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "tool.read",
                "target": "demo.txt",
                "summary": "Read demo",
            },
        )
        with sqlite3.connect(data_dir / "glassbox.db") as conn:
            conn.execute(f"UPDATE events SET {mutation} WHERE id = 1")
        verification = client.get("/api/verify")

    assert verification.status_code == 200
    assert verification.json() == {"valid": False, "event_count": 1, "broken_at": 1}


def test_rollback_never_writes_outside_the_configured_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("after", encoding="utf-8")
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with TestClient(app, base_url="http://127.0.0.1") as client:
        event = client.post(
            "/api/events",
            json={
                "agent": "agent",
                "action": "file.write",
                "target": "../outside.txt",
                "summary": "Suspicious write",
                "before_text": "before",
                "after_text": "after",
            },
        ).json()
        response = client.post(
            f"/api/events/{event['id']}/rollback", json={"confirm": True}
        )

    assert response.status_code == 400
    assert "outside the configured workspace" in response.json()["detail"]
    assert outside.read_text(encoding="utf-8") == "after"


def test_concurrent_writers_preserve_a_single_valid_receipt_chain(tmp_path):
    store = EventStore(tmp_path / "data")

    def record(index: int) -> int:
        event = store.append(
            {
                "agent": f"agent-{index % 4}",
                "action": "tool.read",
                "target": f"item-{index}",
                "summary": f"Read item {index}",
            }
        )
        return event["id"]

    with ThreadPoolExecutor(max_workers=16) as pool:
        ids = list(pool.map(record, range(64)))

    assert len(set(ids)) == 64
    assert store.verify() == {"valid": True, "event_count": 64, "broken_at": None}
