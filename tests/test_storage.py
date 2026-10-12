import os
import sqlite3
import stat
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from glassbox.app import create_app
from glassbox.store import EventStore


def _write_event(store: EventStore, target: str = "demo.txt", **overrides):
    payload = {
        "agent": "agent",
        "action": "file.write",
        "target": target,
        "summary": f"Changed {target}",
        "before_text": "before\n",
        "after_text": "after\n",
    }
    payload.update(overrides)
    return store.append(payload)


def _snapshot_files(store: EventStore) -> list[str]:
    return sorted(os.listdir(store.data_dir / "snapshots"))


def test_snapshots_are_private_files_outside_the_database(tmp_path):
    store = EventStore(tmp_path / "data")
    event = _write_event(store)

    snapshot_dir = store.data_dir / "snapshots"
    assert stat.S_IMODE(snapshot_dir.stat().st_mode) == 0o700
    names = _snapshot_files(store)
    assert event["snapshot_sha256"] in names
    assert event["diff_sha256"] in names
    for name in names:
        entry = snapshot_dir / name
        assert stat.S_IMODE(entry.stat().st_mode) == 0o600
        assert b"before" not in entry.read_bytes()
    with sqlite3.connect(store.db_path) as conn:
        stored = conn.execute("SELECT before_ciphertext FROM events").fetchone()[0]
    assert stored is None
    assert store.verify() == {"valid": True, "event_count": 1, "broken_at": None}


def test_database_stays_small_when_snapshots_are_large(tmp_path):
    store = EventStore(tmp_path / "data")
    text = "x" * 300_000
    for index in range(4):
        _write_event(store, f"big-{index}.txt", before_text=text, after_text=text + "y")

    assert store.db_path.stat().st_size < 64_000
    assert store.verify()["valid"] is True


def test_verification_detects_a_tampered_snapshot_file(tmp_path):
    store = EventStore(tmp_path / "data")
    _write_event(store, "one.txt")
    second = _write_event(store, "two.txt")

    entry = store.data_dir / "snapshots" / second["snapshot_sha256"]
    entry.write_bytes(b"tampered")

    assert store.verify() == {"valid": False, "event_count": 2, "broken_at": 2}


def test_verification_detects_a_deleted_snapshot_file(tmp_path):
    store = EventStore(tmp_path / "data")
    event = _write_event(store)

    (store.data_dir / "snapshots" / event["snapshot_sha256"]).unlink()

    assert store.verify() == {"valid": False, "event_count": 1, "broken_at": 1}
    assert store.verify(check_snapshots=False)["valid"] is True


def test_snapshot_replaced_by_a_symlink_or_hard_link_is_rejected(tmp_path):
    store = EventStore(tmp_path / "data")
    event = _write_event(store)
    entry = store.data_dir / "snapshots" / event["snapshot_sha256"]
    outside = tmp_path / "outside.bin"
    outside.write_bytes(entry.read_bytes())
    outside.chmod(0o600)

    entry.unlink()
    entry.symlink_to(outside)
    assert store.verify()["valid"] is False

    entry.unlink()
    os.link(outside, entry)
    assert store.verify()["valid"] is False


def test_snapshot_directory_must_be_private(tmp_path):
    data_dir = tmp_path / "data"
    EventStore(data_dir).close()
    (data_dir / "snapshots").chmod(0o755)

    with pytest.raises(RuntimeError, match="snapshot directory"):
        EventStore(data_dir)


def test_snapshot_directory_swap_fails_closed(tmp_path):
    store = EventStore(tmp_path / "data")
    _write_event(store)
    snapshot_dir = store.data_dir / "snapshots"
    snapshot_dir.rename(store.data_dir / "moved")
    (store.data_dir / "moved").rename(snapshot_dir)  # same inode: still fine
    assert store.verify()["valid"] is True

    snapshot_dir.rename(store.data_dir / "moved")
    snapshot_dir.mkdir(mode=0o700)
    assert store.verify()["valid"] is False
    with pytest.raises(RuntimeError, match="snapshot directory changed"):
        _write_event(store, "other.txt")


def test_inline_snapshots_from_older_ledgers_are_moved_to_files(tmp_path):
    data_dir = tmp_path / "data"
    store = EventStore(data_dir)
    event = _write_event(store)
    blob = store.data_dir / "snapshots" / event["snapshot_sha256"]
    ciphertext = blob.read_bytes()
    store.close()
    # Recreate the layout an 0.1 ledger used: ciphertext inside the row.
    with sqlite3.connect(data_dir / "glassbox.db") as conn:
        conn.execute("UPDATE events SET before_ciphertext = ?", (ciphertext,))
    blob.unlink()

    reopened = EventStore(data_dir)

    assert blob.read_bytes() == ciphertext
    with sqlite3.connect(reopened.db_path) as conn:
        assert (
            conn.execute("SELECT before_ciphertext FROM events").fetchone()[0] is None
        )
    assert reopened.verify() == {"valid": True, "event_count": 1, "broken_at": None}


def test_receipts_signed_before_new_fields_still_verify(tmp_path):
    data_dir = tmp_path / "data"
    store = EventStore(data_dir)
    # Sign a record exactly as 0.1 did: without risk_reason or diff_sha256.
    record = {
        "created_at": "2026-07-26T16:00:00+00:00",
        "agent": "agent",
        "action": "tool.read",
        "target": "notes.txt",
        "summary": "Legacy receipt",
        "metadata": {},
        "before_sha256": None,
        "after_sha256": None,
        "snapshot_sha256": None,
        "risk": "low",
        "reversible": False,
        "previous_hash": "0" * 64,
    }
    receipt_hash = store._sign(record)
    store.close()
    with sqlite3.connect(data_dir / "glassbox.db") as conn:
        conn.execute(
            "INSERT INTO events (created_at, agent, action, target, summary, "
            "metadata_json, risk, reversible, previous_hash, receipt_hash) "
            "VALUES (?, 'agent', 'tool.read', 'notes.txt', 'Legacy receipt', '{}', "
            "'low', 0, ?, ?)",
            (record["created_at"], record["previous_hash"], receipt_hash),
        )

    reopened = EventStore(data_dir)
    reopened.append(
        {"agent": "agent", "action": "tool.read", "target": "b", "summary": "New"}
    )

    assert reopened.verify() == {"valid": True, "event_count": 2, "broken_at": None}
    with sqlite3.connect(reopened.db_path) as conn:
        conn.execute("UPDATE events SET risk_reason = 'Forged' WHERE id = 1")
    assert reopened.verify() == {"valid": False, "event_count": 2, "broken_at": 1}


def test_risk_reason_and_diff_reference_are_authenticated(tmp_path):
    store = EventStore(tmp_path / "data")
    _write_event(store)

    with sqlite3.connect(store.db_path) as conn:
        conn.execute("UPDATE events SET risk_reason = 'Harmless' WHERE id = 1")
    assert store.verify()["valid"] is False

    with sqlite3.connect(store.db_path) as conn:
        conn.execute("UPDATE events SET risk_reason = NULL WHERE id = 1")
    assert store.verify()["valid"] is False


def test_prune_removes_content_and_explains_it_with_a_signed_receipt(tmp_path):
    store = EventStore(tmp_path / "data")
    for index in range(3):
        _write_event(store, f"file-{index}.txt")

    result = store.prune_snapshots(keep_last=1)

    assert result["pruned"] == 2
    assert result["bytes_freed"] > 0
    assert len(_snapshot_files(store)) == 2
    assert store.verify() == {"valid": True, "event_count": 4, "broken_at": None}
    events = {event["id"]: event for event in store.list_events()}
    assert events[1]["snapshot_pruned"] is True
    assert events[1]["reversible"] is False
    assert events[3]["snapshot_pruned"] is False
    assert events[3]["reversible"] is True
    assert events[4]["action"] == "snapshot.prune"
    assert events[4]["metadata"]["pruned_event_ids"] == [1, 2]
    assert store.read_diff(1) == {
        "event_id": 1,
        "available": False,
        "reason": "The recorded content for this receipt was pruned",
    }
    assert store.prune_snapshots(keep_last=1)["pruned"] == 0


def test_prune_by_age_keeps_recent_snapshots(tmp_path):
    store = EventStore(tmp_path / "data")
    _write_event(store)

    assert store.prune_snapshots(older_than=timedelta(days=1))["pruned"] == 0
    assert store.prune_snapshots(older_than=timedelta(seconds=-5))["pruned"] == 1
    with pytest.raises(ValueError, match="keep_last"):
        store.prune_snapshots()


def test_a_missing_snapshot_is_not_excused_by_a_forged_prune_claim(tmp_path):
    store = EventStore(tmp_path / "data")
    event = _write_event(store)
    (store.data_dir / "snapshots" / event["snapshot_sha256"]).unlink()

    # A prune receipt only counts when Glassbox itself wrote it.
    store.append(
        {
            "agent": "intruder",
            "action": "snapshot.prune",
            "target": "1 receipts",
            "summary": "Pretend prune",
            "metadata": {"pruned_event_ids": [1]},
        }
    )

    assert store.verify()["valid"] is False


def test_api_rejects_reserved_agent_and_actions(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    base = {"target": "x", "summary": "Impersonation attempt"}

    with TestClient(app, base_url="http://127.0.0.1") as client:
        as_glassbox = client.post(
            "/api/events", json={**base, "agent": "Glassbox", "action": "tool.read"}
        )
        prune = client.post(
            "/api/events", json={**base, "agent": "agent", "action": "snapshot.prune"}
        )
        rollback = client.post(
            "/api/events", json={**base, "agent": "agent", "action": "file.rollback"}
        )
        events = client.get("/api/events").json()

    assert as_glassbox.status_code == 422
    assert prune.status_code == 422
    assert rollback.status_code == 422
    assert events["events"] == []


def test_failed_receipt_write_does_not_leave_snapshot_files(tmp_path, monkeypatch):
    store = EventStore(tmp_path / "data")

    def fail_publish(database_bytes):
        raise OSError("simulated publish failure")

    monkeypatch.setattr(store, "_publish_database", fail_publish)
    with pytest.raises(OSError, match="simulated publish failure"):
        _write_event(store)

    assert _snapshot_files(store) == []


def test_read_only_store_reads_without_writing(tmp_path):
    data_dir = tmp_path / "data"
    store = EventStore(data_dir)
    _write_event(store)
    before = (data_dir / "glassbox.db").stat()

    reader = EventStore(data_dir, read_only=True)

    assert reader.verify() == {"valid": True, "event_count": 1, "broken_at": None}
    assert reader.list_events()[0]["target"] == "demo.txt"
    with pytest.raises(RuntimeError, match="read-only"):
        _write_event(reader)
    after = (data_dir / "glassbox.db").stat()
    assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)
    # The writer keeps working: the reader did not republish the database.
    _write_event(store, "second.txt")
    assert store.verify()["valid"] is True


def test_read_only_store_requires_an_existing_ledger(tmp_path):
    with pytest.raises(RuntimeError):
        EventStore(tmp_path / "missing", read_only=True)
    assert not (tmp_path / "missing").exists()


def test_paging_filters_and_whole_ledger_stats(tmp_path):
    store = EventStore(tmp_path / "data")
    for index in range(5):
        store.append(
            {
                "agent": "reader" if index % 2 else "writer",
                "action": "tool.read",
                "target": f"doc-{index}.md",
                "summary": f"Read 100% of doc_{index}",
                "metadata": {"session_id": "s1" if index < 3 else "s2"},
            }
        )
    store.append(
        {
            "agent": "writer",
            "action": "shell.exec",
            "target": "rm -rf build",
            "summary": "Cleaned",
            "metadata": {"session_id": "s2"},
        }
    )
    _write_event(store)

    first = store.page_events(3)
    assert [event["id"] for event in first["events"]] == [7, 6, 5]
    assert first["total"] == 7
    assert first["next_before_id"] == 5
    second = store.page_events(3, before_id=first["next_before_id"])
    assert [event["id"] for event in second["events"]] == [4, 3, 2]
    last = store.page_events(3, before_id=second["next_before_id"])
    assert [event["id"] for event in last["events"]] == [1]
    assert last["next_before_id"] is None

    assert [e["id"] for e in store.list_events(risk="high")] == [6]
    assert store.page_events(agent="reader")["total"] == 2
    assert store.page_events(session="s2")["total"] == 3
    assert store.page_events(action="file.write")["total"] == 1
    assert store.page_events(reversible=True)["total"] == 1
    assert store.page_events(reversible=False)["total"] == 6
    assert store.page_events(query="doc_3")["total"] == 1
    assert store.page_events(query="100%")["total"] == 5
    assert store.page_events(query="%")["total"] == 5
    assert store.page_events(query="RM -RF")["total"] == 1

    stats = store.stats()
    assert stats["total"] == 7
    assert (stats["high"], stats["medium"], stats["low"]) == (1, 1, 5)
    assert stats["reversible"] == 1
    assert stats["agents"][0] == {"agent": "writer", "count": 4}
    assert [s["session_id"] for s in stats["sessions"]] == ["s2", "s1"]
    assert stats["head_id"] == 7
    assert stats["head_hash"] == store.head()["head_hash"]
    assert store.get_event(6)["risk_reason"] == "Command recursive or forced delete"
    assert store.get_event(99) is None


def test_recorded_diff_is_encrypted_at_rest_and_redacted_on_read(tmp_path):
    store = EventStore(tmp_path / "data")
    _write_event(
        store,
        before_text="name = demo\n",
        after_text="name = demo\npassword = hunter2hunter2\n",
    )
    created = store.append(
        {
            "agent": "agent",
            "action": "file.create",
            "target": "new.txt",
            "summary": "Created",
            "after_text": "hello\n",
        }
    )
    deleted = store.append(
        {
            "agent": "agent",
            "action": "file.delete",
            "target": "old.txt",
            "summary": "Deleted",
            "before_text": "goodbye\n",
        }
    )
    plain = store.append(
        {"agent": "agent", "action": "tool.read", "target": "x", "summary": "Read"}
    )

    diff = store.read_diff(1)
    assert diff["available"] is True
    assert "+password=[REDACTED]" in diff["diff"]
    assert "hunter2" not in diff["diff"]
    assert (diff["lines_added"], diff["lines_removed"]) == (1, 0)
    assert "+hello" in store.read_diff(created["id"])["diff"]
    assert "-goodbye" in store.read_diff(deleted["id"])["diff"]
    assert store.read_diff(plain["id"])["available"] is False
    assert store.read_diff(99) is None
    for name in _snapshot_files(store):
        assert b"hunter2" not in (store.data_dir / "snapshots" / name).read_bytes()


def test_diff_endpoint_is_off_unless_enabled(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    payload = {
        "agent": "agent",
        "action": "file.write",
        "target": "demo.txt",
        "summary": "Changed demo",
        "before_text": "before\n",
        "after_text": "after\n",
    }

    app = create_app(data_dir=tmp_path / "data", workspace=workspace)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        client.post("/api/events", json=payload)
        closed = client.get("/api/events/1/diff")
        config = client.get("/api/config").json()
    assert closed.status_code == 403
    assert config["show_diffs"] is False

    app = create_app(data_dir=tmp_path / "data", workspace=workspace, show_diffs=True)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        opened = client.get("/api/events/1/diff")
        missing = client.get("/api/events/9/diff")
        single = client.get("/api/events/1")
        absent = client.get("/api/events/9")
        export = client.get("/api/export").json()
    assert opened.status_code == 200
    assert "-before" in opened.json()["diff"]
    assert missing.status_code == 404
    assert single.json()["has_diff"] is True
    assert "before_ciphertext" not in single.json()
    assert absent.status_code == 404
    assert export["verification"]["valid"] is True
    assert [event["id"] for event in export["events"]] == [1]


def test_second_server_on_the_same_data_directory_is_refused(tmp_path, monkeypatch):
    import glassbox.app as app_module

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    real_acquire = app_module.WriterLock.acquire
    monkeypatch.setattr(
        app_module.WriterLock,
        "acquire",
        lambda self, *, timeout=0.0, info=None: real_acquire(
            self, timeout=0.0, info=info
        ),
    )
    app = create_app(data_dir=tmp_path / "data", workspace=workspace)

    with (
        TestClient(app, base_url="http://127.0.0.1"),
        pytest.raises(RuntimeError, match="already writing"),
    ):
        create_app(data_dir=tmp_path / "data", workspace=workspace)
    # Shutdown releases the lock.
    create_app(data_dir=tmp_path / "data", workspace=workspace)
