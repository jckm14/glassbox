from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "scripts" / "render-launch-assets.sh"
SERVER_HELPER = ROOT / "scripts" / "render-launch-server.py"
CHECKLIST = ROOT / "docs" / "launch" / "LAUNCH-CHECKLIST.md"
LAUNCH_README = ROOT / "docs" / "launch" / "README.md"


def test_renderer_uses_bound_socket_and_run_specific_identity() -> None:
    renderer = RENDERER.read_text(encoding="utf-8")
    helper = SERVER_HELPER.read_text(encoding="utf-8")

    assert "render-launch-server.py" in renderer
    assert 'kill -0 "$SERVER_PID"' in renderer
    assert "__glassbox_launch_ready__/$NONCE" in renderer
    assert "__glassbox_launch_rollback__/$NONCE/3" in renderer
    assert "PORT=$(python3" not in renderer
    assert 'listener.bind(("127.0.0.1", 0))' in helper
    assert "server.run(sockets=[listener])" in helper
    assert 'self.ready_path = f"/__glassbox_launch_ready__/{nonce}"' in helper
    assert 'self.rollback_path = f"/__glassbox_launch_rollback__/{nonce}/3"' in helper
    assert 'scope["path"] == self.ready_path' in helper


def test_renderer_stages_and_atomically_publishes_complete_asset_set() -> None:
    renderer = RENDERER.read_text(encoding="utf-8")

    assert "STAGING_DIR=" in renderer
    assert renderer.index("trap cleanup EXIT") < renderer.index("DEMO_DIR=$(mktemp")
    assert "RENAME_EXCHANGE" in renderer
    assert "validate staged launch assets" in renderer
    assert 'for directory in "$DEMO_DIR" "$CHROMIUM_DIR" "$STAGING_DIR"' in renderer
    assert renderer.index("RENAME_EXCHANGE") < renderer.index("Wrote %s, %s, and %s")


def test_renderer_normalizes_ambient_locale_and_uses_locked_environment() -> None:
    renderer = RENDERER.read_text(encoding="utf-8")

    assert "export TZ=UTC" in renderer
    assert "export LC_ALL=C.UTF-8" in renderer
    assert "uv run --locked" in renderer
    assert "--lang=en-US" in renderer


def test_launch_docs_describe_toolchain_dependent_rendering_honestly() -> None:
    checklist = CHECKLIST.read_text(encoding="utf-8")
    launch_readme = LAUNCH_README.read_text(encoding="utf-8")

    assert "reproducible walkthrough" not in checklist.lower()
    assert "not guaranteed byte-for-byte" in launch_readme.lower()
    assert "chromium" in launch_readme.lower()
    assert "imagemagick" in launch_readme.lower()


def test_walkthrough_caption_does_not_claim_visual_proof_of_restored_bytes() -> None:
    renderer = RENDERER.read_text(encoding="utf-8")

    assert "Guarded rollback restores the file" not in renderer
    assert "the renderer verified the restored bytes" in renderer


def test_allocation_failure_cleans_earlier_temporary_directory(
    tmp_path: Path,
) -> None:
    before = set(Path("/tmp").glob("glassbox-launch-assets.*"))
    environment = os.environ.copy()
    environment["HOME"] = str(tmp_path / "missing-home")
    result = subprocess.run(
        [str(RENDERER)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode != 0
    assert set(Path("/tmp").glob("glassbox-launch-assets.*")) == before


def test_bound_server_exposes_run_specific_identity(tmp_path: Path) -> None:
    nonce = "a" * 64
    workspace = tmp_path / "workspace"
    data_dir = tmp_path / "data"
    port_file = tmp_path / "port"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(ROOT / "src")
    process = subprocess.Popen(
        [
            sys.executable,
            str(SERVER_HELPER),
            "--workspace",
            str(workspace),
            "--data-dir",
            str(data_dir),
            "--nonce",
            nonce,
            "--port-file",
            str(port_file),
        ],
        cwd=ROOT,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not port_file.exists():
            assert process.poll() is None, process.stderr.read()
            time.sleep(0.05)
        if not port_file.exists():
            details = process.stderr.read() if process.poll() is not None else ""
            raise AssertionError(f"server did not publish port: {details}")
        port = int(port_file.read_text(encoding="ascii").strip())
        identity_url = f"http://127.0.0.1:{port}/__glassbox_launch_ready__/{nonce}"
        while True:
            try:
                with urlopen(identity_url, timeout=2) as response:
                    assert response.read().decode("ascii") == nonce
                break
            except URLError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)
        try:
            urlopen(
                f"http://127.0.0.1:{port}/__glassbox_launch_ready__/wrong",
                timeout=2,
            )
        except HTTPError as exc:
            assert exc.code == 404
        else:
            raise AssertionError("wrong launch identity unexpectedly succeeded")

        rollback_body = b'{"confirm":true}'
        wrong_rollback = Request(
            f"http://127.0.0.1:{port}/__glassbox_launch_rollback__/wrong/3",
            data=rollback_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urlopen(wrong_rollback, timeout=2)
        except HTTPError as exc:
            assert exc.code == 404
        else:
            raise AssertionError("wrong rollback identity unexpectedly succeeded")
        assert (workspace / "launch-plan.md").read_text(encoding="utf-8")

        rollback = Request(
            f"http://127.0.0.1:{port}/__glassbox_launch_rollback__/{nonce}/3",
            data=rollback_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(rollback, timeout=10) as response:
            result = json.loads(response.read())
        assert result["status"] == "rolled_back"
        assert result["rollback_receipt_id"] == 5
        assert (workspace / "launch-plan.md").read_text(encoding="utf-8") == ""
        assert process.poll() is None
    finally:
        process.terminate()
        process.wait(timeout=10)
