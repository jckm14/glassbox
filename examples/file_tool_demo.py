"""Run a synthetic file-tool integration against the real in-process API.

Linux only. Uses disposable files, no model, no credentials, and no network.
Run: uv run python examples/file_tool_demo.py
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi.testclient import TestClient

from glassbox.app import create_app


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def recorded_demo_write(client: TestClient, target: Path, text: str) -> int:
    """Illustrate the hook around a trusted, single-writer demo tool.

    This is not a hardened general-purpose file writer. The caller supplies
    only our private demo file. Recording happens AFTER the write: if it fails,
    the edit has already happened. Never blindly retry the tool in that case.
    """
    before = target.read_text(encoding="utf-8")
    target.write_text(text, encoding="utf-8")
    try:
        response = client.post(
            "/api/events",
            json={
                "agent": "synthetic-file-agent",
                "action": "file.write",
                "target": target.name,
                "summary": "Updated a disposable demo plan",
                "before_text": before,
                "after_text": text,
                "metadata": {"tool": "demo_write", "synthetic": True},
            },
        )
        response.raise_for_status()
        return int(response.json()["id"])
    except Exception as exc:
        raise RuntimeError(
            "File changed, but receipt submission was not confirmed. "
            "Stop and inspect; do not retry the write automatically."
        ) from exc


def main() -> None:
    with TemporaryDirectory(prefix="glassbox-tool-demo-") as root:
        workspace = Path(root) / "workspace"
        workspace.mkdir(mode=0o700)
        target = workspace / "plan.txt"
        original = "Review changes before release.\n"
        target.write_text(original, encoding="utf-8")
        app = create_app(data_dir=Path(root) / "data", workspace=workspace)
        with TestClient(app, base_url="http://127.0.0.1") as client:
            receipt = recorded_demo_write(client, target, "Agent updated the plan.\n")
            print("1. Demo tool changed plan.txt and recorded a receipt.")
            response = client.post(
                f"/api/events/{receipt}/rollback", json={"confirm": True}
            )
            response.raise_for_status()
            require(target.read_text(encoding="utf-8") == original, "Restore failed")
            print("2. Confirmed rollback restored the original file bytes.")

            receipt = recorded_demo_write(client, target, "Second agent edit.\n")
            newer = "A human added a newer change.\n"
            target.write_text(newer, encoding="utf-8")
            response = client.post(
                f"/api/events/{receipt}/rollback", json={"confirm": True}
            )
            require(response.status_code == 409, "Expected a rollback conflict")
            require(target.read_text(encoding="utf-8") == newer, "Newer edit lost")
            print("3. Newer edit detected: rollback refused with HTTP 409.")

            verification = client.get("/api/verify")
            verification.raise_for_status()
            require(verification.json()["valid"] is True, "Receipt chain invalid")
            events = client.get("/api/events")
            events.raise_for_status()
            require(len(events.json()["events"]) == 3, "Expected three receipts")
            print("4. Receipt chain verified; both writes and the rollback remain.")
        print("PASS: disposable demo files removed; no real workspace touched.")


if __name__ == "__main__":
    main()
