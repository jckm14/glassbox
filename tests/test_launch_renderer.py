from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "scripts" / "render-launch-assets.sh"
SERVER_HELPER = ROOT / "scripts" / "render-launch-server.py"
ASSET_VALIDATOR = ROOT / "scripts" / "validate-launch-assets.py"
ASSET_PUBLISHER = ROOT / "scripts" / "publish-launch-assets.py"
CHECKLIST = ROOT / "docs" / "launch" / "LAUNCH-CHECKLIST.md"
LAUNCH_README = ROOT / "docs" / "launch" / "README.md"
MINIMAL_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)
MINIMAL_GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")


def write_minimal_assets(stage: Path) -> None:
    (stage / "dashboard.png").write_bytes(MINIMAL_PNG)
    (stage / "social-card.png").write_bytes(MINIMAL_PNG)
    (stage / "walkthrough.gif").write_bytes(MINIMAL_GIF)


def load_asset_publisher() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "glassbox_asset_publisher", ASSET_PUBLISHER
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_asset_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "glassbox_asset_validator", ASSET_VALIDATOR
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def publisher_command(stage: Path, destination: Path) -> list[str]:
    parent = stage.parent.stat()
    manifest = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in stage.iterdir()
    }
    return [
        sys.executable,
        str(ASSET_PUBLISHER),
        str(stage),
        str(destination),
        str(parent.st_dev),
        str(parent.st_ino),
        json.dumps(manifest, sort_keys=True, separators=(",", ":")),
    ]


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    checksum = binascii.crc32(chunk_type + data) % (1 << 32)
    return (
        struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", checksum)
    )


def png_with_nonconsecutive_idat(payload: bytes) -> bytes:
    output = bytearray(payload[:8])
    position = 8
    while position < len(payload):
        length = struct.unpack(">I", payload[position : position + 4])[0]
        chunk_end = position + 12 + length
        chunk_type = payload[position + 4 : position + 8]
        chunk_data = payload[position + 8 : position + 8 + length]
        if chunk_type == b"IDAT":
            split = max(1, len(chunk_data) // 2)
            output.extend(png_chunk(b"IDAT", chunk_data[:split]))
            output.extend(png_chunk(b"tEXt", b"Comment\x00separator"))
            output.extend(png_chunk(b"IDAT", chunk_data[split:]))
        else:
            output.extend(payload[position:chunk_end])
        position = chunk_end
    return bytes(output)


def gif_with_malformed_graphic_control(payload: bytes) -> bytes:
    position = 13
    if payload[10] & 0x80:
        position += 3 * (1 << ((payload[10] & 0x07) + 1))
    return payload[:position] + b"\x21\xf9\x03\x00\x00\x00\x00" + payload[position:]


def gif_with_reserved_image_flag(payload: bytes) -> bytes:
    position = 13
    if payload[10] & 0x80:
        position += 3 * (1 << ((payload[10] & 0x07) + 1))
    if payload[position] != 0x2C:
        raise ValueError("minimal GIF fixture does not begin with an image descriptor")
    result = bytearray(payload)
    result[position + 9] |= 0x08
    return bytes(result)


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
    publisher = ASSET_PUBLISHER.read_text(encoding="utf-8")

    assert "STAGING_DIR=" in renderer
    assert renderer.index("trap cleanup EXIT") < renderer.index("DEMO_DIR=$(mktemp")
    assert renderer.index("ASSET_PARENT_DEVICE ASSET_PARENT_INODE") < renderer.index(
        "DEMO_DIR=$(mktemp"
    )
    assert "RENAME_EXCHANGE" in publisher
    assert "RENAME_NOREPLACE" in publisher
    assert "validate staged launch assets" in renderer
    assert "publish-launch-assets.py" in renderer
    assert "--cleanup-staging" in renderer
    publication_call = renderer.rindex("python3 scripts/publish-launch-assets.py")
    assert renderer.index("validate-launch-assets.py") < publication_call
    assert (
        renderer.index('PUBLISH_STAGING_DIR=$STAGING_DIR\nSTAGING_DIR=""')
        < publication_call
    )
    assert publication_call < renderer.index("Wrote %s, %s, and %s")


def test_runtime_validation_does_not_use_python_assertions() -> None:
    renderer = RENDERER.read_text(encoding="utf-8")
    validator = ASSET_VALIDATOR.read_text(encoding="utf-8")
    publisher = ASSET_PUBLISHER.read_text(encoding="utf-8")

    for runtime_source in (renderer, validator, publisher):
        assert re.search(r"^\s*assert\b", runtime_source, flags=re.MULTILINE) is None
    assert "validate-launch-assets.py" in renderer


def test_asset_validation_remains_active_with_optimized_python(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    write_minimal_assets(stage)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    identify = fake_bin / "identify"
    identify.write_text(
        f"""#!{sys.executable}
import os
import sys
name = os.environ["GLASSBOX_ASSET_NAME"]
format_string = sys.argv[sys.argv.index("-format") + 1]
if format_string == "%m\\n":
    print("GIF" if name == "walkthrough.gif" else "PNG")
    if name == "walkthrough.gif":
        print("GIF")
elif name == "dashboard.png":
    print("1280 x 1")
elif name == "social-card.png":
    print("1280 x 640")
else:
    print("1280 x 1415")
    print("1280 x 1415")
""",
        encoding="utf-8",
    )
    identify.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["PYTHONOPTIMIZE"] = "2"
    result = subprocess.run(
        [sys.executable, str(ASSET_VALIDATOR), str(stage), "a" * 64],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert "dashboard.png dimensions" in result.stderr


def test_validator_rejects_small_png_with_spoofed_canvas(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    write_minimal_assets(stage)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    identify = fake_bin / "identify"
    identify.write_text(
        f"""#!{sys.executable}
import os
import sys
name = os.environ["GLASSBOX_ASSET_NAME"]
format_string = sys.argv[sys.argv.index("-format") + 1]
if format_string == "%m\\n":
    print("GIF" if name == "walkthrough.gif" else "PNG")
    if name == "walkthrough.gif":
        print("GIF")
elif name == "dashboard.png":
    print("1280 x 1331" if "%W" in format_string else "1 x 1")
elif name == "social-card.png":
    print("1280 x 640")
else:
    print("1280 x 1415")
    print("1280 x 1415")
""",
        encoding="utf-8",
    )
    identify.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["PYTHONOPTIMIZE"] = "2"
    result = subprocess.run(
        [sys.executable, str(ASSET_VALIDATOR), str(stage), "a" * 64],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert "dashboard.png pixel dimensions" in result.stderr


def test_validator_rejects_tiny_gif_frames_with_spoofed_canvas(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    write_minimal_assets(stage)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    identify = fake_bin / "identify"
    identify.write_text(
        f"""#!{sys.executable}
import os
import sys
name = os.environ["GLASSBOX_ASSET_NAME"]
format_string = sys.argv[sys.argv.index("-format") + 1]
if format_string == "%m\\n":
    print("GIF" if name == "walkthrough.gif" else "PNG")
    if name == "walkthrough.gif":
        print("GIF")
elif name == "dashboard.png":
    print("1280 x 1331")
elif name == "social-card.png":
    print("1280 x 640")
elif "%W" in format_string:
    print("1280 x 1415")
    print("1280 x 1415")
else:
    print("1 x 1")
    print("1 x 1")
""",
        encoding="utf-8",
    )
    identify.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["PYTHONOPTIMIZE"] = "2"
    result = subprocess.run(
        [sys.executable, str(ASSET_VALIDATOR), str(stage), "a" * 64],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert "walkthrough.gif first-frame pixel dimensions" in result.stderr


def test_validator_rejects_mislabeled_image_formats(tmp_path: Path) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    write_minimal_assets(stage)

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    identify = fake_bin / "identify"
    identify.write_text(
        f"""#!{sys.executable}
import os
import sys
name = os.environ["GLASSBOX_ASSET_NAME"]
format_string = sys.argv[sys.argv.index("-format") + 1]
if format_string == "%m\\n":
    print("TIFF" if name == "walkthrough.gif" else "JPEG")
elif name == "dashboard.png":
    print("1280 x 1331")
elif name == "social-card.png":
    print("1280 x 640")
else:
    print("1280 x 1415")
    print("1280 x 1415")
""",
        encoding="utf-8",
    )
    identify.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["PYTHONOPTIMIZE"] = "2"
    result = subprocess.run(
        [sys.executable, str(ASSET_VALIDATOR), str(stage), "a" * 64],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert "dashboard.png encoded format" in result.stderr


def test_validator_rejects_decoded_nonce_metadata_under_optimization(
    tmp_path: Path,
) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    write_minimal_assets(stage)

    nonce = "a" * 64
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    identify = fake_bin / "identify"
    identify.write_text(
        f"""#!{sys.executable}
import os
import sys
name = os.environ["GLASSBOX_ASSET_NAME"]
format_string = sys.argv[sys.argv.index("-format") + 1]
if format_string == "%m\\n":
    print("GIF" if name == "walkthrough.gif" else "PNG")
    if name == "walkthrough.gif":
        print("GIF")
elif format_string == "%[*]":
    print("comment=private nonce {nonce}" if name == "dashboard.png" else "")
elif name == "dashboard.png":
    print("1280 x 1331")
elif name == "social-card.png":
    print("1280 x 640")
else:
    print("1280 x 1415")
    print("1280 x 1415")
""",
        encoding="utf-8",
    )
    identify.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["PYTHONOPTIMIZE"] = "2"
    result = subprocess.run(
        [sys.executable, str(ASSET_VALIDATOR), str(stage), nonce],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert "dashboard.png decoded metadata contains prohibited marker" in result.stderr

    private_path = "/root/glassbox-launch-assets.SECRET"
    identify.write_text(
        identify.read_text(encoding="utf-8").replace(
            f"private nonce {nonce}", private_path
        ),
        encoding="utf-8",
    )
    path_result = subprocess.run(
        [sys.executable, str(ASSET_VALIDATOR), str(stage), nonce, private_path],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert path_result.returncode != 0
    assert (
        "dashboard.png decoded metadata contains prohibited marker"
        in path_result.stderr
    )


def test_validator_rejects_gif_without_mandatory_trailer_under_optimization(
    tmp_path: Path,
) -> None:
    stage = tmp_path / "stage"
    stage.mkdir()
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
    )
    gif = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
    (stage / "dashboard.png").write_bytes(png)
    (stage / "social-card.png").write_bytes(png)
    (stage / "walkthrough.gif").write_bytes(gif[:-1])

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    identify = fake_bin / "identify"
    identify.write_text(
        f"""#!{sys.executable}
import os
import sys
name = os.environ["GLASSBOX_ASSET_NAME"]
format_string = sys.argv[sys.argv.index("-format") + 1]
if format_string == "%m\\n":
    print("GIF" if name == "walkthrough.gif" else "PNG")
    if name == "walkthrough.gif":
        print("GIF")
elif format_string == "%[*]":
    print("")
elif name == "dashboard.png":
    print("1280 x 1331")
elif name == "social-card.png":
    print("1280 x 640")
else:
    print("1280 x 1415")
    print("1280 x 1415")
""",
        encoding="utf-8",
    )
    identify.chmod(0o755)

    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
    environment["PYTHONOPTIMIZE"] = "2"
    result = subprocess.run(
        [sys.executable, str(ASSET_VALIDATOR), str(stage), "a" * 64],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert "walkthrough.gif malformed GIF container" in result.stderr


def test_validator_rejects_png_ancillary_metadata_chunks() -> None:
    validator = load_asset_validator()
    malformed = png_with_nonconsecutive_idat(MINIMAL_PNG)

    with pytest.raises(ValueError, match="ancillary metadata chunk"):
        validator.validate_png_container(malformed)


def test_validator_rejects_malformed_gif_graphic_control_extension() -> None:
    validator = load_asset_validator()
    malformed = gif_with_malformed_graphic_control(MINIMAL_GIF)

    with pytest.raises(ValueError, match="graphic-control extension"):
        validator.validate_gif_container(malformed, 1)


def test_validator_rejects_reserved_gif_image_flags() -> None:
    validator = load_asset_validator()
    malformed = gif_with_reserved_image_flag(MINIMAL_GIF)

    with pytest.raises(ValueError, match="reserved flags"):
        validator.validate_gif_container(malformed, 1)


def test_validator_uses_pinned_file_during_restored_entry_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    validator = load_asset_validator()
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "dashboard.png").write_bytes(MINIMAL_PNG)
    (stage / "social-card.png").write_bytes(MINIMAL_PNG)
    (stage / "walkthrough.gif").write_bytes(MINIMAL_GIF)
    substituted = False
    inspected_payloads: list[bytes] = []

    def fake_dimensions(
        path: Path,
        format_string: str,
        inherited_fd: int | None = None,
        asset_name: str | None = None,
    ) -> list[str]:
        nonlocal substituted
        assert inherited_fd is not None
        assert asset_name is not None
        if not substituted:
            substituted = True
            saved = stage / "dashboard.saved"
            (stage / "dashboard.png").rename(saved)
            (stage / "dashboard.png").write_bytes(b"UNVALIDATED-PRIVATE")
            inspected_payloads.append(path.read_bytes())
            (stage / "dashboard.png").unlink()
            saved.rename(stage / "dashboard.png")
        if format_string == "%m\n":
            return ["GIF", "GIF"] if asset_name == "walkthrough.gif" else ["PNG"]
        if format_string in {"%W x %H\n", "%w x %h\n"}:
            return validator.EXPECTED_DIMENSIONS[asset_name]
        return []

    monkeypatch.setattr(validator, "dimensions", fake_dimensions)
    monkeypatch.setitem(
        validator.EXPECTED_DIMENSIONS,
        "social-card.png",
        validator.EXPECTED_DIMENSIONS["dashboard.png"],
    )
    monkeypatch.setattr(validator, "validate_png_container", lambda _payload: None)
    monkeypatch.setattr(
        validator, "validate_gif_container", lambda _payload, _frames: None
    )

    try:
        manifest = validator.validate(stage, (b"not-present",))
    except SystemExit as exc:
        assert "dashboard.png changed during validation" in str(exc)
    else:
        assert manifest["dashboard.png"] == hashlib.sha256(MINIMAL_PNG).hexdigest()
    assert inspected_payloads == [MINIMAL_PNG]


def test_publisher_refuses_symlink_destination_without_touching_target(
    tmp_path: Path,
) -> None:
    stage = tmp_path / ".launch-stage.test"
    stage.mkdir()
    (stage / "dashboard.png").write_bytes(b"new")

    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "valuable-launch"
    target.mkdir()
    valuable = target / "valuable.txt"
    valuable.write_text("keep", encoding="utf-8")

    destination = tmp_path / "launch"
    destination.symlink_to(target, target_is_directory=True)
    result = subprocess.run(
        publisher_command(stage, destination),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert "symbolic-link destination" in result.stderr
    assert destination.is_symlink()
    assert valuable.read_text(encoding="utf-8") == "keep"
    assert (stage / "dashboard.png").read_bytes() == b"new"


def test_publisher_exchanges_validated_directory_as_one_set(tmp_path: Path) -> None:
    stage = tmp_path / ".launch-stage.test"
    stage.mkdir()
    (stage / "new.txt").write_text("new", encoding="utf-8")
    stage_inode = stage.stat().st_ino

    destination = tmp_path / "launch"
    destination.mkdir()
    (destination / "old.txt").write_text("old", encoding="utf-8")

    result = subprocess.run(
        publisher_command(stage, destination),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert destination.stat().st_ino == stage_inode
    assert (destination / "new.txt").read_text(encoding="utf-8") == "new"
    assert not stage.exists()


def test_publisher_first_publish_does_not_replace_concurrent_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher = load_asset_publisher()
    stage = tmp_path / ".launch-stage.test"
    stage.mkdir()
    (stage / "validated.txt").write_text("validated", encoding="utf-8")
    destination = tmp_path / "launch"
    real_first_publish = publisher.atomic_first_publish
    destination_created = False

    def first_publish_after_destination_creation(
        parent_fd: int, source_name: str, destination_name: str
    ) -> None:
        nonlocal destination_created
        if not destination_created:
            destination_created = True
            os.mkdir(destination_name, dir_fd=parent_fd)
        real_first_publish(parent_fd, source_name, destination_name)

    monkeypatch.setattr(
        publisher, "atomic_first_publish", first_publish_after_destination_creation
    )
    with pytest.raises(SystemExit, match="atomic first publication failed"):
        publisher.publish(
            stage,
            destination,
            publisher.identity(tmp_path.stat()),
            publisher.path_manifest(stage),
        )

    assert (stage / "validated.txt").read_text(encoding="utf-8") == "validated"
    assert destination.is_dir()
    assert not list(destination.iterdir())


def test_publisher_rejects_parent_replacement_before_commit(tmp_path: Path) -> None:
    publisher = load_asset_publisher()
    parent = tmp_path / "assets"
    parent.mkdir()
    expected_parent_identity = publisher.identity(parent.stat())
    stage = parent / ".launch-stage.test"
    stage.mkdir()
    (stage / "validated.txt").write_text("validated", encoding="utf-8")
    destination = parent / "launch"
    destination.mkdir()
    (destination / "old.txt").write_text("old", encoding="utf-8")

    expected_manifest = publisher.path_manifest(stage)
    original_parent = tmp_path / "assets.original"
    parent.rename(original_parent)
    parent.mkdir()
    forged_stage = parent / stage.name
    forged_stage.mkdir()
    (forged_stage / "forged.txt").write_text("forged", encoding="utf-8")
    forged_destination = parent / destination.name
    forged_destination.mkdir()
    valuable = forged_destination / "valuable.txt"
    valuable.write_text("keep", encoding="utf-8")

    with pytest.raises(SystemExit, match="parent identity changed"):
        publisher.publish(
            stage, destination, expected_parent_identity, expected_manifest
        )

    assert valuable.read_text(encoding="utf-8") == "keep"
    assert (forged_stage / "forged.txt").read_text(encoding="utf-8") == "forged"
    assert (original_parent / stage.name / "validated.txt").read_text(
        encoding="utf-8"
    ) == "validated"
    assert (original_parent / destination.name / "old.txt").read_text(
        encoding="utf-8"
    ) == "old"


def test_publisher_rejects_staging_content_mutation_after_validation(
    tmp_path: Path,
) -> None:
    publisher = load_asset_publisher()
    stage = tmp_path / ".launch-stage.test"
    stage.mkdir()
    asset = stage / "validated.txt"
    asset.write_text("validated", encoding="utf-8")
    expected_manifest = publisher.path_manifest(stage)
    destination = tmp_path / "launch"
    destination.mkdir()
    (destination / "old.txt").write_text("old", encoding="utf-8")

    asset.write_text("UNVALIDATED-PRIVATE", encoding="utf-8")
    with pytest.raises(SystemExit, match="changed after validation"):
        publisher.publish(
            stage,
            destination,
            publisher.identity(tmp_path.stat()),
            expected_manifest,
        )

    assert (destination / "old.txt").read_text(encoding="utf-8") == "old"
    assert asset.read_text(encoding="utf-8") == "UNVALIDATED-PRIVATE"


def test_publisher_quarantines_first_publish_source_substitution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher = load_asset_publisher()
    stage = tmp_path / ".launch-stage.test"
    stage.mkdir()
    (stage / "validated.txt").write_text("validated", encoding="utf-8")
    expected_manifest = publisher.path_manifest(stage)
    destination = tmp_path / "launch"
    validated_saved = tmp_path / "validated.saved"
    substitute = tmp_path / "substitute"
    substitute.mkdir()
    (substitute / "unvalidated.txt").write_text("private", encoding="utf-8")
    real_first_publish = publisher.atomic_first_publish

    def first_publish_after_source_substitution(
        parent_fd: int, source_name: str, destination_name: str
    ) -> None:
        os.rename(
            source_name,
            validated_saved.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.rename(
            substitute.name,
            source_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        real_first_publish(parent_fd, source_name, destination_name)

    monkeypatch.setattr(
        publisher, "atomic_first_publish", first_publish_after_source_substitution
    )
    with pytest.raises(SystemExit, match="removed from the public path"):
        publisher.publish(
            stage,
            destination,
            publisher.identity(tmp_path.stat()),
            expected_manifest,
        )

    assert not destination.exists()
    recovery = next(tmp_path.glob(".launch-recovery.*"))
    assert (recovery / "unvalidated.txt").read_text(encoding="utf-8") == "private"
    assert (validated_saved / "validated.txt").read_text(
        encoding="utf-8"
    ) == "validated"


def test_safe_staging_cleanup_rejects_parent_replacement(tmp_path: Path) -> None:
    publisher = load_asset_publisher()
    parent = tmp_path / "assets"
    parent.mkdir()
    stage = parent / ".launch-stage.test"
    stage.mkdir()
    (stage / "generated.txt").write_text("generated", encoding="utf-8")
    expected_parent = publisher.identity(parent.stat())
    expected_stage = publisher.identity(stage.stat())

    original_parent = tmp_path / "assets.original"
    parent.rename(original_parent)
    parent.mkdir()
    forged_stage = parent / stage.name
    forged_stage.mkdir()
    valuable = forged_stage / "valuable.txt"
    valuable.write_text("keep", encoding="utf-8")

    with pytest.raises(SystemExit, match="cleanup parent identity changed"):
        publisher.cleanup_staging(stage, expected_parent, expected_stage)

    assert valuable.read_text(encoding="utf-8") == "keep"
    assert (original_parent / stage.name / "generated.txt").read_text(
        encoding="utf-8"
    ) == "generated"


def test_publisher_reverses_staging_entry_substitution_without_data_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher = load_asset_publisher()
    stage = tmp_path / ".launch-stage.test"
    stage.mkdir()
    (stage / "validated.txt").write_text("validated", encoding="utf-8")
    destination = tmp_path / "launch"
    destination.mkdir()
    (destination / "old.txt").write_text("old", encoding="utf-8")
    replacement = tmp_path / "replacement"
    replacement.mkdir()
    (replacement / "replacement.txt").write_text("replacement", encoding="utf-8")
    validated_saved = tmp_path / "validated.saved"
    real_exchange = publisher.atomic_exchange
    source_substituted = False

    def exchange_after_source_substitution(
        parent_fd: int, source_name: str, destination_name: str
    ) -> None:
        nonlocal source_substituted
        if not source_substituted:
            source_substituted = True
            os.rename(
                source_name,
                validated_saved.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.rename(
                replacement.name,
                source_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        real_exchange(parent_fd, source_name, destination_name)

    monkeypatch.setattr(
        publisher, "atomic_exchange", exchange_after_source_substitution
    )
    with pytest.raises(SystemExit, match="removed from the public path"):
        publisher.publish(
            stage,
            destination,
            publisher.identity(tmp_path.stat()),
            publisher.path_manifest(stage),
        )

    assert not destination.exists()
    assert (stage / "old.txt").read_text(encoding="utf-8") == "old"
    recovery = next(tmp_path.glob(".launch-recovery.*"))
    assert (recovery / "replacement.txt").read_text(encoding="utf-8") == "replacement"
    assert (validated_saved / "validated.txt").read_text(
        encoding="utf-8"
    ) == "validated"


def test_publisher_reverses_concurrent_destination_without_data_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    publisher = load_asset_publisher()
    stage = tmp_path / ".launch-stage.test"
    stage.mkdir()
    (stage / "validated.txt").write_text("validated", encoding="utf-8")
    destination = tmp_path / "launch"
    destination.mkdir()
    (destination / "old.txt").write_text("old", encoding="utf-8")
    concurrent = tmp_path / "concurrent"
    concurrent.mkdir()
    (concurrent / "concurrent.txt").write_text("concurrent", encoding="utf-8")
    old_saved = tmp_path / "old.saved"
    real_exchange = publisher.atomic_exchange
    destination_substituted = False

    def exchange_after_destination_substitution(
        parent_fd: int, source_name: str, destination_name: str
    ) -> None:
        nonlocal destination_substituted
        if not destination_substituted:
            destination_substituted = True
            os.rename(
                destination_name,
                old_saved.name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            os.rename(
                concurrent.name,
                destination_name,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
        real_exchange(parent_fd, source_name, destination_name)

    monkeypatch.setattr(
        publisher, "atomic_exchange", exchange_after_destination_substitution
    )
    with pytest.raises(SystemExit, match="validated publication retained"):
        publisher.publish(
            stage,
            destination,
            publisher.identity(tmp_path.stat()),
            publisher.path_manifest(stage),
        )

    assert (destination / "validated.txt").read_text(encoding="utf-8") == "validated"
    assert (stage / "concurrent.txt").read_text(encoding="utf-8") == "concurrent"
    assert (old_saved / "old.txt").read_text(encoding="utf-8") == "old"


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
