#!/usr/bin/env python3
"""Fail-closed validation for generated public launch assets."""

from __future__ import annotations

import binascii
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

EXPECTED_DIMENSIONS = {
    "dashboard.png": ["1280 x 1331"],
    "walkthrough.gif": ["1280 x 1415", "1280 x 1415"],
    "social-card.png": ["1280 x 640"],
}
EXPECTED_FORMATS = {
    "dashboard.png": ["PNG"],
    "walkthrough.gif": ["GIF", "GIF"],
    "social-card.png": ["PNG"],
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"Launch asset validation failed: {message}")


def dimensions(
    path: Path,
    format_string: str,
    inherited_fd: int | None = None,
    asset_name: str | None = None,
) -> list[str]:
    environment = os.environ.copy()
    if asset_name is not None:
        environment["GLASSBOX_ASSET_NAME"] = asset_name
    try:
        output = subprocess.check_output(
            ["identify", "-format", format_string, str(path)],
            stderr=subprocess.PIPE,
            text=True,
            pass_fds=() if inherited_fd is None else (inherited_fd,),
            env=environment,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"could not inspect {asset_name or path.name}: {exc}")
    return output.splitlines()


def read_file_descriptor(file_fd: int) -> bytes:
    chunks: list[bytes] = []
    os.lseek(file_fd, 0, os.SEEK_SET)
    while chunk := os.read(file_fd, 1024 * 1024):
        chunks.append(chunk)
    return b"".join(chunks)


def validate_png_container(payload: bytes) -> None:
    if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("invalid PNG signature")

    position = 8
    first_chunk = True
    seen_palette = False
    seen_image_data = False
    image_data_ended = False
    color_type: int | None = None
    while position < len(payload):
        if position + 12 > len(payload):
            raise ValueError("truncated PNG chunk")
        length = struct.unpack(">I", payload[position : position + 4])[0]
        chunk_end = position + 12 + length
        if chunk_end > len(payload):
            raise ValueError("truncated PNG chunk payload")
        chunk_type = payload[position + 4 : position + 8]
        chunk_data = payload[position + 8 : position + 8 + length]
        recorded_crc = struct.unpack(">I", payload[chunk_end - 4 : chunk_end])[0]
        calculated_crc = binascii.crc32(chunk_type + chunk_data) % (1 << 32)
        if recorded_crc != calculated_crc:
            raise ValueError("PNG chunk CRC mismatch")

        if first_chunk:
            if chunk_type != b"IHDR" or length != 13:
                raise ValueError("PNG does not begin with a valid IHDR chunk")
            width, height, bit_depth, color_type, compression, filtering, interlace = (
                struct.unpack(">IIBBBBB", chunk_data)
            )
            if width == 0 or height == 0:
                raise ValueError("PNG IHDR has zero dimensions")
            if compression != 0 or filtering != 0 or interlace not in (0, 1):
                raise ValueError("PNG IHDR uses unsupported encoding fields")
            valid_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                color_type not in valid_depths
                or bit_depth not in valid_depths[color_type]
            ):
                raise ValueError("PNG IHDR has an invalid color type or bit depth")
            first_chunk = False
            position = chunk_end
            continue

        if chunk_type == b"IHDR":
            raise ValueError("PNG contains a duplicate IHDR chunk")
        if chunk_type and 97 <= chunk_type[0] <= 122:
            raise ValueError(
                f"PNG ancillary metadata chunk {chunk_type!r} is forbidden"
            )
        if chunk_type == b"PLTE":
            if seen_palette or seen_image_data:
                raise ValueError("PNG PLTE is duplicated or appears after IDAT")
            if color_type in (0, 4):
                raise ValueError("PNG PLTE is forbidden for this color type")
            if length == 0 or length % 3 != 0 or length > 768:
                raise ValueError("PNG PLTE has an invalid length")
            seen_palette = True
        elif chunk_type == b"IDAT":
            if image_data_ended:
                raise ValueError("PNG IDAT chunks are not consecutive")
            if color_type == 3 and not seen_palette:
                raise ValueError("indexed PNG IDAT appears before required PLTE")
            seen_image_data = True
        else:
            if seen_image_data:
                image_data_ended = True
            if chunk_type == b"IEND":
                if length != 0 or chunk_end != len(payload):
                    raise ValueError("PNG IEND is malformed or not final")
                if not seen_image_data:
                    raise ValueError("PNG contains no IDAT chunk")
                return
            if chunk_type and 65 <= chunk_type[0] <= 90:
                raise ValueError(f"PNG contains unknown critical chunk {chunk_type!r}")
        position = chunk_end
    raise ValueError("PNG IEND chunk is missing")


def skip_gif_sub_blocks(payload: bytes, position: int) -> int:
    while True:
        if position >= len(payload):
            raise ValueError("truncated GIF sub-block sequence")
        size = payload[position]
        position += 1
        if size == 0:
            return position
        if position + size > len(payload):
            raise ValueError("truncated GIF sub-block")
        position += size


def validate_gif_container(payload: bytes, expected_frames: int) -> None:
    if len(payload) < 13 or payload[:6] not in (b"GIF87a", b"GIF89a"):
        raise ValueError("invalid GIF header")

    logical_width, logical_height = struct.unpack("<HH", payload[6:10])
    if logical_width == 0 or logical_height == 0:
        raise ValueError("GIF logical screen has zero dimensions")

    position = 13
    logical_screen_packed = payload[10]
    if logical_screen_packed & 0x80:
        position += 3 * (1 << ((logical_screen_packed & 0x07) + 1))
    if position > len(payload):
        raise ValueError("truncated GIF global color table")

    frames = 0
    while position < len(payload):
        marker = payload[position]
        if marker == 0x3B:
            if position + 1 != len(payload):
                raise ValueError("GIF trailer is not final")
            if frames != expected_frames:
                raise ValueError(
                    f"GIF contains {frames} image blocks; expected {expected_frames}"
                )
            return
        if marker == 0x21:
            if position + 2 > len(payload):
                raise ValueError("truncated GIF extension")
            label = payload[position + 1]
            extension_start = position + 2
            if label == 0xF9:
                if extension_start + 6 > len(payload):
                    raise ValueError("truncated GIF graphic-control extension")
                if payload[extension_start] != 4 or payload[extension_start + 5] != 0:
                    raise ValueError("malformed GIF graphic-control extension")
                graphic_control_packed = payload[extension_start + 1]
                disposal_method = (graphic_control_packed >> 2) & 0x07
                if graphic_control_packed & 0xE0 or disposal_method > 3:
                    raise ValueError("invalid GIF graphic-control flags")
                position = extension_start + 6
                continue
            if label == 0xFF:
                if extension_start >= len(payload) or payload[extension_start] != 11:
                    raise ValueError("malformed GIF application extension")
                application_end = extension_start + 12
                if application_end > len(payload):
                    raise ValueError("truncated GIF application identifier")
                position = skip_gif_sub_blocks(payload, application_end)
                continue
            if label == 0x01:
                if extension_start >= len(payload) or payload[extension_start] != 12:
                    raise ValueError("malformed GIF plain-text extension")
                plain_text_end = extension_start + 13
                if plain_text_end > len(payload):
                    raise ValueError("truncated GIF plain-text header")
                position = skip_gif_sub_blocks(payload, plain_text_end)
                continue
            if label == 0xFE:
                position = skip_gif_sub_blocks(payload, extension_start)
                continue
            raise ValueError(f"unknown GIF extension label 0x{label:02x}")
        if marker == 0x2C:
            if position + 10 > len(payload):
                raise ValueError("truncated GIF image descriptor")
            left, top, width, height = struct.unpack(
                "<HHHH", payload[position + 1 : position + 9]
            )
            if width == 0 or height == 0:
                raise ValueError("GIF image descriptor has zero dimensions")
            if left + width > logical_width or top + height > logical_height:
                raise ValueError("GIF image descriptor exceeds the logical screen")
            image_packed = payload[position + 9]
            if image_packed & 0x18:
                raise ValueError("GIF image descriptor has reserved flags set")
            position += 10
            if image_packed & 0x80:
                position += 3 * (1 << ((image_packed & 0x07) + 1))
            if position >= len(payload):
                raise ValueError("missing GIF LZW code size")
            lzw_code_size = payload[position]
            if not 2 <= lzw_code_size <= 8:
                raise ValueError("GIF LZW code size is invalid")
            position += 1
            position = skip_gif_sub_blocks(payload, position)
            frames += 1
            continue
        raise ValueError(f"unexpected GIF block marker 0x{marker:02x}")
    raise ValueError("mandatory GIF trailer is missing")


def validate(stage: Path, prohibited_bytes: tuple[bytes, ...]) -> dict[str, str]:
    if not stage.is_dir() or stage.is_symlink():
        fail(f"staging path is not a real directory: {stage}")
    try:
        initial_stage_stat = stage.stat(follow_symlinks=False)
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        fail(f"could not snapshot staging directory: {exc}")

    expected = set(EXPECTED_DIMENSIONS)
    actual = set(os.listdir(stage_fd))
    if actual != expected:
        fail(
            f"staged asset set mismatch: actual={sorted(actual)!r}, "
            f"expected={sorted(expected)!r}"
        )

    manifest: dict[str, str] = {}
    for name, expected_dimensions in EXPECTED_DIMENSIONS.items():
        path = stage / name
        if path.is_symlink() or not path.is_file():
            fail(f"{name} is not a regular file")

        try:
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=stage_fd)
            initial_stat = os.fstat(file_fd)
            if not stat.S_ISREG(initial_stat.st_mode):
                fail(f"{name} is not a regular file")
            payload = read_file_descriptor(file_fd)
            after_read_stat = os.fstat(file_fd)
        except OSError as exc:
            fail(f"could not snapshot {name}: {exc}")
        fd_path = Path(f"/proc/self/fd/{file_fd}")
        if (
            (initial_stat.st_dev, initial_stat.st_ino)
            != (after_read_stat.st_dev, after_read_stat.st_ino)
            or initial_stat.st_size != after_read_stat.st_size
            or initial_stat.st_ctime_ns != after_read_stat.st_ctime_ns
            or initial_stat.st_mtime_ns != after_read_stat.st_mtime_ns
        ):
            fail(f"{name} changed while validation began")

        actual_formats = dimensions(fd_path, "%m\n", file_fd, name)
        expected_formats = EXPECTED_FORMATS[name]
        if actual_formats != expected_formats:
            fail(
                f"{name} encoded format mismatch: "
                f"actual={actual_formats!r}, expected={expected_formats!r}"
            )

        actual_dimensions = dimensions(fd_path, "%W x %H\n", file_fd, name)
        if actual_dimensions != expected_dimensions:
            fail(
                f"{name} dimensions/frames mismatch: "
                f"actual={actual_dimensions!r}, expected={expected_dimensions!r}"
            )
        actual_pixels = dimensions(fd_path, "%w x %h\n", file_fd, name)
        if path.suffix == ".png":
            if actual_pixels != expected_dimensions:
                fail(
                    f"{name} pixel dimensions mismatch: "
                    f"actual={actual_pixels!r}, expected={expected_dimensions!r}"
                )
        elif (
            len(actual_pixels) != len(expected_dimensions)
            or actual_pixels[0] != expected_dimensions[0]
        ):
            fail(
                f"{name} first-frame pixel dimensions/frame count mismatch: "
                f"actual={actual_pixels!r}, expected first={expected_dimensions[0]!r} "
                f"with {len(expected_dimensions)} frames"
            )

        try:
            if path.suffix == ".png":
                validate_png_container(payload)
            else:
                validate_gif_container(payload, len(expected_dimensions))
        except ValueError as exc:
            container = "PNG" if path.suffix == ".png" else "GIF"
            fail(f"{name} malformed {container} container: {exc}")

        for prohibited in prohibited_bytes:
            if prohibited in payload:
                fail(f"{name} contains prohibited temporary or run-specific data")

        decoded_metadata = "\n".join(dimensions(fd_path, "%[*]", file_fd, name))
        prohibited_metadata = tuple(
            marker.decode("ascii") for marker in prohibited_bytes
        )
        for metadata_marker in prohibited_metadata:
            if metadata_marker in decoded_metadata:
                fail(f"{name} decoded metadata contains prohibited marker")

        try:
            final_payload = read_file_descriptor(file_fd)
            final_stat = os.fstat(file_fd)
        except OSError as exc:
            fail(f"could not recheck {name}: {exc}")
        if (
            final_payload != payload
            or (initial_stat.st_dev, initial_stat.st_ino)
            != (final_stat.st_dev, final_stat.st_ino)
            or initial_stat.st_size != final_stat.st_size
            or initial_stat.st_ctime_ns != final_stat.st_ctime_ns
            or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
        ):
            fail(f"{name} changed during validation")
        manifest[name] = hashlib.sha256(payload).hexdigest()
        os.close(file_fd)

    try:
        final_stage_stat = os.fstat(stage_fd)
        final_names = set(os.listdir(stage_fd))
    except OSError as exc:
        fail(f"could not recheck staging directory: {exc}")
    if final_names != expected or (
        initial_stage_stat.st_dev,
        initial_stage_stat.st_ino,
    ) != (final_stage_stat.st_dev, final_stage_stat.st_ino):
        fail("staging directory changed during validation")

    os.close(stage_fd)
    return manifest


def main() -> None:
    if len(sys.argv) < 3:
        fail(
            "usage: validate-launch-assets.py STAGING_DIRECTORY NONCE "
            "[RUN_SPECIFIC_PATH ...]"
        )
    try:
        nonce = sys.argv[2].encode("ascii")
    except UnicodeEncodeError as exc:
        fail(f"nonce is not ASCII: {exc}")
    if not nonce:
        fail("nonce must not be empty")
    stage = Path(sys.argv[1])
    path_markers = tuple(
        marker.encode("utf-8") for marker in (str(stage), *sys.argv[3:]) if marker
    )
    manifest = validate(stage, (nonce, b"/home/", b"/tmp/", *path_markers))
    print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
