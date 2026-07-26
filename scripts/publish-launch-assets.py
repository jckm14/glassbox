#!/usr/bin/env python3
"""Publish a validated launch-asset directory without losing displaced content."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import NoReturn

RENAME_NOREPLACE = 1
RENAME_EXCHANGE = 2


def fail(message: str) -> NoReturn:
    raise SystemExit(f"Launch asset publication failed: {message}")


def absolute_without_resolving(path: str) -> Path:
    return Path(os.path.abspath(path))


def identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def entry_stat(parent_fd: int, name: str) -> os.stat_result:
    return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)


def rename_with_flags(
    parent_fd: int,
    source_name: str,
    destination_name: str,
    flags: int,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError:
        fail("renameat2 is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd,
        os.fsencode(source_name),
        parent_fd,
        os.fsencode(destination_name),
        flags,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(
            error,
            os.strerror(error),
            f"{source_name} <-> {destination_name}",
        )


def atomic_exchange(parent_fd: int, source_name: str, destination_name: str) -> None:
    rename_with_flags(parent_fd, source_name, destination_name, RENAME_EXCHANGE)


def atomic_first_publish(
    parent_fd: int, source_name: str, destination_name: str
) -> None:
    rename_with_flags(parent_fd, source_name, destination_name, RENAME_NOREPLACE)


def remove_directory_tree(
    parent_fd: int,
    name: str,
    expected_identity: tuple[int, int],
) -> None:
    current = entry_stat(parent_fd, name)
    if identity(current) != expected_identity or not stat.S_ISDIR(current.st_mode):
        fail("refusing to clean a displaced directory whose identity changed")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    child_fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        if identity(os.fstat(child_fd)) != expected_identity:
            fail("displaced directory changed while it was opened for cleanup")
        with os.scandir(child_fd) as entries:
            for entry in entries:
                child_stat = entry_stat(child_fd, entry.name)
                if stat.S_ISDIR(child_stat.st_mode):
                    remove_directory_tree(child_fd, entry.name, identity(child_stat))
                else:
                    os.unlink(entry.name, dir_fd=child_fd)
    finally:
        os.close(child_fd)

    current = entry_stat(parent_fd, name)
    if identity(current) != expected_identity:
        fail("displaced directory changed before final cleanup")
    os.rmdir(name, dir_fd=parent_fd)


def directory_manifest(
    parent_fd: int, directory_name: str, expected_names: set[str]
) -> dict[str, str]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory_fd = os.open(directory_name, flags, dir_fd=parent_fd)
    try:
        actual_names = set(os.listdir(directory_fd))
        if actual_names != expected_names:
            fail(
                f"publication asset set changed: actual={sorted(actual_names)!r}, "
                f"expected={sorted(expected_names)!r}"
            )
        manifest: dict[str, str] = {}
        for name in sorted(expected_names):
            file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
            try:
                before = os.fstat(file_fd)
                if not stat.S_ISREG(before.st_mode):
                    fail(f"publication asset is not a regular file: {name}")
                digest = hashlib.sha256()
                while chunk := os.read(file_fd, 1024 * 1024):
                    digest.update(chunk)
                after = os.fstat(file_fd)
                if (
                    identity(before) != identity(after)
                    or before.st_size != after.st_size
                    or before.st_ctime_ns != after.st_ctime_ns
                    or before.st_mtime_ns != after.st_mtime_ns
                ):
                    fail(f"publication asset changed while hashing: {name}")
                manifest[name] = digest.hexdigest()
            finally:
                os.close(file_fd)
        return manifest
    finally:
        os.close(directory_fd)


def path_manifest(directory: Path) -> dict[str, str]:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent_fd = os.open(directory.parent, flags)
    try:
        names = set(os.listdir(directory))
        return directory_manifest(parent_fd, directory.name, names)
    finally:
        os.close(parent_fd)


def manifest_matches(
    parent_fd: int, directory_name: str, expected_manifest: dict[str, str]
) -> bool:
    try:
        return (
            directory_manifest(parent_fd, directory_name, set(expected_manifest))
            == expected_manifest
        )
    except (OSError, SystemExit):
        return False


def reverse_uncertain_exchange(
    parent_fd: int,
    source_name: str,
    destination_name: str,
    source_identity: tuple[int, int],
    destination_identity: tuple[int, int],
) -> NoReturn:
    try:
        current_source = identity(entry_stat(parent_fd, source_name))
        current_destination = identity(entry_stat(parent_fd, destination_name))
    except OSError as exc:
        fail(
            f"publication identity became unknowable; recovery entries retained: {exc}"
        )

    if (
        current_destination == source_identity
        and current_source == destination_identity
    ):
        try:
            atomic_exchange(parent_fd, source_name, destination_name)
        except OSError as exc:
            fail(f"guarded reverse exchange failed; recovery entries retained: {exc}")
        fail("exchange-boundary identity conflict; publication was reversed")
    if current_destination != source_identity:
        quarantine_first_publication(parent_fd, destination_name)
    fail("exchange-boundary identity conflict; validated publication retained")


def quarantine_first_publication(parent_fd: int, destination_name: str) -> NoReturn:
    for _ in range(8):
        recovery_name = f".launch-recovery.{secrets.token_hex(16)}"
        try:
            rename_with_flags(
                parent_fd, destination_name, recovery_name, RENAME_NOREPLACE
            )
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                continue
            if exc.errno == errno.ENOENT:
                fail("invalid first publication disappeared before quarantine")
            fail(f"could not quarantine invalid first publication: {exc}")
        try:
            entry_stat(parent_fd, destination_name)
        except FileNotFoundError:
            fail(
                "invalid first publication was removed from the public path; "
                f"recovery retained as {recovery_name}"
            )
        fail(
            "public destination was recreated during quarantine; "
            f"recovery retained as {recovery_name}"
        )
    fail("could not allocate a recovery name for invalid first publication")


def publish(
    source: Path,
    destination: Path,
    expected_parent_identity: tuple[int, int],
    expected_manifest: dict[str, str],
) -> None:
    if source == destination:
        fail("staging and destination paths must be different")
    if source.parent != destination.parent:
        fail("staging and destination paths do not share one lexical parent")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        parent_fd = os.open(source.parent, flags)
    except OSError as exc:
        fail(f"could not pin publication parent: {exc}")

    try:
        if identity(os.fstat(parent_fd)) != expected_parent_identity:
            fail("publication parent identity changed before commit")
        try:
            source_stat = entry_stat(parent_fd, source.name)
        except OSError as exc:
            fail(f"could not inspect staging directory: {exc}")
        if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISDIR(source_stat.st_mode):
            fail("staging path is not a real directory")
        if (
            directory_manifest(parent_fd, source.name, set(expected_manifest))
            != expected_manifest
        ):
            fail("staging contents changed after validation")

        try:
            destination_stat = entry_stat(parent_fd, destination.name)
        except FileNotFoundError:
            destination_stat = None
        except OSError as exc:
            fail(f"could not inspect destination: {exc}")

        if destination_stat is not None:
            if stat.S_ISLNK(destination_stat.st_mode):
                fail("refusing symbolic-link destination")
            if not stat.S_ISDIR(destination_stat.st_mode):
                fail("destination exists but is not a directory")

        source_identity = identity(source_stat)
        if destination_stat is None:
            try:
                atomic_first_publish(parent_fd, source.name, destination.name)
            except OSError as exc:
                fail(f"atomic first publication failed: {exc}")
            try:
                published_identity = identity(entry_stat(parent_fd, destination.name))
            except OSError as exc:
                fail(f"could not verify first publication: {exc}")
            if published_identity != source_identity:
                quarantine_first_publication(parent_fd, destination.name)
            if not manifest_matches(parent_fd, destination.name, expected_manifest):
                quarantine_first_publication(parent_fd, destination.name)
            return

        destination_identity = identity(destination_stat)
        try:
            atomic_exchange(parent_fd, source.name, destination.name)
        except OSError as exc:
            fail(f"atomic directory publication failed: {exc}")

        try:
            published_identity = identity(entry_stat(parent_fd, destination.name))
            displaced_identity = identity(entry_stat(parent_fd, source.name))
        except OSError:
            reverse_uncertain_exchange(
                parent_fd,
                source.name,
                destination.name,
                source_identity,
                destination_identity,
            )

        if (
            published_identity != source_identity
            or displaced_identity != destination_identity
        ):
            reverse_uncertain_exchange(
                parent_fd,
                source.name,
                destination.name,
                source_identity,
                destination_identity,
            )

        if not manifest_matches(parent_fd, destination.name, expected_manifest):
            reverse_uncertain_exchange(
                parent_fd,
                source.name,
                destination.name,
                source_identity,
                destination_identity,
            )

        remove_directory_tree(parent_fd, source.name, destination_identity)
    finally:
        os.close(parent_fd)


def cleanup_staging(
    source: Path,
    expected_parent_identity: tuple[int, int],
    expected_source_identity: tuple[int, int],
) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    parent_fd = os.open(source.parent, flags)
    try:
        if identity(os.fstat(parent_fd)) != expected_parent_identity:
            fail("cleanup parent identity changed; staging recovery retained")
        remove_directory_tree(parent_fd, source.name, expected_source_identity)
    finally:
        os.close(parent_fd)


def main() -> None:
    if len(sys.argv) == 7 and sys.argv[1] == "--cleanup-staging":
        try:
            cleanup_staging(
                absolute_without_resolving(sys.argv[2]),
                (int(sys.argv[3]), int(sys.argv[4])),
                (int(sys.argv[5]), int(sys.argv[6])),
            )
        except ValueError as exc:
            fail(f"cleanup identity is not numeric: {exc}")
        return
    if len(sys.argv) != 6:
        fail(
            "usage: publish-launch-assets.py STAGING_DIRECTORY DESTINATION "
            "EXPECTED_PARENT_DEVICE EXPECTED_PARENT_INODE MANIFEST_JSON"
        )
    try:
        expected_parent_identity = (int(sys.argv[3]), int(sys.argv[4]))
    except ValueError as exc:
        fail(f"parent identity is not numeric: {exc}")
    try:
        parsed_manifest = json.loads(sys.argv[5])
    except json.JSONDecodeError as exc:
        fail(f"manifest is not valid JSON: {exc}")
    if not isinstance(parsed_manifest, dict) or not all(
        isinstance(name, str) and isinstance(digest, str) and len(digest) == 64
        for name, digest in parsed_manifest.items()
    ):
        fail("manifest must map asset names to SHA-256 digests")
    publish(
        absolute_without_resolving(sys.argv[1]),
        absolute_without_resolving(sys.argv[2]),
        expected_parent_identity,
        parsed_manifest,
    )


if __name__ == "__main__":
    main()
