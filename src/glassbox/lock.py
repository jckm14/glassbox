"""Single-writer guard for a Glassbox data directory.

The receipt database is republished as a new file on every write and each
process pins the file it opened, so two processes writing to one data
directory would invalidate each other. Long-running servers hold this lock
for their lifetime; one-shot commands take it briefly or hand the write to
the server that already holds it.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Self

_LOCK_NAME = "writer.lock"
_MAX_INFO_BYTES = 4096


def open_private_dir(data_dir: Path, *, create: bool) -> int:
    """Open the data directory without following symlinks and check it is private."""
    data_dir = Path(data_dir)
    created = False
    if create:
        try:
            data_dir.mkdir(parents=True, mode=0o700)
            created = True
        except FileExistsError:
            pass
    flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(data_dir, flags)
    except OSError as exc:
        raise RuntimeError(
            "Glassbox data directory must be a private real directory"
        ) from exc
    try:
        if created:
            os.fchmod(descriptor, 0o700)
        identity = os.fstat(descriptor)
        if identity.st_uid != os.geteuid() or stat.S_IMODE(identity.st_mode) != 0o700:
            raise RuntimeError(
                "Glassbox data directory must be owned by the running user and mode 0700"
            )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_lock_file(directory_fd: int, *, create: bool) -> int:
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    if create:
        flags |= os.O_CREAT
    descriptor = os.open(_LOCK_NAME, flags, 0o600, dir_fd=directory_fd)
    try:
        identity = os.fstat(descriptor)
        if not stat.S_ISREG(identity.st_mode) or identity.st_uid != os.geteuid():
            raise RuntimeError("Glassbox writer lock must be an owned regular file")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


class WriterLock:
    """Advisory exclusive lock on ``<data-dir>/writer.lock``."""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self._fd: int | None = None

    @property
    def held(self) -> bool:
        return self._fd is not None

    def acquire(
        self, *, timeout: float = 0.0, info: dict[str, Any] | None = None
    ) -> bool:
        """Try to take the lock, waiting up to ``timeout`` seconds."""
        if self._fd is not None:
            return True
        directory_fd = open_private_dir(self.data_dir, create=True)
        try:
            descriptor = _open_lock_file(directory_fd, create=True)
        finally:
            os.close(directory_fd)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    os.close(descriptor)
                    return False
                time.sleep(0.05)
        try:
            payload = json.dumps({"pid": os.getpid(), **(info or {})}).encode("utf-8")
            os.ftruncate(descriptor, 0)
            os.pwrite(descriptor, payload, 0)
        except BaseException:
            os.close(descriptor)
            raise
        self._fd = descriptor
        return True

    def release(self) -> None:
        descriptor, self._fd = self._fd, None
        if descriptor is None:
            return
        try:
            os.ftruncate(descriptor, 0)
        except OSError:
            pass
        os.close(descriptor)

    def __enter__(self) -> Self:
        if not self.acquire():
            raise RuntimeError("Glassbox data directory is in use by another writer")
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.release()

    def __del__(self) -> None:
        self.release()


def read_holder_info(data_dir: Path) -> dict[str, Any]:
    """Return what the current lock holder published about itself, if anything."""
    try:
        directory_fd = open_private_dir(Path(data_dir), create=False)
    except RuntimeError:
        return {}
    try:
        descriptor = _open_lock_file(directory_fd, create=False)
    except (OSError, RuntimeError):
        return {}
    finally:
        os.close(directory_fd)
    try:
        raw = os.pread(descriptor, _MAX_INFO_BYTES, 0)
    finally:
        os.close(descriptor)
    try:
        info = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {}
    return info if isinstance(info, dict) else {}
