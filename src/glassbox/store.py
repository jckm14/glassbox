from __future__ import annotations

import base64
import ctypes
import difflib
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, NoReturn

from cryptography.fernet import Fernet, InvalidToken

from . import __version__
from .security import assess_risk, redact, redact_text

_AT_FDCWD = -100
_AT_SYMLINK_FOLLOW = 0x400
_AT_EMPTY_PATH = 0x1000
_RENAME_NOREPLACE = 1
_RENAME_EXCHANGE = 2

INTERNAL_AGENT = "glassbox"
ROLLBACK_ACTION = "file.rollback"
PRUNE_ACTION = "snapshot.prune"
INTERNAL_ACTIONS = frozenset({ROLLBACK_ACTION, PRUNE_ACTION})

_SNAPSHOT_DIR = "snapshots"
_BLOB_NAME = re.compile(r"[0-9a-f]{64}")
_MAX_BLOB_BYTES = 32 * 1024 * 1024
_MAX_DIFF_INPUT_CHARS = 400_000
_PRUNE_RECEIPT_CHUNK = 2000
_EVENT_COLUMNS = (
    "id, created_at, agent, action, target, summary, metadata_json, "
    "before_sha256, after_sha256, snapshot_sha256, risk, reversible, "
    "previous_hash, receipt_hash, risk_reason, diff_sha256, "
    "before_ciphertext IS NOT NULL AS has_inline_snapshot"
)


def validate_external_event(agent: str, action: str) -> None:
    """Reject submissions that impersonate receipts Glassbox writes itself.

    Rollback and prune receipts change how later receipts are interpreted, so
    integrations may not submit them or use the reserved agent name.
    """
    if agent.strip().lower() == INTERNAL_AGENT:
        raise ValueError(f"agent name {INTERNAL_AGENT!r} is reserved for Glassbox")
    if action.strip().lower() in INTERNAL_ACTIONS:
        raise ValueError(f"action {action!r} is reserved for Glassbox")


def _renameat2(
    first: str | Path,
    second: str | Path,
    flags: int,
    *,
    first_dir_fd: int = _AT_FDCWD,
    second_dir_fd: int = _AT_FDCWD,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "Atomic path exchange is unavailable")
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        first_dir_fd,
        os.fsencode(first),
        second_dir_fd,
        os.fsencode(second),
        flags,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _exchange_paths(
    first: str | Path,
    second: str | Path,
    *,
    first_dir_fd: int = _AT_FDCWD,
    second_dir_fd: int = _AT_FDCWD,
) -> None:
    """Atomically exchange two directory entries, or fail closed."""
    _renameat2(
        first,
        second,
        _RENAME_EXCHANGE,
        first_dir_fd=first_dir_fd,
        second_dir_fd=second_dir_fd,
    )


def _move_without_replacing(
    first: str | Path,
    second: str | Path,
    *,
    first_dir_fd: int = _AT_FDCWD,
    second_dir_fd: int = _AT_FDCWD,
) -> None:
    """Atomically move an entry to a name that must not exist, or fail closed."""
    _renameat2(
        first,
        second,
        _RENAME_NOREPLACE,
        first_dir_fd=first_dir_fd,
        second_dir_fd=second_dir_fd,
    )


def _link_unnamed_file(descriptor: int, directory_fd: int, name: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    linkat = libc.linkat
    linkat.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
    ]
    linkat.restype = ctypes.c_int
    result = linkat(
        descriptor,
        b"",
        directory_fd,
        os.fsencode(name),
        _AT_EMPTY_PATH,
    )
    if result != 0 and ctypes.get_errno() in {errno.ENOENT, errno.EPERM}:
        result = linkat(
            _AT_FDCWD,
            os.fsencode(f"/proc/self/fd/{descriptor}"),
            directory_fd,
            os.fsencode(name),
            _AT_SYMLINK_FOLLOW,
        )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


class RollbackError(Exception):
    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


class SnapshotError(RuntimeError):
    """A stored snapshot is missing its protections or fails its integrity check."""


class EventStore:
    def __init__(self, data_dir: Path, *, read_only: bool = False):
        self.data_dir = Path(data_dir)
        self.read_only = read_only
        created = False
        if not read_only:
            try:
                self.data_dir.mkdir(parents=True, mode=0o700)
                created = True
            except FileExistsError:
                pass
        directory_flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            self._data_dir_fd = os.open(self.data_dir, directory_flags)
        except OSError as exc:
            raise RuntimeError(
                "Glassbox data directory must be a private real directory"
            ) from exc
        self._db_fd: int | None = None
        self._key_fd: int | None = None
        self._snapshot_dir_fd: int | None = None
        self._write_lock = threading.RLock()
        try:
            if created:
                os.fchmod(self._data_dir_fd, 0o700)
            directory_identity = os.fstat(self._data_dir_fd)
            if (
                directory_identity.st_uid != os.geteuid()
                or stat.S_IMODE(directory_identity.st_mode) != 0o700
            ):
                raise RuntimeError(
                    "Glassbox data directory must be owned by the running user and mode 0700"
                )
            self.db_path = self.data_dir / "glassbox.db"
            self.key_path = self.data_dir / "receipt.key"
            self._key = self._load_key()
            cipher_key = base64.urlsafe_b64encode(
                hashlib.sha256(self._key + b":snapshot").digest()
            )
            self._cipher = Fernet(cipher_key)
            self._prepare_db_file()
            self._open_snapshot_dir()
            if read_only:
                self._require_initialized()
            else:
                self._initialize()
        except BaseException:
            if self._snapshot_dir_fd is not None:
                os.close(self._snapshot_dir_fd)
                self._snapshot_dir_fd = None
            if self._db_fd is not None:
                os.close(self._db_fd)
                self._db_fd = None
            if self._key_fd is not None:
                os.close(self._key_fd)
                self._key_fd = None
            os.close(self._data_dir_fd)
            raise

    def close(self) -> None:
        write_lock = getattr(self, "_write_lock", None)
        if write_lock is None:
            self._close_descriptors()
            return
        with write_lock:
            self._close_descriptors()

    def _close_descriptors(self) -> None:
        database_fd = getattr(self, "_db_fd", None)
        if database_fd is not None:
            try:
                os.close(database_fd)
            except OSError:
                pass
            self._db_fd = None
        key_fd = getattr(self, "_key_fd", None)
        if key_fd is not None:
            try:
                os.close(key_fd)
            except OSError:
                pass
            self._key_fd = None
        snapshot_dir_fd = getattr(self, "_snapshot_dir_fd", None)
        if snapshot_dir_fd is not None:
            try:
                os.close(snapshot_dir_fd)
            except OSError:
                pass
            self._snapshot_dir_fd = None
        data_dir_fd = getattr(self, "_data_dir_fd", -1)
        if data_dir_fd >= 0:
            try:
                os.close(data_dir_fd)
            except OSError:
                pass
            self._data_dir_fd = -1

    def __del__(self) -> None:
        self.close()

    @staticmethod
    def _validate_private_file(descriptor: int, label: str) -> os.stat_result:
        identity = os.fstat(descriptor)
        if (
            not stat.S_ISREG(identity.st_mode)
            or identity.st_nlink != 1
            or stat.S_IMODE(identity.st_mode) != 0o600
            or identity.st_uid != os.geteuid()
        ):
            raise RuntimeError(
                f"{label} must be an owned mode-0600 private regular file with one link"
            )
        return identity

    def _prepare_db_file(self) -> None:
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | no_follow
        try:
            if self.read_only:
                raise FileExistsError
            descriptor = os.open("glassbox.db", flags, 0o600, dir_fd=self._data_dir_fd)
        except FileExistsError:
            try:
                descriptor = os.open(
                    "glassbox.db",
                    os.O_RDWR | no_follow,
                    dir_fd=self._data_dir_fd,
                )
            except OSError as exc:
                raise RuntimeError(
                    "Glassbox database must be a private regular file"
                ) from exc
        try:
            self._validate_private_file(descriptor, "Glassbox database")
        except BaseException:
            os.close(descriptor)
            raise
        self._db_fd = descriptor

    def _load_key(self) -> bytes:
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow
        try:
            if self.read_only:
                raise FileExistsError
            descriptor = os.open(
                "receipt.key",
                create_flags,
                0o600,
                dir_fd=self._data_dir_fd,
            )
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as key_file:
                key_file.write(secrets.token_bytes(32))
                key_file.flush()
                os.fsync(key_file.fileno())

        try:
            descriptor = os.open(
                "receipt.key",
                os.O_RDONLY | no_follow,
                dir_fd=self._data_dir_fd,
            )
        except OSError as exc:
            raise RuntimeError("Receipt key must be a private regular file") from exc
        try:
            self._validate_private_file(descriptor, "Receipt key")
            with os.fdopen(os.dup(descriptor), "rb") as key_file:
                key = key_file.read()
            self._validate_pinned_entry(descriptor, "receipt.key", "Receipt key")
            if len(key) != 32:
                raise RuntimeError("Receipt key must contain exactly 32 bytes")
        except BaseException:
            os.close(descriptor)
            raise
        self._key_fd = descriptor
        return key

    def _validate_pinned_entry(self, descriptor: int, name: str, label: str) -> None:
        pinned = self._validate_private_file(descriptor, label)
        try:
            current = os.stat(
                name,
                dir_fd=self._data_dir_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise RuntimeError(f"{label} entry changed after validation") from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino)
            or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != 0o600
            or current.st_uid != os.geteuid()
        ):
            raise RuntimeError(f"{label} entry changed after validation")

    def _validate_security_entries(self) -> None:
        directory_identity = os.fstat(self._data_dir_fd)
        if (
            directory_identity.st_uid != os.geteuid()
            or stat.S_IMODE(directory_identity.st_mode) != 0o700
        ):
            raise RuntimeError("Glassbox data directory protection changed")
        if self._db_fd is None or self._key_fd is None:
            raise RuntimeError("Glassbox security descriptors are unavailable")
        self._validate_pinned_entry(self._db_fd, "glassbox.db", "Glassbox database")
        self._validate_pinned_entry(self._key_fd, "receipt.key", "Receipt key")

    def _open_snapshot_dir(self) -> None:
        """Pin the private directory that holds encrypted snapshot blobs."""
        directory_flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        created = False
        if not self.read_only:
            try:
                os.mkdir(_SNAPSHOT_DIR, mode=0o700, dir_fd=self._data_dir_fd)
                created = True
            except FileExistsError:
                pass
        try:
            descriptor = os.open(
                _SNAPSHOT_DIR, directory_flags, dir_fd=self._data_dir_fd
            )
        except FileNotFoundError:
            if self.read_only:
                return
            raise RuntimeError(
                "Glassbox snapshot directory must be a private real directory"
            ) from None
        except OSError as exc:
            raise RuntimeError(
                "Glassbox snapshot directory must be a private real directory"
            ) from exc
        try:
            if created:
                os.fchmod(descriptor, 0o700)
            identity = os.fstat(descriptor)
            if (
                identity.st_uid != os.geteuid()
                or stat.S_IMODE(identity.st_mode) != 0o700
            ):
                raise RuntimeError(
                    "Glassbox snapshot directory must be owned by the running user and mode 0700"
                )
        except BaseException:
            os.close(descriptor)
            raise
        self._snapshot_dir_fd = descriptor

    def _validate_snapshot_dir(self) -> int:
        descriptor = self._snapshot_dir_fd
        if descriptor is None:
            raise SnapshotError("Glassbox snapshot directory is unavailable")
        pinned = os.fstat(descriptor)
        try:
            current = os.stat(
                _SNAPSHOT_DIR, dir_fd=self._data_dir_fd, follow_symlinks=False
            )
        except OSError as exc:
            raise SnapshotError("Glassbox snapshot directory changed") from exc
        if (
            not stat.S_ISDIR(current.st_mode)
            or (current.st_dev, current.st_ino) != (pinned.st_dev, pinned.st_ino)
            or pinned.st_uid != os.geteuid()
            or stat.S_IMODE(pinned.st_mode) != 0o700
        ):
            raise SnapshotError("Glassbox snapshot directory changed")
        return descriptor

    def _write_blob(self, ciphertext: bytes) -> str:
        """Store one encrypted blob under its SHA-256 name without overwriting."""
        digest = hashlib.sha256(ciphertext).hexdigest()
        directory_fd = self._validate_snapshot_dir()
        descriptor = os.open(
            ".",
            os.O_WRONLY | os.O_TMPFILE | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            view = memoryview(ciphertext)
            offset = 0
            while offset < len(view):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    raise OSError(errno.EIO, "Snapshot write made no progress")
                offset += written
            os.fsync(descriptor)
            try:
                _link_unnamed_file(descriptor, directory_fd, digest)
            except FileExistsError:
                if self._read_blob(digest) != ciphertext:
                    raise SnapshotError(
                        "Existing snapshot does not match its content address"
                    ) from None
        finally:
            os.close(descriptor)
        os.fsync(directory_fd)
        return digest

    def _read_blob(self, digest: str) -> bytes | None:
        """Return a stored blob, ``None`` if absent; raise if it is not trustworthy."""
        if self._snapshot_dir_fd is None:
            return None
        if not _BLOB_NAME.fullmatch(digest):
            raise SnapshotError("Snapshot reference is not a SHA-256 digest")
        directory_fd = self._validate_snapshot_dir()
        try:
            descriptor = os.open(
                digest,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise SnapshotError("Snapshot must be a private regular file") from exc
        try:
            identity = os.fstat(descriptor)
            if (
                not stat.S_ISREG(identity.st_mode)
                or identity.st_nlink != 1
                or stat.S_IMODE(identity.st_mode) != 0o600
                or identity.st_uid != os.geteuid()
                or identity.st_size > _MAX_BLOB_BYTES
            ):
                raise SnapshotError(
                    "Snapshot must be an owned mode-0600 private regular file with one link"
                )
            data = self._read_database_bytes(descriptor)
        finally:
            os.close(descriptor)
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), digest):
            raise SnapshotError("Encrypted snapshot failed integrity verification")
        return data

    def _remove_blob(self, digest: str) -> int:
        """Unlink one blob and return the bytes released (0 if already absent)."""
        if self._snapshot_dir_fd is None or not _BLOB_NAME.fullmatch(digest):
            return 0
        directory_fd = self._validate_snapshot_dir()
        try:
            size = os.stat(digest, dir_fd=directory_fd, follow_symlinks=False).st_size
            os.unlink(digest, dir_fd=directory_fd)
        except FileNotFoundError:
            return 0
        return size

    @staticmethod
    def _read_database_bytes(descriptor: int) -> bytes:
        size = os.fstat(descriptor).st_size
        chunks: list[bytes] = []
        offset = 0
        while offset < size:
            chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
            if not chunk:
                raise RuntimeError("Glassbox database snapshot ended unexpectedly")
            chunks.append(chunk)
            offset += len(chunk)
        return b"".join(chunks)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with self._write_lock:
            self._validate_security_entries()
            assert self._db_fd is not None
            database_bytes = self._read_database_bytes(self._db_fd)
            self._validate_security_entries()
            conn = sqlite3.connect(":memory:")
            try:
                if database_bytes:
                    conn.deserialize(database_bytes)
                conn.row_factory = sqlite3.Row
                yield conn
                self._validate_security_entries()
            finally:
                conn.close()

    def _publish_database(self, database_bytes: bytes) -> None:
        if not database_bytes:
            raise RuntimeError("Glassbox refused to publish an empty database")
        temporary_fd = os.open(
            ".",
            os.O_RDWR | os.O_TMPFILE | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=self._data_dir_fd,
        )
        temporary_name = f".glassbox-db-{secrets.token_hex(16)}.tmp"
        linked = False
        published = False
        old_database_fd = self._db_fd
        try:
            view = memoryview(database_bytes)
            offset = 0
            while offset < len(view):
                written = os.write(temporary_fd, view[offset:])
                if written <= 0:
                    raise OSError(errno.EIO, "Database snapshot write made no progress")
                offset += written
            os.fsync(temporary_fd)
            candidate_identity = os.fstat(temporary_fd)
            if (
                not stat.S_ISREG(candidate_identity.st_mode)
                or candidate_identity.st_nlink != 0
                or stat.S_IMODE(candidate_identity.st_mode) != 0o600
                or candidate_identity.st_uid != os.geteuid()
            ):
                raise RuntimeError(
                    "Glassbox database candidate is not a private unnamed regular file"
                )
            _link_unnamed_file(temporary_fd, self._data_dir_fd, temporary_name)
            linked = True
            try:
                _exchange_paths(
                    temporary_name,
                    "glassbox.db",
                    first_dir_fd=self._data_dir_fd,
                    second_dir_fd=self._data_dir_fd,
                )
            except BaseException:
                current = os.stat(
                    "glassbox.db",
                    dir_fd=self._data_dir_fd,
                    follow_symlinks=False,
                )
                published = (current.st_dev, current.st_ino) == (
                    candidate_identity.st_dev,
                    candidate_identity.st_ino,
                )
                if not published:
                    raise
            else:
                published = True
            self._db_fd = temporary_fd
            temporary_fd = -1
            try:
                os.unlink(temporary_name, dir_fd=self._data_dir_fd)
                linked = False
                os.fsync(self._data_dir_fd)
            except OSError:
                # The new immutable snapshot is already the live database. Retain the
                # displaced snapshot rather than report a false failed commit.
                pass
            if old_database_fd is not None:
                os.close(old_database_fd)
            self._validate_security_entries()
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            if linked and not published:
                try:
                    os.unlink(temporary_name, dir_fd=self._data_dir_fd)
                except OSError:
                    pass

    @contextmanager
    def _write_connect(self) -> Iterator[sqlite3.Connection]:
        with self._write_lock:
            self._validate_security_entries()
            assert self._db_fd is not None
            database_bytes = self._read_database_bytes(self._db_fd)
            self._validate_security_entries()

            conn = sqlite3.connect(":memory:")
            try:
                if database_bytes:
                    conn.deserialize(database_bytes)
                conn.row_factory = sqlite3.Row
                yield conn
                self._validate_security_entries()
                conn.commit()
                serialized_database = conn.serialize()
                if serialized_database != database_bytes:
                    self._publish_database(serialized_database)
            except BaseException:
                conn.rollback()
                raise
            finally:
                conn.close()

    def _initialize(self) -> None:
        with self._write_connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    before_sha256 TEXT,
                    after_sha256 TEXT,
                    before_ciphertext BLOB,
                    snapshot_sha256 TEXT,
                    risk TEXT NOT NULL,
                    reversible INTEGER NOT NULL,
                    previous_hash TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    risk_reason TEXT,
                    diff_sha256 TEXT
                )
                """
            )
            columns = self._table_columns(conn)
            for column in ("risk_reason", "diff_sha256"):
                if column not in columns:
                    conn.execute(f"ALTER TABLE events ADD COLUMN {column} TEXT")
            self._externalize_inline_snapshots(conn)

    def _externalize_inline_snapshots(self, conn: sqlite3.Connection) -> None:
        """Move snapshots that older versions stored inside the database to files.

        Only ``snapshot_sha256`` is authenticated by a receipt, so relocating an
        intact ciphertext does not change any signature. A ciphertext that no
        longer matches its recorded hash is left in place so verification keeps
        reporting it.
        """
        rows = conn.execute(
            "SELECT id, before_ciphertext, snapshot_sha256 FROM events "
            "WHERE before_ciphertext IS NOT NULL"
        ).fetchall()
        for row in rows:
            ciphertext = row["before_ciphertext"]
            recorded = row["snapshot_sha256"]
            if not isinstance(ciphertext, bytes) or not isinstance(recorded, str):
                continue
            if not hmac.compare_digest(
                hashlib.sha256(ciphertext).hexdigest(), recorded
            ):
                continue
            self._write_blob(ciphertext)
            conn.execute(
                "UPDATE events SET before_ciphertext = NULL WHERE id = ?",
                (row["id"],),
            )

    def _require_initialized(self) -> None:
        with self._connect() as conn:
            if not self._table_columns(conn):
                raise RuntimeError("Glassbox ledger has not been initialized")

    @staticmethod
    def _table_columns(conn: sqlite3.Connection) -> set[str]:
        return {row[1] for row in conn.execute("PRAGMA table_info(events)")}

    @classmethod
    def _select_columns(cls, conn: sqlite3.Connection) -> str:
        """Column list that also reads ledgers written before newer columns."""
        columns = cls._table_columns(conn)
        selected = _EVENT_COLUMNS
        for column in ("risk_reason", "diff_sha256"):
            if column not in columns:
                selected = selected.replace(f"{column}, ", f"NULL AS {column}, ")
        return selected

    @staticmethod
    def _digest(value: str | None) -> str | None:
        return (
            hashlib.sha256(value.encode("utf-8")).hexdigest()
            if value is not None
            else None
        )

    @staticmethod
    def _target_parts(target: str) -> tuple[str, ...]:
        relative = Path(target)
        if relative.is_absolute() or not relative.parts:
            raise RollbackError(
                "Rollback target is outside the configured workspace", 400
            )
        if any(part in {"", ".", ".."} for part in relative.parts):
            raise RollbackError(
                "Rollback target is outside the configured workspace", 400
            )
        return relative.parts

    @staticmethod
    def open_workspace(workspace: str | Path) -> tuple[Path, int]:
        workspace_path = Path(os.path.abspath(os.fspath(workspace)))
        directory_flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open("/", directory_flags)
        try:
            for component in workspace_path.parts[1:]:
                next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
        except OSError:
            os.close(descriptor)
            raise
        return workspace_path, descriptor

    @staticmethod
    def _open_parent_at_workspace(
        workspace: Path,
        parts: tuple[str, ...],
        pinned_workspace_fd: int | None = None,
    ) -> tuple[int, int]:
        directory_flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            if pinned_workspace_fd is None:
                _, root_fd = EventStore.open_workspace(workspace)
            else:
                root_fd = os.dup(pinned_workspace_fd)
        except OSError as exc:
            raise RollbackError("Configured workspace is unavailable", 409) from exc
        parent_fd = os.dup(root_fd)
        try:
            for component in parts[:-1]:
                next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
        except OSError as exc:
            os.close(parent_fd)
            os.close(root_fd)
            raise RollbackError(
                "Rollback target parent is not a stable workspace directory", 409
            ) from exc
        return root_fd, parent_fd

    @staticmethod
    def _same_identity(first: os.stat_result, second: os.stat_result) -> bool:
        return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)

    @classmethod
    def _parent_is_current(
        cls,
        workspace: Path,
        parts: tuple[str, ...],
        root_identity: os.stat_result,
        parent_identity: os.stat_result,
        pinned_workspace_fd: int | None = None,
    ) -> bool:
        try:
            fresh_root_fd, fresh_parent_fd = cls._open_parent_at_workspace(
                workspace, parts, pinned_workspace_fd
            )
        except (OSError, RollbackError):
            return False
        try:
            _, configured_root_fd = cls.open_workspace(workspace)
        except OSError:
            os.close(fresh_parent_fd)
            os.close(fresh_root_fd)
            return False
        try:
            return (
                cls._same_identity(os.fstat(fresh_root_fd), root_identity)
                and cls._same_identity(os.fstat(fresh_parent_fd), parent_identity)
                and cls._same_identity(os.fstat(configured_root_fd), root_identity)
            )
        finally:
            os.close(configured_root_fd)
            os.close(fresh_parent_fd)
            os.close(fresh_root_fd)

    @staticmethod
    def _open_regular_at(parent_fd: int, name: str, flags: int = os.O_RDONLY) -> int:
        descriptor = os.open(
            name,
            flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise OSError(errno.EINVAL, "Rollback entry must be a regular file")
        return descriptor

    @staticmethod
    def _get_posix_acl(descriptor: int, *, default: bool = False) -> bytes | None:
        attribute = "system.posix_acl_default" if default else "system.posix_acl_access"
        try:
            return os.getxattr(descriptor, attribute)
        except OSError as exc:
            if exc.errno in {errno.ENODATA, errno.ENOTSUP}:
                return None
            raise

    @staticmethod
    def _remove_posix_acl(descriptor: int, *, default: bool = False) -> None:
        attribute = "system.posix_acl_default" if default else "system.posix_acl_access"
        try:
            os.removexattr(descriptor, attribute)
        except OSError as exc:
            if exc.errno not in {errno.ENODATA, errno.ENOTSUP}:
                raise

    @classmethod
    def _read_regular_text_at(
        cls, parent_fd: int, name: str
    ) -> tuple[str, os.stat_result, bytes | None]:
        descriptor = cls._open_regular_at(parent_fd, name)
        try:
            identity = os.fstat(descriptor)
            access_acl = cls._get_posix_acl(descriptor)
            with os.fdopen(os.dup(descriptor), "r", encoding="utf-8") as source:
                return source.read(), identity, access_acl
        finally:
            os.close(descriptor)

    @classmethod
    def _write_temp_text_at(
        cls, parent_fd: int, target_name: str, text: str, mode: int, *, label: str
    ) -> str:
        temp_name = f".{target_name}.glassbox-{label}-{secrets.token_hex(8)}.tmp"
        descriptor = os.open(
            temp_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=parent_fd,
        )
        try:
            cls._remove_posix_acl(descriptor)
            with os.fdopen(descriptor, "w", encoding="utf-8") as temp_file:
                temp_file.write(text)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                os.fchmod(temp_file.fileno(), mode)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            try:
                os.unlink(temp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            raise
        return temp_name

    @classmethod
    def _apply_regular_acl_at(
        cls,
        parent_fd: int,
        name: str,
        access_acl: bytes | None,
        mode: int,
        uid: int,
        gid: int,
    ) -> None:
        descriptor = cls._open_regular_at(parent_fd, name)
        try:
            os.fchown(descriptor, uid, gid)
            os.fchmod(descriptor, mode)
            if access_acl is None:
                cls._remove_posix_acl(descriptor)
            else:
                os.setxattr(descriptor, "system.posix_acl_access", access_acl)
            identity = os.fstat(descriptor)
            if (
                stat.S_IMODE(identity.st_mode) != mode
                or identity.st_uid != uid
                or identity.st_gid != gid
                or cls._get_posix_acl(descriptor) != access_acl
            ):
                raise OSError(errno.EPERM, "Could not preserve target access policy")
        finally:
            os.close(descriptor)

    @classmethod
    def _create_private_recovery_dir(
        cls, parent_fd: int, target_name: str
    ) -> tuple[str, int]:
        directory_name = f".{target_name}.glassbox-recovery-{secrets.token_hex(8)}"
        os.mkdir(directory_name, mode=0o700, dir_fd=parent_fd)
        flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor: int | None = None
        try:
            descriptor = os.open(directory_name, flags, dir_fd=parent_fd)
            cls._remove_posix_acl(descriptor)
            cls._remove_posix_acl(descriptor, default=True)
            os.fchmod(descriptor, 0o700)
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.rmdir(directory_name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
        assert descriptor is not None
        return directory_name, descriptor

    @staticmethod
    def _entry_path(parent_fd: int, name: str) -> Path:
        parent_path = Path(os.readlink(f"/proc/self/fd/{parent_fd}"))
        return parent_path / name

    def _sign(self, record: dict[str, Any]) -> str:
        canonical = json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )
        return hmac.new(
            self._key, canonical.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    @staticmethod
    def _is_reversible(
        action: str, before_text: str | None, after_text: str | None
    ) -> bool:
        if action == "file.write":
            return before_text is not None and after_text is not None
        if action == "file.create":
            return before_text is None and after_text is not None
        if action == "file.delete":
            return before_text is not None and after_text is None
        return False

    @staticmethod
    def _unified_diff(
        action: str, target: str, before_text: str | None, after_text: str | None
    ) -> str | None:
        """Text diff recorded with a receipt, or ``None`` when there is none to keep."""
        if after_text is None:
            return None
        if before_text is None:
            if action != "file.create":
                return None
            before_text = ""
        if len(before_text) + len(after_text) > _MAX_DIFF_INPUT_CHARS:
            return None
        return "".join(
            difflib.unified_diff(
                before_text.splitlines(keepends=True),
                after_text.splitlines(keepends=True),
                fromfile=f"a/{target}",
                tofile=f"b/{target}",
            )
        )

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.read_only:
            raise RuntimeError("Glassbox store was opened read-only")
        action = payload["action"]
        before_text = payload.get("before_text")
        after_text = payload.get("after_text")
        metadata = payload.get("metadata") or {}
        target = redact(payload["target"])
        # A target rewritten by redaction no longer names the file that changed.
        path_intact = target == payload["target"]
        risk, risk_reason = assess_risk(action, payload["target"], metadata)
        before_ciphertext = (
            self._cipher.encrypt(before_text.encode("utf-8"))
            if before_text is not None
            else None
        )
        diff_text = self._unified_diff(action, target, before_text, after_text)
        diff_ciphertext = (
            self._cipher.encrypt(diff_text.encode("utf-8"))
            if diff_text is not None
            else None
        )
        written_blobs: list[str] = []
        committed = False
        receipt_hash: str | None = None
        try:
            with self._write_connect() as conn:
                conn.execute("BEGIN IMMEDIATE")
                previous = conn.execute(
                    "SELECT receipt_hash FROM events ORDER BY id DESC LIMIT 1"
                ).fetchone()
                previous_hash = previous[0] if previous else "0" * 64
                snapshot_sha256: str | None = None
                diff_sha256: str | None = None
                if before_ciphertext is not None:
                    snapshot_sha256 = self._write_blob(before_ciphertext)
                    written_blobs.append(snapshot_sha256)
                if diff_ciphertext is not None:
                    diff_sha256 = self._write_blob(diff_ciphertext)
                    written_blobs.append(diff_sha256)
                record: dict[str, Any] = {
                    "created_at": datetime.now(UTC).isoformat(),
                    "agent": payload["agent"],
                    "action": action,
                    "target": target,
                    "summary": redact(payload["summary"]),
                    "metadata": redact(metadata),
                    "before_sha256": self._digest(before_text),
                    "after_sha256": self._digest(after_text),
                    "snapshot_sha256": snapshot_sha256,
                    "risk": risk,
                    "reversible": path_intact
                    and self._is_reversible(action, before_text, after_text),
                    "previous_hash": previous_hash,
                    "risk_reason": risk_reason,
                }
                if diff_sha256 is not None:
                    record["diff_sha256"] = diff_sha256
                receipt_hash = self._sign(record)
                cursor = conn.execute(
                    """
                    INSERT INTO events (
                        created_at, agent, action, target, summary, metadata_json,
                        before_sha256, after_sha256, snapshot_sha256,
                        risk, reversible, previous_hash, receipt_hash,
                        risk_reason, diff_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        record["created_at"],
                        record["agent"],
                        record["action"],
                        record["target"],
                        record["summary"],
                        json.dumps(record["metadata"], sort_keys=True),
                        record["before_sha256"],
                        record["after_sha256"],
                        snapshot_sha256,
                        record["risk"],
                        int(record["reversible"]),
                        previous_hash,
                        receipt_hash,
                        risk_reason,
                        diff_sha256,
                    ),
                )
                event_id = cursor.lastrowid
            committed = True
        finally:
            if not committed and written_blobs:
                # Fernet ciphertexts are unique per call, so these blobs can
                # only belong to this receipt. A failure raised after the
                # database was published still leaves a committed receipt, so
                # remove them only when the receipt is known to be absent.
                try:
                    absent = receipt_hash is None or not self.has_receipt(receipt_hash)
                except BaseException:  # noqa: BLE001 - keep blobs when unsure
                    absent = False
                if absent:
                    for digest in written_blobs:
                        try:
                            self._remove_blob(digest)
                        except (OSError, SnapshotError):
                            pass
        return {"id": event_id, **record, "receipt_hash": receipt_hash}

    def has_receipt(self, receipt_hash: str) -> bool:
        """Whether a receipt with this hash is in the ledger."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM events WHERE receipt_hash = ?", (receipt_hash,)
            ).fetchone()
        return row is not None

    def _find_rollback_operation(self, operation_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, metadata_json FROM events "
                "WHERE action = 'file.rollback' ORDER BY id DESC"
            ).fetchall()
        for candidate in rows:
            try:
                metadata = json.loads(candidate["metadata_json"])
            except (TypeError, ValueError):
                continue
            if (
                isinstance(metadata, dict)
                and metadata.get("rollback_operation_id") == operation_id
            ):
                return {"id": candidate["id"]}
        return None

    @staticmethod
    def _require_recorded_workspace(row: sqlite3.Row, workspace: Path) -> None:
        """Refuse to apply a receipt recorded for a different workspace.

        Targets are workspace-relative, so the same relative path in another
        project names an unrelated file.
        """
        try:
            metadata = json.loads(row["metadata_json"])
        except (TypeError, ValueError):
            return
        recorded = metadata.get("workspace") if isinstance(metadata, dict) else None
        if isinstance(recorded, str) and os.path.realpath(recorded) != os.path.realpath(
            workspace
        ):
            raise RollbackError(
                "This receipt was recorded for a different workspace; refusing rollback",
                409,
            )

    def _decrypt_snapshot(self, row: sqlite3.Row, is_pruned: bool) -> str:
        ciphertext = row["before_ciphertext"]
        recorded = row["snapshot_sha256"]
        if ciphertext is not None:
            # Snapshot stored inside the row by an older version.
            if not isinstance(recorded, str) or not hmac.compare_digest(
                hashlib.sha256(ciphertext).hexdigest(), recorded
            ):
                raise RollbackError(
                    "Encrypted rollback snapshot failed integrity verification", 409
                )
        else:
            if recorded is None:
                raise RollbackError("This event has no reversible file snapshot", 409)
            if is_pruned:
                raise RollbackError(
                    "The rollback snapshot for this receipt was pruned", 409
                )
            try:
                ciphertext = self._read_blob(recorded)
            except (SnapshotError, OSError, TypeError) as exc:
                raise RollbackError(
                    "Encrypted rollback snapshot failed integrity verification", 409
                ) from exc
            if ciphertext is None:
                raise RollbackError("Encrypted rollback snapshot is missing", 409)
        try:
            return self._cipher.decrypt(bytes(ciphertext)).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise RollbackError(
                "Encrypted rollback snapshot cannot be decrypted", 409
            ) from exc

    def rollback(
        self,
        event_id: int,
        workspace: Path,
        workspace_identity: tuple[int, int] | None = None,
        workspace_fd: int | None = None,
    ) -> dict[str, Any]:
        with self._connect() as conn:
            pruned, _ = self._load_internal_state(conn)
            row = conn.execute(
                f"SELECT {self._select_columns(conn)}, before_ciphertext "
                "FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            raise RollbackError("Event not found", 404)
        verification = self.verify()
        if not verification["valid"]:
            raise RollbackError(
                "Receipt chain verification failed; refusing rollback", 409
            )
        if row["action"] not in {"file.write", "file.create", "file.delete"} or (
            not row["reversible"]
        ):
            raise RollbackError("This event has no reversible file snapshot", 409)
        workspace = Path(workspace)
        self._require_recorded_workspace(row, workspace)
        if row["action"] == "file.create":
            return self._rollback_create(
                row, event_id, workspace, workspace_identity, workspace_fd
            )
        restored_text = self._decrypt_snapshot(row, event_id in pruned)
        if row["action"] == "file.delete":
            return self._rollback_delete(
                row,
                event_id,
                restored_text,
                workspace,
                workspace_identity,
                workspace_fd,
            )

        rollback_operation_id = secrets.token_hex(16)
        parts = self._target_parts(row["target"])
        target_name = parts[-1]
        root_fd, parent_fd = self._open_parent_at_workspace(
            workspace, parts, workspace_fd
        )
        root_identity = os.fstat(root_fd)
        if (
            workspace_identity is not None
            and (
                root_identity.st_dev,
                root_identity.st_ino,
            )
            != workspace_identity
        ):
            os.close(parent_fd)
            os.close(root_fd)
            raise RollbackError(
                "Configured workspace identity changed; refusing rollback", 409
            )
        parent_identity = os.fstat(parent_fd)
        recovery_dir_name: str | None = None
        recovery_fd: int | None = None
        temp_name: str | None = None
        preserve_temp = False
        receipt: dict[str, Any] | None = None
        recovery_path: Path | None = None
        current_text: str | None = None
        target_identity: os.stat_result | None = None
        target_acl: bytes | None = None

        def exchange_entries() -> None:
            if recovery_fd is None:
                raise RollbackError("Recovery directory is unavailable", 500)
            _exchange_paths(
                temp_name or "",
                target_name,
                first_dir_fd=recovery_fd,
                second_dir_fd=parent_fd,
            )

        def recover_exchange(
            reason: str, cause: BaseException | None = None
        ) -> NoReturn:
            try:
                if recovery_fd is None or not temp_name:
                    raise OSError(errno.EINVAL, "Recovery entry is unavailable")
                entry_to_restore = os.stat(
                    temp_name, dir_fd=recovery_fd, follow_symlinks=False
                )
                exchange_entries()
                recovered_entry = os.stat(
                    target_name, dir_fd=parent_fd, follow_symlinks=False
                )
            except BaseException as recovery_exc:
                raise RollbackError(
                    f"{reason}; recovery failed and displaced content was retained at {recovery_path}",
                    500,
                ) from recovery_exc
            if not self._same_identity(recovered_entry, entry_to_restore):
                raise RollbackError(
                    f"{reason}; recovery identity validation failed and displaced content was retained at {recovery_path}",
                    500,
                ) from cause
            raise RollbackError(
                f"{reason}; filesystem was compensated and recovery retained at {recovery_path}",
                409,
            ) from cause

        try:
            try:
                current_text, target_identity, target_acl = self._read_regular_text_at(
                    parent_fd, target_name
                )
            except (OSError, UnicodeDecodeError) as exc:
                raise RollbackError(
                    "Rollback target must be an existing UTF-8 regular file", 409
                ) from exc
            if self._digest(current_text) != row["after_sha256"]:
                raise RollbackError(
                    "Target changed after this receipt; refusing to overwrite newer work",
                    409,
                )

            mode = stat.S_IMODE(target_identity.st_mode)
            recovery_dir_name, recovery_fd = self._create_private_recovery_dir(
                parent_fd, target_name
            )
            assert recovery_fd is not None
            temp_name = self._write_temp_text_at(
                recovery_fd, target_name, restored_text, mode, label="restore"
            )
            try:
                self._apply_regular_acl_at(
                    recovery_fd,
                    temp_name,
                    target_acl,
                    mode,
                    target_identity.st_uid,
                    target_identity.st_gid,
                )
            except OSError as exc:
                raise RollbackError(
                    "Rollback target ownership or access policy cannot be preserved",
                    409,
                ) from exc
            try:
                candidate_text, candidate_identity, candidate_acl = (
                    self._read_regular_text_at(recovery_fd, temp_name)
                )
            except (OSError, UnicodeDecodeError) as exc:
                raise RollbackError(
                    "Rollback restore candidate changed while preparing the restore",
                    409,
                ) from exc
            if (
                candidate_text != restored_text
                or stat.S_IMODE(candidate_identity.st_mode) != mode
                or candidate_identity.st_uid != target_identity.st_uid
                or candidate_identity.st_gid != target_identity.st_gid
                or candidate_acl != target_acl
            ):
                raise RollbackError(
                    "Rollback restore candidate failed identity or access-policy validation",
                    409,
                )
            recovery_path = self._entry_path(recovery_fd, temp_name)

            if not self._parent_is_current(
                workspace,
                parts,
                root_identity,
                parent_identity,
                workspace_fd,
            ):
                raise RollbackError(
                    "Rollback target parent changed while preparing the restore", 409
                )
            try:
                latest_text, latest_identity, latest_acl = self._read_regular_text_at(
                    parent_fd, target_name
                )
            except (OSError, UnicodeDecodeError) as exc:
                raise RollbackError(
                    "Rollback target entry changed while preparing the restore", 409
                ) from exc
            if not self._same_identity(latest_identity, target_identity):
                raise RollbackError(
                    "Rollback target identity changed while preparing the restore", 409
                )
            if (
                stat.S_IMODE(latest_identity.st_mode) != mode
                or latest_identity.st_uid != target_identity.st_uid
                or latest_identity.st_gid != target_identity.st_gid
                or latest_acl != target_acl
            ):
                raise RollbackError(
                    "Rollback target access policy changed while preparing the restore",
                    409,
                )
            if self._digest(latest_text) != row["after_sha256"]:
                raise RollbackError(
                    "Target changed while preparing the restore; refusing to overwrite newer work",
                    409,
                )

            preserve_temp = True
            try:
                exchange_entries()
            except OSError as exc:
                raise RollbackError(
                    f"Filesystem does not support safe atomic rollback exchange; recovery retained at {recovery_path}",
                    409,
                ) from exc

            try:
                installed_text, installed_identity, installed_acl = (
                    self._read_regular_text_at(parent_fd, target_name)
                )
            except BaseException as exc:  # noqa: BLE001 - compensate asynchronous failures
                recover_exchange(
                    "Rollback restore candidate changed at the atomic exchange", exc
                )
            if (
                not self._same_identity(installed_identity, candidate_identity)
                or installed_text != restored_text
                or stat.S_IMODE(installed_identity.st_mode) != mode
                or installed_identity.st_uid != target_identity.st_uid
                or installed_identity.st_gid != target_identity.st_gid
                or installed_acl != target_acl
            ):
                recover_exchange(
                    "Rollback restore candidate identity or access policy changed at the atomic exchange"
                )

            try:
                parent_is_current = self._parent_is_current(
                    workspace,
                    parts,
                    root_identity,
                    parent_identity,
                    workspace_fd,
                )
            except BaseException as exc:  # noqa: BLE001 - compensate asynchronous failures
                recover_exchange(
                    "Rollback validation failed after the atomic exchange", exc
                )
            if not parent_is_current:
                recover_exchange(
                    "Rollback target parent changed at the atomic exchange"
                )

            try:
                displaced_text, displaced_identity, displaced_acl = (
                    self._read_regular_text_at(recovery_fd, temp_name)
                )
            except BaseException as exc:  # noqa: BLE001 - compensate asynchronous failures
                recover_exchange(
                    "Rollback target entry changed at the atomic exchange", exc
                )

            if not self._same_identity(displaced_identity, target_identity):
                recover_exchange(
                    "Rollback target identity changed at the atomic exchange"
                )
            if (
                stat.S_IMODE(displaced_identity.st_mode) != mode
                or displaced_identity.st_uid != target_identity.st_uid
                or displaced_identity.st_gid != target_identity.st_gid
                or displaced_acl != target_acl
            ):
                recover_exchange(
                    "Rollback target access policy changed at the atomic exchange"
                )
            if self._digest(displaced_text) != row["after_sha256"]:
                recover_exchange("Target changed at the atomic exchange")

            try:
                parent_is_current = self._parent_is_current(
                    workspace,
                    parts,
                    root_identity,
                    parent_identity,
                    workspace_fd,
                )
            except BaseException as exc:  # noqa: BLE001 - compensate asynchronous failures
                recover_exchange(
                    "Rollback validation failed before receipt persistence", exc
                )
            if not parent_is_current:
                recover_exchange(
                    "Rollback target parent changed before receipt persistence"
                )

            try:
                receipt = self.append(
                    {
                        "agent": "glassbox",
                        "action": "file.rollback",
                        "target": row["target"],
                        "summary": f"Rolled back receipt #{event_id}",
                        "before_text": displaced_text,
                        "after_text": restored_text,
                        "metadata": {
                            "rolled_back_event_id": event_id,
                            "rollback_operation_id": rollback_operation_id,
                            "displaced_path": str(recovery_path),
                        },
                    }
                )
            except BaseException as receipt_exc:
                try:
                    committed_receipt = self._find_rollback_operation(
                        rollback_operation_id
                    )
                except BaseException as reconciliation_exc:
                    raise RollbackError(
                        f"Rollback receipt outcome is uncertain; filesystem remains rolled back and recovery retained at {recovery_path}",
                        500,
                    ) from reconciliation_exc
                if committed_receipt is not None:
                    verification = self.verify()
                    if not verification["valid"]:
                        raise RollbackError(
                            f"Rollback receipt committed but ledger verification failed; filesystem remains rolled back and recovery retained at {recovery_path}",
                            500,
                        ) from receipt_exc
                    receipt = committed_receipt
                else:
                    try:
                        target_text, _, _ = self._read_regular_text_at(
                            parent_fd, target_name
                        )
                    except (OSError, UnicodeDecodeError):
                        target_text = None
                    if target_text == restored_text:
                        try:
                            exchange_entries()
                            compensated_displaced, _, _ = self._read_regular_text_at(
                                recovery_fd, temp_name
                            )
                        except (OSError, UnicodeDecodeError) as recovery_exc:
                            raise RollbackError(
                                f"Receipt persistence and compensation failed; recovery retained at {recovery_path}",
                                500,
                            ) from recovery_exc
                        if compensated_displaced != restored_text:
                            raise RollbackError(
                                f"Receipt persistence failed while a concurrent edit arrived; retained at {recovery_path}",
                                500,
                            ) from receipt_exc
                    raise RollbackError(
                        f"Rollback receipt persistence failed; recovery content retained at {recovery_path}",
                        500,
                    ) from receipt_exc
        finally:
            if recovery_fd is not None:
                if temp_name is not None and not preserve_temp:
                    try:
                        os.unlink(temp_name, dir_fd=recovery_fd)
                    except FileNotFoundError:
                        pass
                os.close(recovery_fd)
            if recovery_dir_name is not None and not preserve_temp:
                try:
                    os.rmdir(recovery_dir_name, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            os.close(parent_fd)
            os.close(root_fd)

        if receipt is None or recovery_path is None:
            raise RollbackError("Rollback did not produce a receipt", 500)
        return {
            "status": "rolled_back",
            "event_id": event_id,
            "rollback_receipt_id": receipt["id"],
            "displaced_path": str(recovery_path),
        }

    # --- Rollback of created and deleted files ------------------------------------

    def _open_rollback_parent(
        self,
        row: sqlite3.Row,
        workspace: Path,
        workspace_identity: tuple[int, int] | None,
        workspace_fd: int | None,
    ) -> tuple[tuple[str, ...], int, int, os.stat_result]:
        parts = self._target_parts(row["target"])
        root_fd, parent_fd = self._open_parent_at_workspace(
            workspace, parts, workspace_fd
        )
        root_identity = os.fstat(root_fd)
        if (
            workspace_identity is not None
            and (root_identity.st_dev, root_identity.st_ino) != workspace_identity
        ):
            os.close(parent_fd)
            os.close(root_fd)
            raise RollbackError(
                "Configured workspace identity changed; refusing rollback", 409
            )
        return parts, root_fd, parent_fd, root_identity

    def _record_rollback(
        self, payload: dict[str, Any], operation_id: str, state: str
    ) -> tuple[dict[str, Any] | None, BaseException | None]:
        """Append a rollback receipt, reconciling a failure raised after commit.

        Returns ``(receipt, None)`` when the receipt is in the ledger and
        ``(None, cause)`` when it is known to be absent.
        """
        try:
            return self.append(payload), None
        except BaseException as receipt_exc:
            try:
                committed = self._find_rollback_operation(operation_id)
            except BaseException as reconciliation_exc:
                raise RollbackError(
                    f"Rollback receipt outcome is uncertain; {state}", 500
                ) from reconciliation_exc
            if committed is None:
                return None, receipt_exc
            if not self.verify()["valid"]:
                raise RollbackError(
                    f"Rollback receipt committed but ledger verification failed; {state}",
                    500,
                ) from receipt_exc
            return committed, None

    @staticmethod
    def _recorded_mode(row: sqlite3.Row) -> int:
        """Permission bits an integration recorded for a deleted file, else 0600."""
        try:
            metadata = json.loads(row["metadata_json"])
        except (TypeError, ValueError):
            return 0o600
        value = metadata.get("mode") if isinstance(metadata, dict) else None
        if type(value) is int and 0 <= value <= 0o7777:
            return value & 0o777
        if isinstance(value, str) and re.fullmatch(r"(?:0o?)?[0-7]{3,4}", value):
            return int(value.removeprefix("0o"), 8) & 0o777
        return 0o600

    def _rollback_create(
        self,
        row: sqlite3.Row,
        event_id: int,
        workspace: Path,
        workspace_identity: tuple[int, int] | None,
        workspace_fd: int | None,
    ) -> dict[str, Any]:
        """Undo a file creation by moving the file into a private recovery directory.

        The file is never unlinked: it is moved with a no-replace rename, so the
        content stays recoverable and late writers keep a linked inode.
        """
        operation_id = secrets.token_hex(16)
        parts, root_fd, parent_fd, root_identity = self._open_rollback_parent(
            row, workspace, workspace_identity, workspace_fd
        )
        target_name = parts[-1]
        retained_name = f".{target_name}.glassbox-removed-{secrets.token_hex(8)}.tmp"
        recovery_dir_name: str | None = None
        recovery_fd: int | None = None
        try:
            parent_identity = os.fstat(parent_fd)
            try:
                current_text, target_identity, _ = self._read_regular_text_at(
                    parent_fd, target_name
                )
            except (OSError, UnicodeDecodeError) as exc:
                raise RollbackError(
                    "Rollback target must be an existing UTF-8 regular file", 409
                ) from exc
            if self._digest(current_text) != row["after_sha256"]:
                raise RollbackError(
                    "Target changed after this receipt; refusing to remove newer work",
                    409,
                )
            recovery_dir_name, recovery_fd = self._create_private_recovery_dir(
                parent_fd, target_name
            )
            recovery_path = self._entry_path(recovery_fd, retained_name)
            if not self._parent_is_current(
                workspace, parts, root_identity, parent_identity, workspace_fd
            ):
                raise RollbackError(
                    "Rollback target parent changed while preparing the removal", 409
                )
            try:
                latest_text, latest_identity, _ = self._read_regular_text_at(
                    parent_fd, target_name
                )
            except (OSError, UnicodeDecodeError) as exc:
                raise RollbackError(
                    "Rollback target entry changed while preparing the removal", 409
                ) from exc
            if (
                not self._same_identity(latest_identity, target_identity)
                or self._digest(latest_text) != row["after_sha256"]
            ):
                raise RollbackError(
                    "Target changed while preparing the removal; refusing to remove newer work",
                    409,
                )
            try:
                _move_without_replacing(
                    target_name,
                    retained_name,
                    first_dir_fd=parent_fd,
                    second_dir_fd=recovery_fd,
                )
            except OSError as exc:
                raise RollbackError(
                    "Filesystem does not support safe atomic rollback move", 409
                ) from exc

            def put_back(
                reason: str, status_code: int, cause: BaseException | None = None
            ) -> NoReturn:
                assert recovery_fd is not None
                try:
                    _move_without_replacing(
                        retained_name,
                        target_name,
                        first_dir_fd=recovery_fd,
                        second_dir_fd=parent_fd,
                    )
                except BaseException as recovery_exc:
                    raise RollbackError(
                        f"{reason}; the file could not be put back and was retained at {recovery_path}",
                        500,
                    ) from recovery_exc
                raise RollbackError(
                    f"{reason}; the file was put back", status_code
                ) from cause

            try:
                displaced_text, displaced_identity, _ = self._read_regular_text_at(
                    recovery_fd, retained_name
                )
                parent_is_current = self._parent_is_current(
                    workspace, parts, root_identity, parent_identity, workspace_fd
                )
            except BaseException as exc:  # noqa: BLE001 - compensate asynchronous failures
                put_back("Rollback validation failed after the atomic move", 409, exc)
            if (
                not self._same_identity(displaced_identity, target_identity)
                or self._digest(displaced_text) != row["after_sha256"]
            ):
                put_back("Target changed at the atomic move", 409)
            if not parent_is_current:
                put_back("Rollback target parent changed at the atomic move", 409)

            receipt, failure = self._record_rollback(
                {
                    "agent": INTERNAL_AGENT,
                    "action": ROLLBACK_ACTION,
                    "target": row["target"],
                    "summary": f"Rolled back receipt #{event_id}: removed the created file",
                    "before_text": displaced_text,
                    "after_text": None,
                    "metadata": {
                        "rolled_back_event_id": event_id,
                        "rollback_operation_id": operation_id,
                        "rollback_kind": "remove_created_file",
                        "displaced_path": str(recovery_path),
                    },
                },
                operation_id,
                f"the created file remains removed and was retained at {recovery_path}",
            )
            if receipt is None:
                put_back("Rollback receipt persistence failed", 500, failure)
        finally:
            if recovery_fd is not None:
                os.close(recovery_fd)
            if recovery_dir_name is not None:
                try:
                    # Succeeds only while the directory is empty; a retained
                    # file is never deleted here.
                    os.rmdir(recovery_dir_name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)
            os.close(root_fd)
        return {
            "status": "rolled_back",
            "event_id": event_id,
            "rollback_receipt_id": receipt["id"],
            "displaced_path": str(recovery_path),
        }

    def _rollback_delete(
        self,
        row: sqlite3.Row,
        event_id: int,
        restored_text: str,
        workspace: Path,
        workspace_identity: tuple[int, int] | None,
        workspace_fd: int | None,
    ) -> dict[str, Any]:
        """Undo a file deletion by recreating it, only where nothing exists now."""
        operation_id = secrets.token_hex(16)
        parts, root_fd, parent_fd, root_identity = self._open_rollback_parent(
            row, workspace, workspace_identity, workspace_fd
        )
        target_name = parts[-1]
        mode = self._recorded_mode(row)
        recovery_dir_name: str | None = None
        recovery_fd: int | None = None
        temp_name: str | None = None
        moved = False
        try:
            parent_identity = os.fstat(parent_fd)
            try:
                os.stat(target_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RollbackError(
                    "Target exists; refusing to overwrite newer work", 409
                )
            recovery_dir_name, recovery_fd = self._create_private_recovery_dir(
                parent_fd, target_name
            )
            temp_name = self._write_temp_text_at(
                recovery_fd, target_name, restored_text, mode, label="restore"
            )
            recovery_path = self._entry_path(recovery_fd, temp_name)
            restored_path = self._entry_path(parent_fd, target_name)
            try:
                candidate_text, candidate_identity, _ = self._read_regular_text_at(
                    recovery_fd, temp_name
                )
            except (OSError, UnicodeDecodeError) as exc:
                raise RollbackError(
                    "Rollback restore candidate changed while preparing the restore",
                    409,
                ) from exc
            if (
                candidate_text != restored_text
                or stat.S_IMODE(candidate_identity.st_mode) != mode
            ):
                raise RollbackError(
                    "Rollback restore candidate failed identity or access-policy validation",
                    409,
                )
            if not self._parent_is_current(
                workspace, parts, root_identity, parent_identity, workspace_fd
            ):
                raise RollbackError(
                    "Rollback target parent changed while preparing the restore", 409
                )
            moved = True
            try:
                _move_without_replacing(
                    temp_name,
                    target_name,
                    first_dir_fd=recovery_fd,
                    second_dir_fd=parent_fd,
                )
            except FileExistsError as exc:
                moved = False
                raise RollbackError(
                    "Target appeared while preparing the restore; refusing to overwrite newer work",
                    409,
                ) from exc
            except OSError as exc:
                moved = False
                raise RollbackError(
                    "Filesystem does not support safe atomic rollback move", 409
                ) from exc

            def withdraw(
                reason: str, status_code: int, cause: BaseException | None = None
            ) -> NoReturn:
                assert recovery_fd is not None and temp_name is not None
                try:
                    installed = os.stat(
                        target_name, dir_fd=parent_fd, follow_symlinks=False
                    )
                    if not self._same_identity(installed, candidate_identity):
                        raise OSError(errno.ESTALE, "Restored entry was replaced")
                    _move_without_replacing(
                        target_name,
                        temp_name,
                        first_dir_fd=parent_fd,
                        second_dir_fd=recovery_fd,
                    )
                except BaseException as recovery_exc:
                    raise RollbackError(
                        f"{reason}; the restored file could not be withdrawn and remains at {restored_path}",
                        500,
                    ) from recovery_exc
                raise RollbackError(
                    f"{reason}; the restored file was withdrawn to {recovery_path}",
                    status_code,
                ) from cause

            try:
                installed_text, installed_identity, _ = self._read_regular_text_at(
                    parent_fd, target_name
                )
                parent_is_current = self._parent_is_current(
                    workspace, parts, root_identity, parent_identity, workspace_fd
                )
            except BaseException as exc:  # noqa: BLE001 - compensate asynchronous failures
                withdraw("Rollback validation failed after the atomic move", 409, exc)
            if (
                not self._same_identity(installed_identity, candidate_identity)
                or installed_text != restored_text
            ):
                withdraw("Restored file changed at the atomic move", 409)
            if not parent_is_current:
                withdraw("Rollback target parent changed at the atomic move", 409)

            receipt, failure = self._record_rollback(
                {
                    "agent": INTERNAL_AGENT,
                    "action": ROLLBACK_ACTION,
                    "target": row["target"],
                    "summary": f"Rolled back receipt #{event_id}: restored the deleted file",
                    "before_text": None,
                    "after_text": restored_text,
                    "metadata": {
                        "rolled_back_event_id": event_id,
                        "rollback_operation_id": operation_id,
                        "rollback_kind": "restore_deleted_file",
                    },
                },
                operation_id,
                f"the restored file remains at {restored_path}",
            )
            if receipt is None:
                withdraw("Rollback receipt persistence failed", 500, failure)
        finally:
            if recovery_fd is not None:
                if temp_name is not None and not moved:
                    try:
                        os.unlink(temp_name, dir_fd=recovery_fd)
                    except FileNotFoundError:
                        pass
                os.close(recovery_fd)
            if recovery_dir_name is not None:
                try:
                    os.rmdir(recovery_dir_name, dir_fd=parent_fd)
                except OSError:
                    pass
            os.close(parent_fd)
            os.close(root_fd)
        return {
            "status": "rolled_back",
            "event_id": event_id,
            "rollback_receipt_id": receipt["id"],
            "displaced_path": None,
            "restored_path": str(restored_path),
        }

    # --- Reading ------------------------------------------------------------------

    @staticmethod
    def _internal_state(rows: Any) -> tuple[set[int], dict[int, int]]:
        """Derive pruned and rolled-back receipt IDs from Glassbox's own receipts."""
        pruned: set[int] = set()
        rolled_back: dict[int, int] = {}
        for row in rows:
            if row["agent"] != INTERNAL_AGENT:
                continue
            try:
                metadata = json.loads(row["metadata_json"])
            except (TypeError, ValueError):
                continue
            if not isinstance(metadata, dict):
                continue
            receipt_id = row["id"]
            if row["action"] == PRUNE_ACTION:
                identifiers = metadata.get("pruned_event_ids")
                if isinstance(identifiers, list):
                    pruned.update(
                        value
                        for value in identifiers
                        if type(value) is int and value < receipt_id
                    )
            elif row["action"] == ROLLBACK_ACTION:
                original = metadata.get("rolled_back_event_id")
                if type(original) is int and original < receipt_id:
                    rolled_back[original] = receipt_id
        return pruned, rolled_back

    def _load_internal_state(
        self, conn: sqlite3.Connection
    ) -> tuple[set[int], dict[int, int]]:
        """Read internal receipts and expose them to SQL as temporary tables.

        ``conn`` is a private in-memory copy of the ledger, so the temporary
        tables never reach the published database.
        """
        rows = conn.execute(
            "SELECT id, agent, action, metadata_json FROM events "
            "WHERE agent = ? AND action IN (?, ?) ORDER BY id",
            (INTERNAL_AGENT, PRUNE_ACTION, ROLLBACK_ACTION),
        ).fetchall()
        pruned, rolled_back = self._internal_state(rows)
        conn.execute("CREATE TEMP TABLE pruned_events (id INTEGER PRIMARY KEY)")
        conn.execute("CREATE TEMP TABLE rolled_back_events (id INTEGER PRIMARY KEY)")
        conn.executemany(
            "INSERT INTO pruned_events VALUES (?)", [(value,) for value in pruned]
        )
        conn.executemany(
            "INSERT INTO rolled_back_events VALUES (?)",
            [(value,) for value in rolled_back],
        )
        return pruned, rolled_back

    _EFFECTIVELY_REVERSIBLE = (
        "(reversible = 1 "
        "AND id NOT IN (SELECT id FROM rolled_back_events) "
        "AND NOT (snapshot_sha256 IS NOT NULL "
        "AND id IN (SELECT id FROM pruned_events)))"
    )

    @staticmethod
    def _public_event(
        row: sqlite3.Row, pruned: set[int], rolled_back: dict[int, int]
    ) -> dict[str, Any]:
        try:
            metadata = json.loads(row["metadata_json"])
        except (TypeError, ValueError):
            metadata = {}
        event_id = row["id"]
        is_pruned = event_id in pruned
        has_snapshot = row["snapshot_sha256"] is not None
        return {
            "id": event_id,
            "created_at": row["created_at"],
            "agent": row["agent"],
            "action": row["action"],
            "target": row["target"],
            "summary": row["summary"],
            "metadata": metadata,
            "before_sha256": row["before_sha256"],
            "after_sha256": row["after_sha256"],
            "risk": row["risk"],
            "risk_reason": row["risk_reason"],
            "reversible": bool(row["reversible"])
            and event_id not in rolled_back
            and not (is_pruned and has_snapshot),
            "rolled_back_by": rolled_back.get(event_id),
            "snapshot_pruned": is_pruned
            and (has_snapshot or row["diff_sha256"] is not None),
            "has_diff": not is_pruned
            and (
                row["diff_sha256"] is not None
                or (row["action"] == "file.delete" and has_snapshot)
            ),
            "previous_hash": row["previous_hash"],
            "receipt_hash": row["receipt_hash"],
        }

    def page_events(
        self,
        limit: int = 100,
        *,
        before_id: int | None = None,
        risk: str | None = None,
        agent: str | None = None,
        action: str | None = None,
        session: str | None = None,
        query: str | None = None,
        reversible: bool | None = None,
    ) -> dict[str, Any]:
        """Return one newest-first page of receipts matching the filters."""
        limit = max(1, limit)
        clauses: list[str] = []
        parameters: list[Any] = []
        if risk is not None:
            clauses.append("risk = ?")
            parameters.append(risk)
        if agent is not None:
            clauses.append("agent = ?")
            parameters.append(agent)
        if action is not None:
            clauses.append("action = ?")
            parameters.append(action)
        if session is not None:
            clauses.append(
                "CASE WHEN json_valid(metadata_json) "
                "THEN json_extract(metadata_json, '$.session_id') END = ?"
            )
            parameters.append(session)
        if query:
            escaped = (
                query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            )
            clauses.append(
                "(summary LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\' "
                "OR agent LIKE ? ESCAPE '\\' OR action LIKE ? ESCAPE '\\')"
            )
            parameters.extend([f"%{escaped}%"] * 4)
        if reversible is not None:
            clauses.append(
                self._EFFECTIVELY_REVERSIBLE
                if reversible
                else f"NOT {self._EFFECTIVELY_REVERSIBLE}"
            )
        with self._connect() as conn:
            pruned, rolled_back = self._load_internal_state(conn)
            where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
            total = conn.execute(
                f"SELECT COUNT(*) FROM events{where}", parameters
            ).fetchone()[0]
            page_clauses = list(clauses)
            page_parameters = list(parameters)
            if before_id is not None:
                page_clauses.append("id < ?")
                page_parameters.append(before_id)
            page_where = f" WHERE {' AND '.join(page_clauses)}" if page_clauses else ""
            rows = conn.execute(
                f"SELECT {self._select_columns(conn)} FROM events{page_where} "
                "ORDER BY id DESC LIMIT ?",
                [*page_parameters, limit + 1],
            ).fetchall()
        has_more = len(rows) > limit
        events = [self._public_event(row, pruned, rolled_back) for row in rows[:limit]]
        return {
            "events": events,
            "total": total,
            "next_before_id": events[-1]["id"] if has_more and events else None,
        }

    def list_events(self, limit: int = 100, **filters: Any) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = self.page_events(limit, **filters)["events"]
        return events

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            pruned, rolled_back = self._load_internal_state(conn)
            row = conn.execute(
                f"SELECT {self._select_columns(conn)} FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()
        return None if row is None else self._public_event(row, pruned, rolled_back)

    def head(self) -> dict[str, Any]:
        """Latest receipt hash: store it elsewhere to detect a truncated ledger."""
        with self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            row = conn.execute(
                "SELECT id, receipt_hash, created_at FROM events "
                "ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return {
            "event_count": count,
            "head_id": row["id"] if row else None,
            "head_hash": row["receipt_hash"] if row else None,
            "head_created_at": row["created_at"] if row else None,
        }

    def stats(self) -> dict[str, Any]:
        """Whole-ledger counts for dashboards; not limited to one page."""
        with self._connect() as conn:
            self._load_internal_state(conn)
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            by_risk = {
                row[0]: row[1]
                for row in conn.execute(
                    "SELECT risk, COUNT(*) FROM events GROUP BY risk"
                )
                if isinstance(row[0], str)
            }
            reversible = conn.execute(
                f"SELECT COUNT(*) FROM events WHERE {self._EFFECTIVELY_REVERSIBLE}"
            ).fetchone()[0]
            agents = [
                {"agent": row[0], "count": row[1]}
                for row in conn.execute(
                    "SELECT agent, COUNT(*) FROM events GROUP BY agent "
                    "ORDER BY COUNT(*) DESC, agent LIMIT 100"
                )
            ]
            sessions = [
                {"session_id": row[0], "count": row[1], "last_id": row[2]}
                for row in conn.execute(
                    "SELECT session, COUNT(*), MAX(id) FROM ("
                    "SELECT id, CASE WHEN json_valid(metadata_json) "
                    "THEN json_extract(metadata_json, '$.session_id') END AS session "
                    "FROM events) WHERE typeof(session) = 'text' "
                    "GROUP BY session ORDER BY MAX(id) DESC LIMIT 100"
                )
            ]
            head = conn.execute(
                "SELECT id, receipt_hash FROM events ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return {
            "total": total,
            "high": by_risk.get("high", 0),
            "medium": by_risk.get("medium", 0),
            "low": by_risk.get("low", 0),
            "reversible": reversible,
            "agents": agents,
            "sessions": sessions,
            "head_id": head["id"] if head else None,
            "head_hash": head["receipt_hash"] if head else None,
        }

    def read_diff(self, event_id: int) -> dict[str, Any] | None:
        """Decrypt the recorded text change for one receipt.

        Returns ``None`` when the receipt does not exist. The diff is plaintext
        workspace content, so callers decide whether to expose it; common
        credential shapes are redacted before it is returned.
        """
        with self._connect() as conn:
            pruned, _ = self._load_internal_state(conn)
            row = conn.execute(
                f"SELECT {self._select_columns(conn)}, before_ciphertext "
                "FROM events WHERE id = ?",
                (event_id,),
            ).fetchone()
        if row is None:
            return None

        def unavailable(reason: str) -> dict[str, Any]:
            return {"event_id": event_id, "available": False, "reason": reason}

        if event_id in pruned:
            return unavailable("The recorded content for this receipt was pruned")
        try:
            if row["diff_sha256"] is not None:
                blob = self._read_blob(row["diff_sha256"])
                if blob is None:
                    return unavailable("The recorded diff is missing")
                diff_text = self._cipher.decrypt(blob).decode("utf-8")
            elif row["action"] == "file.delete" and row["snapshot_sha256"] is not None:
                blob = row["before_ciphertext"] or self._read_blob(
                    row["snapshot_sha256"]
                )
                if blob is None:
                    return unavailable("The recorded snapshot is missing")
                before_text = self._cipher.decrypt(bytes(blob)).decode("utf-8")
                diff_text = "".join(
                    difflib.unified_diff(
                        before_text.splitlines(keepends=True),
                        [],
                        fromfile=f"a/{row['target']}",
                        tofile="/dev/null",
                    )
                )
            else:
                return unavailable("No file content was recorded with this receipt")
        except (SnapshotError, InvalidToken, UnicodeDecodeError, TypeError):
            return unavailable("The recorded content failed its integrity check")
        added = removed = 0
        for line in diff_text.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                added += 1
            elif line.startswith("-") and not line.startswith("---"):
                removed += 1
        return {
            "event_id": event_id,
            "available": True,
            "diff": redact_text(diff_text),
            "lines_added": added,
            "lines_removed": removed,
        }

    def verify(self, *, check_snapshots: bool = True) -> dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {self._select_columns(conn)}, before_ciphertext "
                "FROM events ORDER BY id"
            ).fetchall()

        def broken(event_id: Any) -> dict[str, Any]:
            return {"valid": False, "event_count": len(rows), "broken_at": event_id}

        previous_hash = "0" * 64
        chain_break: Any = None
        verified: list[sqlite3.Row] = []
        for row in rows:
            try:
                metadata = json.loads(row["metadata_json"])
                ciphertext = row["before_ciphertext"]
                snapshot_hash = row["snapshot_sha256"]
                # Snapshots written by older versions live inside the row.
                inline_matches = ciphertext is None or (
                    snapshot_hash is not None
                    and hmac.compare_digest(
                        hashlib.sha256(ciphertext).hexdigest(), snapshot_hash
                    )
                )
                record = {
                    "created_at": row["created_at"],
                    "agent": row["agent"],
                    "action": row["action"],
                    "target": row["target"],
                    "summary": row["summary"],
                    "metadata": metadata,
                    "before_sha256": row["before_sha256"],
                    "after_sha256": row["after_sha256"],
                    "snapshot_sha256": row["snapshot_sha256"],
                    "risk": row["risk"],
                    "reversible": bool(row["reversible"]),
                    "previous_hash": row["previous_hash"],
                }
                # Fields added after 0.1 are signed only when present, so
                # receipts written before them still verify unchanged.
                if row["risk_reason"] is not None:
                    record["risk_reason"] = row["risk_reason"]
                if row["diff_sha256"] is not None:
                    record["diff_sha256"] = row["diff_sha256"]
                receipt_matches = hmac.compare_digest(
                    row["receipt_hash"], self._sign(record)
                )
            except (json.JSONDecodeError, TypeError, ValueError, OverflowError):
                chain_break = row["id"]
                break

            if (
                not inline_matches
                or row["previous_hash"] != previous_hash
                or not receipt_matches
            ):
                chain_break = row["id"]
                break
            previous_hash = row["receipt_hash"]
            verified.append(row)

        if check_snapshots:
            # A snapshot may be absent only when a signed prune receipt says so.
            pruned, _ = self._internal_state(verified)
            for row in verified:
                if row["id"] in pruned:
                    continue
                digests = [row["diff_sha256"]]
                if row["before_ciphertext"] is None:
                    digests.append(row["snapshot_sha256"])
                for digest in digests:
                    if digest is None:
                        continue
                    try:
                        present = self._read_blob(digest) is not None
                    except (SnapshotError, OSError, TypeError):
                        present = False
                    if not present:
                        return broken(row["id"])
        if chain_break is not None:
            return broken(chain_break)
        return {"valid": True, "event_count": len(rows), "broken_at": None}

    def export(self) -> dict[str, Any]:
        """Every receipt, oldest first, with the verification result and chain head."""
        events: list[dict[str, Any]] = []
        before_id: int | None = None
        while True:
            page = self.page_events(500, before_id=before_id)
            events.extend(page["events"])
            before_id = page["next_before_id"]
            if before_id is None:
                break
        events.reverse()
        return {
            "exported_at": datetime.now(UTC).isoformat(),
            "glassbox_version": __version__,
            "verification": self.verify(),
            "head": self.head(),
            "events": events,
        }

    # --- Retention ----------------------------------------------------------------

    def prune_snapshots(
        self,
        *,
        keep_last: int | None = None,
        older_than: timedelta | None = None,
    ) -> dict[str, Any]:
        """Delete stored snapshots and diffs, recording a signed prune receipt.

        Receipts themselves are never removed. A pruned receipt can no longer be
        rolled back from its snapshot or show its diff, and verification accepts
        the missing files only because the prune receipt names them.
        """
        if keep_last is None and older_than is None:
            raise ValueError("Pruning needs keep_last, older_than, or both")
        if keep_last is not None and keep_last < 0:
            raise ValueError("keep_last must not be negative")
        if not self.verify()["valid"]:
            raise RuntimeError("Receipt chain verification failed; refusing to prune")
        with self._write_lock:
            with self._connect() as conn:
                self._load_internal_state(conn)
                rows = conn.execute(
                    "SELECT id, created_at, snapshot_sha256, diff_sha256 FROM events "
                    "WHERE (snapshot_sha256 IS NOT NULL OR diff_sha256 IS NOT NULL) "
                    "AND before_ciphertext IS NULL "
                    "AND id NOT IN (SELECT id FROM pruned_events) ORDER BY id DESC"
                ).fetchall()
            candidates = rows[keep_last:] if keep_last is not None else rows
            if older_than is not None:
                cutoff = (datetime.now(UTC) - older_than).isoformat()
                candidates = [row for row in candidates if row["created_at"] < cutoff]
            candidates = sorted(candidates, key=lambda row: row["id"])
            receipt_ids: list[int] = []
            freed = 0
            for offset in range(0, len(candidates), _PRUNE_RECEIPT_CHUNK):
                chunk = candidates[offset : offset + _PRUNE_RECEIPT_CHUNK]
                identifiers = [row["id"] for row in chunk]
                # The receipt is committed first: a crash afterwards leaves
                # harmless extra files, never an unexplained missing snapshot.
                receipt = self.append(
                    {
                        "agent": INTERNAL_AGENT,
                        "action": PRUNE_ACTION,
                        "target": f"{len(identifiers)} receipts",
                        "summary": (
                            f"Pruned stored content for receipts "
                            f"#{identifiers[0]}–#{identifiers[-1]}"
                        ),
                        "metadata": {"pruned_event_ids": identifiers},
                    }
                )
                receipt_ids.append(receipt["id"])
                for row in chunk:
                    for digest in (row["snapshot_sha256"], row["diff_sha256"]):
                        if isinstance(digest, str):
                            freed += self._remove_blob(digest)
            freed += self._remove_unreferenced_blobs()
            if self._snapshot_dir_fd is not None:
                os.fsync(self._snapshot_dir_fd)
        return {
            "pruned": len(candidates),
            "bytes_freed": freed,
            "receipt_ids": receipt_ids,
        }

    def _remove_unreferenced_blobs(self) -> int:
        """Remove blobs no live receipt refers to, such as those of failed writes."""
        with self._connect() as conn:
            self._load_internal_state(conn)
            live = {
                digest
                for row in conn.execute(
                    "SELECT snapshot_sha256, diff_sha256 FROM events "
                    "WHERE id NOT IN (SELECT id FROM pruned_events)"
                )
                for digest in row
                if isinstance(digest, str)
            }
        directory_fd = self._validate_snapshot_dir()
        freed = 0
        for name in os.listdir(directory_fd):
            if _BLOB_NAME.fullmatch(name) and name not in live:
                freed += self._remove_blob(name)
        return freed
