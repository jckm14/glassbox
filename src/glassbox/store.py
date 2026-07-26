from __future__ import annotations

import base64
import ctypes
import errno
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import stat
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn

from cryptography.fernet import Fernet, InvalidToken

from .security import classify_risk, redact

_AT_FDCWD = -100
_AT_SYMLINK_FOLLOW = 0x400
_AT_EMPTY_PATH = 0x1000
_RENAME_EXCHANGE = 2


def _exchange_paths(
    first: str | Path,
    second: str | Path,
    *,
    first_dir_fd: int = _AT_FDCWD,
    second_dir_fd: int = _AT_FDCWD,
) -> None:
    """Atomically exchange two directory entries, or fail closed."""
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
        _RENAME_EXCHANGE,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


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


class EventStore:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        created = False
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
            self._initialize()
        except BaseException:
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
                    receipt_hash TEXT NOT NULL UNIQUE
                )
                """
            )

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

    def append(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._write_connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            previous = conn.execute(
                "SELECT receipt_hash FROM events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_hash = previous[0] if previous else "0" * 64
            before_text = payload.get("before_text")
            after_text = payload.get("after_text")
            before_ciphertext = (
                self._cipher.encrypt(before_text.encode("utf-8"))
                if before_text is not None
                else None
            )
            record = {
                "created_at": datetime.now(UTC).isoformat(),
                "agent": payload["agent"],
                "action": payload["action"],
                "target": payload["target"],
                "summary": redact(payload["summary"]),
                "metadata": redact(payload.get("metadata") or {}),
                "before_sha256": self._digest(before_text),
                "after_sha256": self._digest(after_text),
                "snapshot_sha256": hashlib.sha256(before_ciphertext).hexdigest()
                if before_ciphertext
                else None,
                "risk": classify_risk(payload["action"]),
                "reversible": payload["action"] == "file.write"
                and before_text is not None
                and after_text is not None,
                "previous_hash": previous_hash,
            }
            receipt_hash = self._sign(record)
            cursor = conn.execute(
                """
                INSERT INTO events (
                    created_at, agent, action, target, summary, metadata_json,
                    before_sha256, after_sha256, before_ciphertext, snapshot_sha256,
                    risk, reversible, previous_hash, receipt_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    before_ciphertext,
                    record["snapshot_sha256"],
                    record["risk"],
                    int(record["reversible"]),
                    previous_hash,
                    receipt_hash,
                ),
            )
            event_id = cursor.lastrowid
        return {"id": event_id, **record, "receipt_hash": receipt_hash}

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

    def rollback(
        self,
        event_id: int,
        workspace: Path,
        workspace_identity: tuple[int, int] | None = None,
        workspace_fd: int | None = None,
    ) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM events WHERE id = ?", (event_id,)
            ).fetchone()
        if row is None:
            raise RollbackError("Event not found", 404)
        verification = self.verify()
        if not verification["valid"]:
            raise RollbackError(
                "Receipt chain verification failed; refusing rollback", 409
            )
        if (
            row["action"] != "file.write"
            or not row["reversible"]
            or row["before_ciphertext"] is None
        ):
            raise RollbackError("This event has no reversible file snapshot", 409)

        ciphertext = row["before_ciphertext"]
        if hashlib.sha256(ciphertext).hexdigest() != row["snapshot_sha256"]:
            raise RollbackError(
                "Encrypted rollback snapshot failed integrity verification", 409
            )
        try:
            restored_text = self._cipher.decrypt(ciphertext).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise RollbackError(
                "Encrypted rollback snapshot cannot be decrypted", 409
            ) from exc

        rollback_operation_id = secrets.token_hex(16)
        workspace = Path(workspace)
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

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [
            {
                "id": row["id"],
                "created_at": row["created_at"],
                "agent": row["agent"],
                "action": row["action"],
                "target": row["target"],
                "summary": row["summary"],
                "metadata": json.loads(row["metadata_json"]),
                "before_sha256": row["before_sha256"],
                "after_sha256": row["after_sha256"],
                "risk": row["risk"],
                "reversible": bool(row["reversible"]),
                "previous_hash": row["previous_hash"],
                "receipt_hash": row["receipt_hash"],
            }
            for row in rows
        ]

    def verify(self) -> dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY id").fetchall()
        previous_hash = "0" * 64
        for row in rows:
            broken = {
                "valid": False,
                "event_count": len(rows),
                "broken_at": row["id"],
            }
            try:
                metadata = json.loads(row["metadata_json"])
                ciphertext = row["before_ciphertext"]
                snapshot_hash = row["snapshot_sha256"]
                snapshot_matches = (ciphertext is None and snapshot_hash is None) or (
                    ciphertext is not None
                    and snapshot_hash is not None
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
                receipt_matches = hmac.compare_digest(
                    row["receipt_hash"], self._sign(record)
                )
            except (json.JSONDecodeError, TypeError, ValueError, OverflowError):
                return broken

            if (
                not snapshot_matches
                or row["previous_hash"] != previous_hash
                or not receipt_matches
            ):
                return broken
            previous_hash = row["receipt_hash"]
        return {"valid": True, "event_count": len(rows), "broken_at": None}
