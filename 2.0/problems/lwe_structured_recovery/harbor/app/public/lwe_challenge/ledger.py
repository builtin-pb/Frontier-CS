"""Canonical cumulative witness-ledger helpers."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Sequence

from .strict_json import loads_object


MAX_LEDGER_RECORDS = 200
MAX_LEDGER_BYTES = 2_000_000
MAX_LEDGER_NODES = 1_000_005
MAX_SECRET_ABS = 2**63 - 1
_INSTANCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class LedgerContractError(ValueError):
    """A decoded cumulative ledger violates its public contract."""


@dataclass(frozen=True, slots=True)
class Ledger:
    schema_version: int
    solutions: Mapping[str, tuple[int, ...]]

    def __post_init__(self) -> None:
        copied = {
            instance_id: tuple(secret)
            for instance_id, secret in self.solutions.items()
        }
        object.__setattr__(
            self,
            "solutions",
            MappingProxyType(dict(sorted(copied.items()))),
        )


@contextmanager
def ledger_lock(path: str | Path) -> Iterator[None]:
    """Hold the stable sibling lock for a complete ledger transaction."""

    ledger_path = Path(path)
    lock_path = ledger_path.with_name(f"{ledger_path.name}.lock")
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("platform cannot safely open the ledger lock")
    descriptor = os.open(
        lock_path,
        os.O_RDWR
        | os.O_CREAT
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
        0o600,
    )
    locked = False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LedgerContractError("ledger lock must be a regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        locked = True
        yield
    finally:
        try:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _validate_instance_id(instance_id: object) -> str:
    if (
        not isinstance(instance_id, str)
        or _INSTANCE_ID.fullmatch(instance_id) is None
    ):
        raise ValueError("invalid instance ID")
    return instance_id


def _normalize_secret(secret: Sequence[int]) -> tuple[int, ...]:
    try:
        candidate = tuple(secret)
    except TypeError as exc:
        raise ValueError("invalid secret") from exc
    if any(
        type(value) is not int or abs(value) > MAX_SECRET_ABS
        for value in candidate
    ):
        raise ValueError("invalid secret")
    return candidate


def _open_regular_readonly(path: Path) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise OSError("platform cannot safely open a ledger")
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise LedgerContractError("ledger must be a regular file")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _open_parent_directory(path: Path) -> int:
    required_flags = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required_flags):
        raise OSError("platform cannot safely open the ledger directory")
    descriptor = os.open(
        path.parent,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise LedgerContractError("ledger parent must be a directory")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def load_ledger(path: str | Path) -> Ledger:
    ledger_path = Path(path)
    descriptor = _open_regular_readonly(ledger_path)
    with os.fdopen(descriptor, "rb") as handle:
        data = handle.read(MAX_LEDGER_BYTES + 1)
    document = loads_object(
        data,
        max_bytes=MAX_LEDGER_BYTES,
        max_depth=4,
        max_nodes=MAX_LEDGER_NODES,
    )
    if set(document) != {"schema_version", "solutions"}:
        raise LedgerContractError("invalid ledger fields")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
    ):
        raise LedgerContractError("ledger schema_version must be integer 1")
    raw_solutions = document["solutions"]
    if not isinstance(raw_solutions, list):
        raise LedgerContractError("ledger solutions must be a JSON array")
    if len(raw_solutions) > MAX_LEDGER_RECORDS:
        raise LedgerContractError("ledger has too many solution records")

    solutions: dict[str, tuple[int, ...]] = {}
    for raw_record in raw_solutions:
        if not isinstance(raw_record, dict) or set(raw_record) != {
            "instance_id",
            "secret",
        }:
            raise LedgerContractError("invalid ledger solution record")
        try:
            instance_id = _validate_instance_id(raw_record["instance_id"])
        except ValueError as exc:
            raise LedgerContractError("invalid ledger instance ID") from exc
        if instance_id in solutions:
            raise LedgerContractError("repeated ledger instance ID")
        raw_secret = raw_record["secret"]
        if not isinstance(raw_secret, list):
            raise LedgerContractError("invalid ledger secret")
        try:
            solutions[instance_id] = _normalize_secret(raw_secret)
        except ValueError as exc:
            raise LedgerContractError("invalid ledger secret") from exc

    return Ledger(schema_version=1, solutions=solutions)


def _canonical_bytes(ledger: Ledger) -> bytes:
    if type(ledger.schema_version) is not int or ledger.schema_version != 1:
        raise LedgerContractError("ledger schema_version must be integer 1")
    if not isinstance(ledger.solutions, Mapping):
        raise LedgerContractError("invalid ledger solutions")
    if len(ledger.solutions) > MAX_LEDGER_RECORDS:
        raise LedgerContractError("ledger has too many solution records")

    normalized: list[tuple[str, tuple[int, ...]]] = []
    for raw_instance_id, raw_secret in ledger.solutions.items():
        try:
            instance_id = _validate_instance_id(raw_instance_id)
            secret = _normalize_secret(raw_secret)
        except (TypeError, ValueError) as exc:
            raise LedgerContractError("invalid ledger solution record") from exc
        normalized.append((instance_id, secret))
    normalized.sort(key=lambda item: item[0])
    document = {
        "schema_version": 1,
        "solutions": [
            {"instance_id": instance_id, "secret": list(secret)}
            for instance_id, secret in normalized
        ],
    }
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8") + b"\n"
    if len(encoded) > MAX_LEDGER_BYTES:
        raise LedgerContractError("ledger exceeds byte limit")
    return encoded


def _restore_foreign_temp(
    quarantine_fd: int, temporary_path: str
) -> None:
    """Restore without replacing a path that appeared during quarantine.

    Hard-link creation fails when ``temporary_path`` has been reoccupied. The
    source lookup stays relative to the traversal-isolated inner directory.
    The quarantine link is deliberately retained even after restoration: if
    the exposed link disappears concurrently, the foreign inode must remain
    reachable as durable preservation evidence.
    """

    try:
        os.link(
            "entry",
            temporary_path,
            src_dir_fd=quarantine_fd,
            follow_symlinks=False,
        )
    except OSError:
        return


def _restore_foreign_directory(
    quarantine: "_Quarantine", temporary_path: str
) -> None:
    """Expose a no-clobber symlink while retaining the directory in quarantine."""

    quarantined_path = quarantine.directory / "private" / "entry"
    target = os.path.relpath(
        quarantined_path,
        start=Path(temporary_path).parent,
    )
    try:
        os.symlink(target, temporary_path)
    except OSError:
        return


@dataclass(slots=True)
class _Quarantine:
    directory: Path
    outer_fd: int
    inner_fd: int
    traversal_available: bool = True


def _prepare_quarantine(destination: Path, parent_fd: int) -> _Quarantine:
    """Create and open the private cleanup namespace before any temp file."""

    required_flags = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required_flags):
        raise OSError("platform cannot safely prepare ledger cleanup")
    quarantine_directory = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.quarantine.",
            dir=destination.parent,
        )
    )
    outer_fd: int | None = None
    inner_fd: int | None = None
    prepared = False
    try:
        directory_flags = (
            os.O_RDONLY
            | os.O_DIRECTORY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        outer_fd = os.open(
            quarantine_directory.name,
            directory_flags,
            dir_fd=parent_fd,
        )
        outer = os.fstat(outer_fd)
        if (
            not stat.S_ISDIR(outer.st_mode)
            or stat.S_IMODE(outer.st_mode) != 0o700
        ):
            raise OSError("ledger quarantine outer directory is not private")
        os.mkdir("private", mode=0o700, dir_fd=outer_fd)
        inner_fd = os.open("private", directory_flags, dir_fd=outer_fd)
        inner = os.fstat(inner_fd)
        if (
            not stat.S_ISDIR(inner.st_mode)
            or stat.S_IMODE(inner.st_mode) != 0o700
        ):
            raise OSError("ledger quarantine inner directory is not private")
        quarantine = _Quarantine(
            directory=quarantine_directory,
            outer_fd=outer_fd,
            inner_fd=inner_fd,
        )
        outer_fd = None
        inner_fd = None
        prepared = True
        return quarantine
    finally:
        if inner_fd is not None:
            try:
                os.close(inner_fd)
            except OSError:
                pass
        if outer_fd is not None:
            try:
                os.close(outer_fd)
            except OSError:
                pass
        if not prepared:
            try:
                os.rmdir(quarantine_directory / "private")
            except OSError:
                pass
            try:
                os.rmdir(quarantine_directory)
            except OSError:
                pass


def _close_quarantine(quarantine: _Quarantine) -> None:
    if not quarantine.traversal_available:
        try:
            os.fchmod(quarantine.outer_fd, 0o700)
            quarantine.traversal_available = True
        except OSError:
            pass
    try:
        os.close(quarantine.inner_fd)
    except OSError:
        pass
    try:
        os.close(quarantine.outer_fd)
    except OSError:
        pass
    if quarantine.traversal_available:
        try:
            os.rmdir(quarantine.directory / "private")
        except OSError:
            pass
        try:
            os.rmdir(quarantine.directory)
        except OSError:
            pass


def _quarantine_owned_temp(
    quarantine: _Quarantine,
    temporary_path: str,
    identity: tuple[int, int] | None,
) -> None:
    """Remove only the created inode after atomically isolating the path entry.

    ``mkdtemp`` supplies a unique mode-0700 sibling outer directory containing
    another mode-0700 directory held open by descriptor. A same-filesystem POSIX
    rename moves the exposed path entry into the inner directory atomically. The
    outer directory is then chmodded to mode 000, revoking pathname traversal,
    while descriptor-relative operations on the still-permitted inner directory
    remain usable. The moved entry is opened with ``O_NOFOLLOW`` and checked via
    ``fstat``; only that matching regular inode is unlinked through the inner
    directory descriptor. A foreign regular inode is restored with a no-clobber
    hard link when possible, while its quarantine link is always retained.

    This portable boundary excludes a process that already holds the freshly
    created inner directory descriptor or can change quarantine permissions.
    It prevents ordinary pathname races on both macOS and the Linux judge
    without relying on platform-specific conditional-unlink operations.
    """

    try:
        os.rename(temporary_path, "entry", dst_dir_fd=quarantine.inner_fd)
    except OSError:
        return
    if identity is None:
        return
    entry_fd: int | None = None
    try:
        try:
            os.fchmod(quarantine.outer_fd, 0)
        except OSError:
            return
        quarantine.traversal_available = False
        try:
            entry_metadata = os.stat(
                "entry",
                dir_fd=quarantine.inner_fd,
                follow_symlinks=False,
            )
        except OSError:
            return
        if stat.S_ISDIR(entry_metadata.st_mode):
            _restore_foreign_directory(quarantine, temporary_path)
            return
        if not stat.S_ISREG(entry_metadata.st_mode):
            _restore_foreign_temp(quarantine.inner_fd, temporary_path)
            return
        try:
            entry_flags = (
                os.O_RDONLY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            entry_fd = os.open(
                "entry", entry_flags, dir_fd=quarantine.inner_fd
            )
            quarantined = os.fstat(entry_fd)
        except OSError:
            return
        if (
            (quarantined.st_dev, quarantined.st_ino) == identity
            and stat.S_ISREG(quarantined.st_mode)
        ):
            try:
                os.unlink("entry", dir_fd=quarantine.inner_fd)
            except OSError:
                return
        elif stat.S_ISREG(quarantined.st_mode):
            _restore_foreign_temp(quarantine.inner_fd, temporary_path)
    finally:
        if entry_fd is not None:
            try:
                os.close(entry_fd)
            except OSError:
                pass


def write_ledger_atomic(path: str | Path, ledger: Ledger) -> None:
    destination = Path(path)
    data = _canonical_bytes(ledger)
    try:
        destination_fd = _open_regular_readonly(destination)
    except FileNotFoundError:
        pass
    else:
        os.close(destination_fd)
    parent_fd = _open_parent_directory(destination)
    quarantine: _Quarantine | None = None
    temporary_path: str | None = None
    temporary_fd: int | None = None
    temporary_identity: tuple[int, int] | None = None
    try:
        quarantine = _prepare_quarantine(destination, parent_fd)
        temporary_fd, temporary_path = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        created = os.fstat(temporary_fd)
        temporary_identity = (created.st_dev, created.st_ino)
        with os.fdopen(temporary_fd, "wb") as handle:
            temporary_fd = None
            data_view = memoryview(data)
            offset = 0
            while offset < len(data_view):
                written = handle.write(data_view[offset:])
                remaining = len(data_view) - offset
                if (
                    type(written) is not int
                    or written <= 0
                    or written > remaining
                ):
                    raise OSError("unable to write complete ledger")
                offset += written
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
        os.fsync(parent_fd)
    except BaseException:
        if temporary_fd is not None:
            try:
                os.close(temporary_fd)
            except OSError:
                pass
        if temporary_path is not None and quarantine is not None:
            _quarantine_owned_temp(
                quarantine,
                temporary_path,
                temporary_identity,
            )
        raise
    finally:
        if quarantine is not None:
            _close_quarantine(quarantine)
        try:
            os.close(parent_fd)
        except OSError:
            pass


def merge_witness(
    ledger: Ledger,
    *,
    instance_id: str,
    secret: Sequence[int],
    replace: bool = False,
) -> Ledger:
    instance_id = _validate_instance_id(instance_id)
    candidate = _normalize_secret(secret)
    if not replace and ledger.solutions.get(instance_id) == candidate:
        return ledger
    if not replace and instance_id in ledger.solutions:
        raise ValueError("instance already has a different witness")
    if (
        instance_id not in ledger.solutions
        and len(ledger.solutions) >= MAX_LEDGER_RECORDS
    ):
        raise ValueError("ledger may contain at most 200 witnesses")
    solutions = dict(ledger.solutions)
    solutions[instance_id] = candidate
    return Ledger(schema_version=ledger.schema_version, solutions=solutions)
