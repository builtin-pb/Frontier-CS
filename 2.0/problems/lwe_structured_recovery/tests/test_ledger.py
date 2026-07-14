import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

import lwe_challenge.ledger as ledger_module
from lwe_challenge.ledger import (
    Ledger,
    LedgerContractError,
    ledger_lock,
    load_ledger,
    merge_witness,
    write_ledger_atomic,
)


def _run_add_solution(
    task_dir: Path, path: Path, *arguments: str
) -> subprocess.CompletedProcess[str]:
    script = task_dir / "harbor" / "app" / "add_solution.py"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(task_dir / "harbor" / "app" / "public")
    return subprocess.run(
        [
            sys.executable,
            str(script),
            "--ledger",
            str(path),
            *arguments,
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=10,
    )


def _start_add_solution(
    task_dir: Path, path: Path, *arguments: str
) -> subprocess.Popen[str]:
    script = task_dir / "harbor" / "app" / "add_solution.py"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(task_dir / "harbor" / "app" / "public")
    return subprocess.Popen(
        [
            sys.executable,
            str(script),
            "--ledger",
            str(path),
            *arguments,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def test_identical_merge_is_idempotent() -> None:
    ledger = Ledger(schema_version=1, solutions={"a": (1, 0)})

    merged = merge_witness(
        ledger, instance_id="a", secret=(1, 0), replace=False
    )

    assert merged is ledger


def test_ledger_lock_uses_persistent_regular_sibling(tmp_path: Path) -> None:
    path = tmp_path / "solution.json"
    lock_path = tmp_path / "solution.json.lock"

    with ledger_lock(path):
        metadata = lock_path.stat(follow_symlinks=False)
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o600

    assert lock_path.exists()


def test_ledger_lock_rejects_symlink_lock_file(tmp_path: Path) -> None:
    path = tmp_path / "solution.json"
    target = tmp_path / "lock-target"
    target.write_bytes(b"unchanged")
    lock_path = tmp_path / "solution.json.lock"
    lock_path.symlink_to(target)

    with pytest.raises(OSError):
        with ledger_lock(path):
            raise AssertionError("symlink lock unexpectedly acquired")

    assert lock_path.is_symlink()
    assert target.read_bytes() == b"unchanged"


def test_ledger_constructor_copies_sorts_and_freezes_input() -> None:
    source = {"z": [2], "a": [1, 0]}

    ledger = Ledger(schema_version=1, solutions=source)
    source["a"][0] = 9
    source["new"] = [3]

    assert tuple(ledger.solutions) == ("a", "z")
    assert ledger.solutions["a"] == (1, 0)
    assert "new" not in ledger.solutions
    with pytest.raises(TypeError):
        ledger.solutions["a"] = (9,)


def test_conflicting_merge_is_refused_without_replace() -> None:
    ledger = Ledger(schema_version=1, solutions={"a": (1, 0)})

    with pytest.raises(ValueError, match="already has a different witness"):
        merge_witness(
            ledger, instance_id="a", secret=(0, 1), replace=False
        )


def test_explicit_replacement_does_not_mutate_input() -> None:
    ledger = Ledger(schema_version=1, solutions={"a": (1, 0)})

    merged = merge_witness(
        ledger, instance_id="a", secret=(0, 1), replace=True
    )

    assert dict(ledger.solutions) == {"a": (1, 0)}
    assert dict(merged.solutions) == {"a": (0, 1)}


def test_new_merge_is_sorted_and_deeply_immutable() -> None:
    ledger = Ledger(schema_version=1, solutions={"z": (2,)})

    merged = merge_witness(
        ledger, instance_id="a", secret=[1, 0], replace=False
    )

    assert tuple(merged.solutions) == ("a", "z")
    assert merged.solutions["a"] == (1, 0)
    with pytest.raises(TypeError):
        merged.solutions["a"] = (9,)


def test_merge_refuses_to_exceed_protocol_record_cap() -> None:
    ledger = Ledger(
        schema_version=1,
        solutions={f"a{index:03d}": () for index in range(200)},
    )

    with pytest.raises(ValueError, match="at most 200"):
        merge_witness(ledger, instance_id="new", secret=())


@pytest.mark.parametrize(
    "instance_id", ["", "_leading", "contains space", "café", "a" * 65]
)
def test_merge_rejects_invalid_instance_ids(instance_id: str) -> None:
    ledger = Ledger(schema_version=1, solutions={})

    with pytest.raises(ValueError, match="invalid instance ID"):
        merge_witness(ledger, instance_id=instance_id, secret=())


@pytest.mark.parametrize(
    "secret", [[True], [1.0], ["1"], [2**63], [-(2**63)]]
)
def test_merge_rejects_invalid_secrets(secret: list[object]) -> None:
    ledger = Ledger(schema_version=1, solutions={})

    with pytest.raises(ValueError, match="invalid secret"):
        merge_witness(ledger, instance_id="a", secret=secret)


def test_load_ledger_returns_sorted_deeply_immutable_records(
    tmp_path: Path,
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"z","secret":[2]},'
        b'{"instance_id":"a","secret":[1,0]}]}'
    )

    ledger = load_ledger(path)

    assert ledger.schema_version == 1
    assert dict(ledger.solutions) == {"a": (1, 0), "z": (2,)}
    assert tuple(ledger.solutions) == ("a", "z")
    with pytest.raises(TypeError):
        ledger.solutions["a"] = (9,)


def test_ledger_destinations_reject_symlinks_in_api_and_cli(
    tmp_path: Path, task_dir: Path
) -> None:
    target = tmp_path / "target.json"
    target_bytes = b'{"schema_version":1,"solutions":[]}\n'
    target.write_bytes(target_bytes)
    path = tmp_path / "solution.json"
    path.symlink_to(target)

    with pytest.raises((LedgerContractError, OSError)):
        load_ledger(path)
    with pytest.raises((LedgerContractError, OSError)):
        write_ledger_atomic(
            path,
            Ledger(schema_version=1, solutions={"a": (1,)}),
        )

    result = _run_add_solution(task_dir, path, "a", "1")

    assert result.returncode != 0
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert path.is_symlink()
    assert target.read_bytes() == target_bytes


def test_write_ledger_uses_exact_canonical_bytes(tmp_path: Path) -> None:
    path = tmp_path / "solution.json"
    ledger = Ledger(schema_version=1, solutions={"z": (2,), "a": (1, 0)})

    write_ledger_atomic(path, ledger)

    assert path.read_bytes() == (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"a","secret":[1,0]},'
        b'{"instance_id":"z","secret":[2]}]}\n'
    )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (
            b'{"schema_version":1,"solutions":[],"extra":0}',
            "ledger fields",
        ),
        (b'{"schema_version":true,"solutions":[]}', "schema_version"),
        (b'{"schema_version":2,"solutions":[]}', "schema_version"),
        (b'{"schema_version":1,"solutions":{}}', "JSON array"),
        (b'{"schema_version":1,"solutions":[42]}', "solution record"),
        (
            b'{"schema_version":1,"solutions":['
            b'{"instance_id":"a","secret":[],"extra":0}]}',
            "solution record",
        ),
        (
            b'{"schema_version":1,"solutions":['
            b'{"instance_id":"_bad","secret":[]}]}',
            "instance ID",
        ),
        (
            b'{"schema_version":1,"solutions":['
            b'{"instance_id":"a","secret":[true]}]}',
            "ledger secret",
        ),
        (
            b'{"schema_version":1,"solutions":['
            b'{"instance_id":"a","secret":[]},'
            b'{"instance_id":"a","secret":[]}]}',
            "repeated ledger instance ID",
        ),
        (
            b'{"schema_version":1,"schema_version":1,"solutions":[]}',
            "duplicate JSON key",
        ),
    ],
)
def test_load_ledger_rejects_malformed_contracts(
    tmp_path: Path, data: bytes, message: str
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(data)

    with pytest.raises(ValueError, match=message):
        load_ledger(path)


def test_load_ledger_enforces_record_and_byte_bounds(tmp_path: Path) -> None:
    path = tmp_path / "solution.json"
    records = b",".join(
        b'{"instance_id":"a%03d","secret":[]}' % index
        for index in range(201)
    )
    path.write_bytes(b'{"schema_version":1,"solutions":[' + records + b"]}")
    with pytest.raises(LedgerContractError, match="too many"):
        load_ledger(path)

    path.write_bytes(b" " * (ledger_module.MAX_LEDGER_BYTES + 1))
    with pytest.raises(ValueError, match="exceeds .* bytes"):
        load_ledger(path)


def test_serialization_failure_preserves_original_and_creates_no_temp(
    tmp_path: Path,
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)

    with pytest.raises(LedgerContractError, match="schema_version"):
        write_ledger_atomic(path, Ledger(schema_version=2, solutions={}))

    assert path.read_bytes() == original
    assert sorted(tmp_path.iterdir()) == [path]


def test_quarantine_infrastructure_is_ready_before_temp_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    temp_requested = False
    real_mkstemp = ledger_module.tempfile.mkstemp

    def fail_mkdtemp(*_args: object, **_kwargs: object) -> str:
        raise OSError("synthetic quarantine setup failure")

    def record_mkstemp(*args: object, **kwargs: object):
        nonlocal temp_requested
        temp_requested = True
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", fail_mkdtemp)
    monkeypatch.setattr(ledger_module.tempfile, "mkstemp", record_mkstemp)

    with pytest.raises(OSError, match="quarantine setup failure"):
        write_ledger_atomic(
            path,
            Ledger(schema_version=1, solutions={"a": (1,)}),
        )

    assert path.read_bytes() == original
    assert not temp_requested
    assert sorted(tmp_path.iterdir()) == [path]


def test_partial_quarantine_setup_is_cleaned_before_temp_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    real_open = ledger_module.os.open
    real_mkstemp = ledger_module.tempfile.mkstemp
    temp_requested = False

    def fail_quarantine_open(
        raw_path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if (
            isinstance(raw_path, str)
            and raw_path.startswith(".solution.json.quarantine.")
        ):
            raise OSError("synthetic quarantine open failure")
        return real_open(raw_path, flags, mode, dir_fd=dir_fd)

    def record_mkstemp(*args: object, **kwargs: object):
        nonlocal temp_requested
        temp_requested = True
        return real_mkstemp(*args, **kwargs)

    monkeypatch.setattr(ledger_module.os, "open", fail_quarantine_open)
    monkeypatch.setattr(ledger_module.tempfile, "mkstemp", record_mkstemp)

    with pytest.raises(OSError, match="quarantine open failure"):
        write_ledger_atomic(
            path,
            Ledger(schema_version=1, solutions={"a": (1,)}),
        )

    assert path.read_bytes() == original
    assert not temp_requested
    assert sorted(tmp_path.iterdir()) == [path]


def test_temp_with_unverifiable_identity_is_moved_into_ready_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    real_mkstemp = ledger_module.tempfile.mkstemp
    real_fstat = ledger_module.os.fstat
    temp_descriptors: set[int] = set()

    def capture_mkstemp(*args: object, **kwargs: object):
        descriptor, temporary_path = real_mkstemp(*args, **kwargs)
        temp_descriptors.add(descriptor)
        return descriptor, temporary_path

    def fail_temp_fstat(file_descriptor: int) -> os.stat_result:
        if file_descriptor in temp_descriptors:
            raise OSError("synthetic temp identity failure")
        return real_fstat(file_descriptor)

    monkeypatch.setattr(ledger_module.tempfile, "mkstemp", capture_mkstemp)
    monkeypatch.setattr(ledger_module.os, "fstat", fail_temp_fstat)

    with pytest.raises(OSError, match="temp identity failure"):
        write_ledger_atomic(
            path,
            Ledger(schema_version=1, solutions={"a": (1,)}),
        )

    assert path.read_bytes() == original
    exposed_temps = [
        candidate
        for candidate in tmp_path.iterdir()
        if candidate.name.endswith(".tmp")
    ]
    assert exposed_temps == []
    quarantines = [
        candidate
        for candidate in tmp_path.iterdir()
        if ".quarantine." in candidate.name
    ]
    assert len(quarantines) == 1
    assert (quarantines[0] / "private" / "entry").is_file()


def test_fsync_failure_preserves_original_and_removes_owned_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)

    def fail_fsync(_fd: int) -> None:
        raise OSError("synthetic fsync failure")

    monkeypatch.setattr(ledger_module.os, "fsync", fail_fsync)

    with pytest.raises(OSError, match="synthetic fsync failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert sorted(tmp_path.iterdir()) == [path]


def test_write_failure_preserves_original_and_removes_owned_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    real_fdopen = ledger_module.os.fdopen

    class FailingWriter:
        def __init__(self, file_descriptor: int, mode: str) -> None:
            self._handle = real_fdopen(file_descriptor, mode)

        def __enter__(self) -> "FailingWriter":
            return self

        def __exit__(self, *_args: object) -> None:
            self._handle.close()

        def write(self, _data: bytes) -> int:
            raise OSError("synthetic write failure")

    monkeypatch.setattr(ledger_module.os, "fdopen", FailingWriter)

    with pytest.raises(OSError, match="synthetic write failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert sorted(tmp_path.iterdir()) == [path]


def test_short_writes_are_retried_until_canonical_output_is_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    real_fdopen = ledger_module.os.fdopen

    class OneByteWriter:
        def __init__(self, file_descriptor: int, mode: str) -> None:
            self._handle = real_fdopen(file_descriptor, mode)

        def __enter__(self) -> "OneByteWriter":
            return self

        def __exit__(self, *_args: object) -> None:
            self._handle.close()

        def write(self, data: object) -> int:
            return self._handle.write(memoryview(data)[:1])

        def flush(self) -> None:
            self._handle.flush()

        def fileno(self) -> int:
            return self._handle.fileno()

    monkeypatch.setattr(ledger_module.os, "fdopen", OneByteWriter)

    write_ledger_atomic(path, Ledger(schema_version=1, solutions={"a": (1,)}))

    assert path.read_bytes() == (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"a","secret":[1]}]}\n'
    )


@pytest.mark.parametrize("write_result", [None, 0, -1, True, 10**9])
def test_invalid_write_counts_preserve_original(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_result: object,
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    real_fdopen = ledger_module.os.fdopen

    class InvalidCountWriter:
        def __init__(self, file_descriptor: int, mode: str) -> None:
            self._handle = real_fdopen(file_descriptor, mode)

        def __enter__(self) -> "InvalidCountWriter":
            return self

        def __exit__(self, *_args: object) -> None:
            self._handle.close()

        def write(self, _data: object) -> object:
            return write_result

        def flush(self) -> None:
            self._handle.flush()

        def fileno(self) -> int:
            return self._handle.fileno()

    monkeypatch.setattr(ledger_module.os, "fdopen", InvalidCountWriter)

    with pytest.raises(OSError, match="complete ledger"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert sorted(tmp_path.iterdir()) == [path]


def test_replace_failure_preserves_original_and_unrelated_sibling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    unrelated = tmp_path / ".solution.json.unrelated.tmp"
    original = b"original\n"
    path.write_bytes(original)
    unrelated.write_bytes(b"do not remove")

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(ledger_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert unrelated.read_bytes() == b"do not remove"
    assert sorted(tmp_path.iterdir()) == [unrelated, path]


def test_failure_cleanup_does_not_unlink_a_swapped_temp_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    swapped_paths: list[Path] = []

    def swap_then_fail(source: object, _destination: object) -> None:
        source_path = Path(source)
        source_path.unlink()
        source_path.write_bytes(b"replacement not owned by writer")
        swapped_paths.append(source_path)
        raise OSError("synthetic post-swap failure")

    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)

    with pytest.raises(OSError, match="synthetic post-swap failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert len(swapped_paths) == 1
    assert swapped_paths[0].read_bytes() == b"replacement not owned by writer"


def test_foreign_temp_is_quarantined_if_safe_restore_would_clobber(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    foreign = b"foreign replacement\n"
    blocker = b"new unrelated path entry\n"
    path.write_bytes(original)
    temporary_paths: list[Path] = []
    entry_file_descriptors: set[int] = set()
    real_open = ledger_module.os.open
    real_fstat = ledger_module.os.fstat
    blocked = False

    def swap_then_fail(source: object, _destination: object) -> None:
        temporary_path = Path(source)
        temporary_path.unlink()
        temporary_path.write_bytes(foreign)
        temporary_paths.append(temporary_path)
        raise OSError("synthetic replace failure")

    def capture_open(
        raw_path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(raw_path, flags, mode, dir_fd=dir_fd)
        if raw_path == "entry" and dir_fd is not None:
            entry_file_descriptors.add(descriptor)
        return descriptor

    def block_restore(file_descriptor: int) -> os.stat_result:
        nonlocal blocked
        result = real_fstat(file_descriptor)
        if not blocked and file_descriptor in entry_file_descriptors:
            temporary_paths[0].write_bytes(blocker)
            blocked = True
        return result

    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)
    monkeypatch.setattr(ledger_module.os, "open", capture_open)
    monkeypatch.setattr(ledger_module.os, "fstat", block_restore)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert blocked
    assert temporary_paths[0].read_bytes() == blocker
    quarantines = [
        candidate
        for candidate in tmp_path.iterdir()
        if ".quarantine." in candidate.name
    ]
    assert len(quarantines) == 1
    assert (quarantines[0] / "private" / "entry").read_bytes() == foreign


def test_foreign_quarantine_link_survives_loss_of_restored_exposed_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    foreign = b"foreign replacement\n"
    path.write_bytes(original)
    real_link = ledger_module.os.link
    restored_paths: list[Path] = []
    hook_fired = False

    def swap_then_fail(source: object, _destination: object) -> None:
        temporary_path = Path(source)
        temporary_path.unlink()
        temporary_path.write_bytes(foreign)
        raise OSError("synthetic replace failure")

    def restore_then_remove(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal hook_fired
        real_link(source, destination, *args, **kwargs)
        restored_path = Path(destination)
        assert restored_path.read_bytes() == foreign
        restored_path.unlink()
        restored_paths.append(restored_path)
        hook_fired = True

    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)
    monkeypatch.setattr(ledger_module.os, "link", restore_then_remove)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert hook_fired, "restored-link removal hook did not fire"
    assert len(restored_paths) == 1
    assert not restored_paths[0].exists()
    quarantines = [
        candidate
        for candidate in tmp_path.iterdir()
        if ".quarantine." in candidate.name
    ]
    assert len(quarantines) == 1
    assert (quarantines[0] / "private" / "entry").read_bytes() == foreign


def test_swapped_symlink_inode_is_hard_linked_and_remains_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    target = tmp_path / "foreign-target"
    target.write_bytes(b"foreign target content")
    path.write_bytes(original)
    exposed_paths: list[Path] = []

    def swap_then_fail(source: object, _destination: object) -> None:
        exposed_path = Path(source)
        exposed_path.unlink()
        exposed_path.symlink_to(target)
        exposed_paths.append(exposed_path)
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    quarantines = [
        candidate
        for candidate in tmp_path.iterdir()
        if ".quarantine." in candidate.name
    ]
    assert path.read_bytes() == original
    assert len(quarantines) == 1
    quarantined_entry = quarantines[0] / "private" / "entry"
    assert exposed_paths[0].is_symlink()
    assert quarantined_entry.is_symlink()
    assert os.lstat(exposed_paths[0]).st_ino == os.lstat(quarantined_entry).st_ino
    assert exposed_paths[0].read_bytes() == b"foreign target content"


def test_swapped_fifo_inode_is_hard_linked_and_remains_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    exposed_paths: list[Path] = []

    def swap_then_fail(source: object, _destination: object) -> None:
        exposed_path = Path(source)
        exposed_path.unlink()
        os.mkfifo(exposed_path)
        exposed_paths.append(exposed_path)
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    quarantines = [
        candidate
        for candidate in tmp_path.iterdir()
        if ".quarantine." in candidate.name
    ]
    assert path.read_bytes() == original
    assert len(quarantines) == 1
    quarantined_entry = quarantines[0] / "private" / "entry"
    assert stat.S_ISFIFO(os.lstat(exposed_paths[0]).st_mode)
    assert stat.S_ISFIFO(os.lstat(quarantined_entry).st_mode)
    assert os.lstat(exposed_paths[0]).st_ino == os.lstat(quarantined_entry).st_ino


def test_swapped_directory_gets_no_clobber_symlink_and_stays_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    exposed_paths: list[Path] = []
    foreign_inodes: list[int] = []

    def swap_then_fail(source: object, _destination: object) -> None:
        exposed_path = Path(source)
        exposed_path.unlink()
        exposed_path.mkdir()
        (exposed_path / "marker").write_bytes(b"foreign directory content")
        exposed_paths.append(exposed_path)
        foreign_inodes.append(os.lstat(exposed_path).st_ino)
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    quarantines = [
        candidate
        for candidate in tmp_path.iterdir()
        if ".quarantine." in candidate.name
    ]
    assert path.read_bytes() == original
    assert len(quarantines) == 1
    quarantined_entry = quarantines[0] / "private" / "entry"
    assert os.lstat(quarantined_entry).st_ino == foreign_inodes[0]
    assert exposed_paths[0].is_symlink()
    assert exposed_paths[0].resolve() == quarantined_entry.resolve()
    assert (exposed_paths[0] / "marker").read_bytes() == (
        b"foreign directory content"
    )


def test_quarantine_fstat_swap_hook_cannot_replace_owned_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    foreign = b"foreign replacement\n"
    path.write_bytes(original)
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    real_open = ledger_module.os.open
    real_stat = ledger_module.os.stat
    real_fstat = ledger_module.os.fstat
    quarantine_directories: list[Path] = []
    entry_file_descriptors: set[int] = set()
    hook_fired = False
    swap_succeeded = False

    def fail_replace(_source: object, _destination: object) -> None:
        raise OSError("synthetic replace failure")

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def capture_open(
        raw_path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(raw_path, flags, mode, dir_fd=dir_fd)
        if raw_path == "entry" and dir_fd is not None:
            entry_file_descriptors.add(descriptor)
        return descriptor

    def attempt_swap(candidate: Path) -> None:
        nonlocal hook_fired, swap_succeeded
        hook_fired = True
        try:
            candidate.unlink()
        except PermissionError:
            return
        candidate.write_bytes(foreign)
        swap_succeeded = True

    def stat_then_attack(
        raw_path: object, *args: object, **kwargs: object
    ) -> os.stat_result:
        result = real_stat(raw_path, *args, **kwargs)
        candidate = Path(raw_path)
        if (
            not hook_fired
            and candidate.name == "entry"
            and ".quarantine." in candidate.parent.name
        ):
            attempt_swap(candidate)
        return result

    def fstat_then_attack(file_descriptor: int) -> os.stat_result:
        result = real_fstat(file_descriptor)
        if not hook_fired and file_descriptor in entry_file_descriptors:
            attempt_swap(quarantine_directories[-1] / "private" / "entry")
        return result

    monkeypatch.setattr(ledger_module.os, "replace", fail_replace)
    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
    monkeypatch.setattr(ledger_module.os, "open", capture_open)
    monkeypatch.setattr(ledger_module.os, "stat", stat_then_attack)
    monkeypatch.setattr(ledger_module.os, "fstat", fstat_then_attack)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert hook_fired, "race hook did not target the inspected quarantine entry"
    assert not swap_succeeded
    assert len(quarantine_directories) == 1
    assert not quarantine_directories[0].exists()


def test_atomic_write_does_not_follow_predictable_temp_symlink(
    tmp_path: Path,
) -> None:
    path = tmp_path / "solution.json"
    victim = tmp_path / "victim"
    decoy = tmp_path / ".solution.json.predictable.tmp"
    victim.write_bytes(b"untouched")
    decoy.symlink_to(victim)

    write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert victim.read_bytes() == b"untouched"
    assert decoy.is_symlink()
    assert path.read_bytes() == b'{"schema_version":1,"solutions":[]}\n'


def test_atomic_write_uses_unique_private_siblings_after_fsync(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    real_fsync = ledger_module.os.fsync
    real_replace = ledger_module.os.replace
    events: list[str] = []
    temporary_paths: list[Path] = []

    def record_fsync(file_descriptor: int) -> None:
        kind = (
            "fsync_directory"
            if stat.S_ISDIR(os.fstat(file_descriptor).st_mode)
            else "fsync_file"
        )
        events.append(kind)
        real_fsync(file_descriptor)

    def record_replace(source: object, destination: object) -> None:
        source_path = Path(source)
        temporary_paths.append(source_path)
        assert source_path.parent == path.parent
        assert not source_path.is_symlink()
        assert stat.S_IMODE(source_path.stat().st_mode) == 0o600
        assert Path(destination) == path
        events.append("replace")
        real_replace(source, destination)

    monkeypatch.setattr(ledger_module.os, "fsync", record_fsync)
    monkeypatch.setattr(ledger_module.os, "replace", record_replace)

    write_ledger_atomic(path, Ledger(schema_version=1, solutions={"a": (1,)}))
    write_ledger_atomic(path, Ledger(schema_version=1, solutions={"b": (2,)}))

    assert events == [
        "fsync_file",
        "replace",
        "fsync_directory",
        "fsync_file",
        "replace",
        "fsync_directory",
    ]
    assert len({temporary.name for temporary in temporary_paths}) == 2
    assert path.read_bytes() == (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"b","secret":[2]}]}\n'
    )


def test_add_solution_cli_updates_ledger_without_echoing_witness(
    tmp_path: Path, task_dir: Path
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(b'{"schema_version":1,"solutions":[]}\n')
    result = _run_add_solution(
        task_dir, path, "sensitive-id", "123456789,-7"
    )

    assert result.returncode == 0
    assert result.stdout == "1\n"
    assert result.stderr == ""
    assert "sensitive-id" not in result.stdout + result.stderr
    assert "123456789" not in result.stdout + result.stderr
    assert dict(load_ledger(path).solutions) == {
        "sensitive-id": (123456789, -7)
    }


def test_add_solution_cli_sanitizes_conflicting_witness_error(
    tmp_path: Path, task_dir: Path
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"private-id","secret":[1]}]}\n'
    )

    result = _run_add_solution(
        task_dir, path, "private-id", "987654321"
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert result.stderr == "error: unable to update ledger\n"
    assert "Traceback" not in result.stderr
    assert "private-id" not in result.stderr
    assert "987654321" not in result.stderr
    assert dict(load_ledger(path).solutions) == {"private-id": (1,)}


def test_add_solution_cli_replaces_only_when_requested(
    tmp_path: Path, task_dir: Path
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"a","secret":[1]}]}\n'
    )

    result = _run_add_solution(task_dir, path, "--replace", "a", "2,-3")

    assert result.returncode == 0
    assert result.stdout == "1\n"
    assert result.stderr == ""
    assert dict(load_ledger(path).solutions) == {"a": (2, -3)}


def test_add_solution_cli_accepts_vector_beginning_with_negative_integer(
    tmp_path: Path, task_dir: Path
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(b'{"schema_version":1,"solutions":[]}\n')

    result = _run_add_solution(task_dir, path, "a", "-1,0,1")

    assert result.returncode == 0
    assert result.stdout == "1\n"
    assert result.stderr == ""
    assert dict(load_ledger(path).solutions) == {"a": (-1, 0, 1)}


@pytest.mark.parametrize("_round", range(3))
def test_two_synchronized_cli_processes_preserve_distinct_updates(
    tmp_path: Path, task_dir: Path, _round: int
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(b'{"schema_version":1,"solutions":[]}\n')
    processes: list[subprocess.Popen[str]] = []
    try:
        with ledger_lock(path):
            processes = [
                _start_add_solution(task_dir, path, "a", "1"),
                _start_add_solution(task_dir, path, "b", "2"),
            ]
            time.sleep(0.1)
            assert all(process.poll() is None for process in processes)

        results = [process.communicate(timeout=10) for process in processes]
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)

    assert [process.returncode for process in processes] == [0, 0]
    assert sorted(stdout for stdout, _stderr in results) == ["1\n", "2\n"]
    assert all(stderr == "" for _stdout, stderr in results)
    assert dict(load_ledger(path).solutions) == {"a": (1,), "b": (2,)}


def test_cli_rereads_ledger_after_acquiring_transaction_lock(
    tmp_path: Path, task_dir: Path
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(b'{"schema_version":1,"solutions":[]}\n')
    process: subprocess.Popen[str] | None = None
    try:
        with ledger_lock(path):
            process = _start_add_solution(task_dir, path, "b", "2")
            time.sleep(0.1)
            assert process.poll() is None
            write_ledger_atomic(
                path,
                Ledger(schema_version=1, solutions={"a": (1,)}),
            )

        stdout, stderr = process.communicate(timeout=10)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)

    assert process is not None
    assert process.returncode == 0
    assert stdout == "2\n"
    assert stderr == ""
    assert dict(load_ledger(path).solutions) == {"a": (1,), "b": (2,)}


@pytest.mark.parametrize("_round", range(3))
def test_two_synchronized_cli_processes_cannot_both_replace_same_id(
    tmp_path: Path, task_dir: Path, _round: int
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(b'{"schema_version":1,"solutions":[]}\n')
    processes: list[subprocess.Popen[str]] = []
    try:
        with ledger_lock(path):
            processes = [
                _start_add_solution(task_dir, path, "same", "1"),
                _start_add_solution(task_dir, path, "same", "2"),
            ]
            time.sleep(0.1)
            assert all(process.poll() is None for process in processes)

        results = [process.communicate(timeout=10) for process in processes]
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)

    assert sorted(process.returncode for process in processes) == [0, 2]
    successful_stdout = [
        stdout
        for process, (stdout, _stderr) in zip(processes, results)
        if process.returncode == 0
    ]
    assert successful_stdout == ["1\n"]
    assert dict(load_ledger(path).solutions)["same"] in {(1,), (2,)}


def test_add_solution_cli_rejects_malformed_vector_without_echoing_it(
    tmp_path: Path, task_dir: Path
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(b'{"schema_version":1,"solutions":[]}\n')

    result = _run_add_solution(
        task_dir, path, "private-id", "987654321,,7"
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert "private-id" not in result.stderr
    assert "987654321" not in result.stderr
    assert dict(load_ledger(path).solutions) == {}


def test_add_solution_cli_sanitizes_argument_parser_errors(
    tmp_path: Path, task_dir: Path
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(b'{"schema_version":1,"solutions":[]}\n')

    result = _run_add_solution(
        task_dir, path, "a", "1", "--replace=TOPSECRET"
    )

    assert result.returncode != 0
    assert result.stdout == ""
    assert "Traceback" not in result.stderr
    assert "TOPSECRET" not in result.stderr
    assert dict(load_ledger(path).solutions) == {}
