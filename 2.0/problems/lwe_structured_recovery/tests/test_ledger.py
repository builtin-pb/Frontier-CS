import os
import runpy
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
from lwe_challenge.schema import MAX_N
from lwe_challenge.submission import parse_submission


def _run_add_solution(
    task_dir: Path, path: Path, *arguments: str
) -> subprocess.CompletedProcess[str]:
    script = task_dir / "harbor" / "app" / "add_solution.py"
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
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
    env.pop("PYTHONPATH", None)
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


def _replace_private_source_with_bytes(
    source: object,
    call_kwargs: dict[str, object],
    data: bytes,
) -> None:
    source_directory_fd = call_kwargs.get("src_dir_fd")
    assert type(source_directory_fd) is int
    os.unlink(source, dir_fd=source_directory_fd)
    descriptor = os.open(
        source,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
        dir_fd=source_directory_fd,
    )
    try:
        assert os.write(descriptor, data) == len(data)
    finally:
        os.close(descriptor)


def test_identical_merge_is_idempotent() -> None:
    ledger = Ledger(schema_version=1, solutions={"a": (1, 0)})

    merged = merge_witness(
        ledger, instance_id="a", secret=(1, 0), replace=False
    )

    assert merged is ledger


def test_helper_output_stays_within_evaluator_structural_budget(
    tmp_path: Path, catalog
) -> None:
    path = tmp_path / "solution.json"
    path.write_bytes(b'{"schema_version":1,"solutions":[]}\n')
    overlong = (0,) * (MAX_N + 1)

    with pytest.raises(ValueError, match="secret"):
        merge_witness(
            Ledger(schema_version=1, solutions={}),
            instance_id="toy-uniform",
            secret=overlong,
        )
    with pytest.raises(LedgerContractError, match="solution record"):
        write_ledger_atomic(
            path,
            Ledger(
                schema_version=1,
                solutions={"toy-uniform": overlong},
            ),
        )

    allowed = Ledger(
        schema_version=1,
        solutions={"toy-uniform": (0,) * MAX_N},
    )
    write_ledger_atomic(path, allowed)
    parsed = parse_submission(path.read_bytes(), catalog=catalog)

    assert parsed.records["toy-uniform"] == (0,) * MAX_N


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
    real_open = ledger_module.os.open

    def fail_mkdtemp(*_args: object, **_kwargs: object) -> str:
        raise OSError("synthetic quarantine setup failure")

    def record_open(
        raw_path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal temp_requested
        if raw_path == "entry" and flags & os.O_CREAT:
            temp_requested = True
        return real_open(raw_path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", fail_mkdtemp)
    monkeypatch.setattr(ledger_module.os, "open", record_open)

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
    temp_requested = False

    def fail_quarantine_open(
        raw_path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal temp_requested
        if (
            isinstance(raw_path, str)
            and raw_path.startswith(".solution.json.quarantine.")
        ):
            raise OSError("synthetic quarantine open failure")
        if raw_path == "entry" and flags & os.O_CREAT:
            temp_requested = True
        return real_open(raw_path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(ledger_module.os, "open", fail_quarantine_open)

    with pytest.raises(OSError, match="quarantine open failure"):
        write_ledger_atomic(
            path,
            Ledger(schema_version=1, solutions={"a": (1,)}),
        )

    assert path.read_bytes() == original
    assert not temp_requested
    assert sorted(tmp_path.iterdir()) == [path]


def test_quarantine_traversal_is_revoked_before_temp_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    real_open = ledger_module.os.open
    quarantine_directories: list[Path] = []
    temp_created = False

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def assert_private_open(
        raw_path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal temp_created
        if raw_path == "entry" and flags & os.O_CREAT:
            temp_created = True
            assert stat.S_IMODE(
                quarantine_directories[-1].stat().st_mode
            ) == 0
        return real_open(raw_path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
    monkeypatch.setattr(ledger_module.os, "open", assert_private_open)

    write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert temp_created
    assert path.read_bytes() == b'{"schema_version":1,"solutions":[]}\n'


def test_temp_with_unverifiable_identity_is_retained_in_ready_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    real_open = ledger_module.os.open
    real_fstat = ledger_module.os.fstat
    temp_descriptors: set[int] = set()

    def capture_open(
        raw_path: object,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = real_open(raw_path, flags, mode, dir_fd=dir_fd)
        if raw_path == "entry" and flags & os.O_CREAT:
            temp_descriptors.add(descriptor)
        return descriptor

    def fail_temp_fstat(file_descriptor: int) -> os.stat_result:
        if file_descriptor in temp_descriptors:
            raise OSError("synthetic temp identity failure")
        return real_fstat(file_descriptor)

    monkeypatch.setattr(ledger_module.os, "open", capture_open)
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


def test_parent_fsync_failure_keeps_replaced_ledger_and_cleans_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    real_fsync = ledger_module.os.fsync

    def fail_parent_fsync(file_descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(file_descriptor).st_mode):
            raise OSError("synthetic parent fsync failure")
        real_fsync(file_descriptor)

    monkeypatch.setattr(ledger_module.os, "fsync", fail_parent_fsync)

    with pytest.raises(OSError, match="parent fsync failure"):
        write_ledger_atomic(
            path,
            Ledger(schema_version=1, solutions={"a": (1,)}),
        )

    assert path.read_bytes() == (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"a","secret":[1]}]}\n'
    )
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

    def fail_replace(
        _source: object,
        _destination: object,
        *_args: object,
        **_kwargs: object,
    ) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(ledger_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert unrelated.read_bytes() == b"do not remove"
    assert sorted(tmp_path.iterdir()) == [unrelated, path]


def test_failure_cleanup_does_not_unlink_a_swapped_private_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    foreign = b"replacement not owned by writer"
    path.write_bytes(original)
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    quarantine_directories: list[Path] = []

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def swap_then_fail(
        source: object,
        _destination: object,
        *_args: object,
        **kwargs: object,
    ) -> None:
        _replace_private_source_with_bytes(source, kwargs, foreign)
        raise OSError("synthetic post-swap failure")

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)

    with pytest.raises(OSError, match="synthetic post-swap failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert len(quarantine_directories) == 1
    assert (
        quarantine_directories[0] / "private" / "entry"
    ).read_bytes() == foreign


def test_replace_cannot_install_an_attacker_swapped_foreign_inode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    foreign_source = tmp_path / "foreign-source"
    foreign = b"attacker-controlled bytes\n"
    foreign_source.write_bytes(foreign)
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    real_replace = ledger_module.os.replace
    quarantine_directories: list[Path] = []
    attack_attempted = False
    swap_succeeded = False

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def swap_then_replace(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal attack_attempted, swap_succeeded
        attack_attempted = True
        source_directory_fd = kwargs.get("src_dir_fd")
        if source_directory_fd is None:
            attacked_source = Path(source)
        else:
            attacked_source = (
                quarantine_directories[-1] / "private" / str(source)
            )
        try:
            real_replace(foreign_source, attacked_source)
        except PermissionError:
            pass
        else:
            swap_succeeded = True
        real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
    monkeypatch.setattr(ledger_module.os, "replace", swap_then_replace)

    write_ledger_atomic(
        path,
        Ledger(schema_version=1, solutions={"a": (1,)}),
    )

    assert attack_attempted
    assert not swap_succeeded
    assert foreign_source.read_bytes() == foreign
    assert path.read_bytes() == (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"a","secret":[1]}]}\n'
    )


def test_pre_replace_identity_mismatch_preserves_foreign_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    foreign = b"foreign replacement\n"
    path.write_bytes(original)
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    real_verify = ledger_module._verify_owned_temp
    quarantine_directories: list[Path] = []
    replace_called = False

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def swap_then_verify(
        quarantine: object, identity: tuple[int, int]
    ) -> int:
        _replace_private_source_with_bytes(
            "entry",
            {"src_dir_fd": quarantine.inner_fd},
            foreign,
        )
        return real_verify(quarantine, identity)

    def record_replace(
        _source: object,
        _destination: object,
        *_args: object,
        **_kwargs: object,
    ) -> None:
        nonlocal replace_called
        replace_called = True

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
    monkeypatch.setattr(ledger_module, "_verify_owned_temp", swap_then_verify)
    monkeypatch.setattr(ledger_module.os, "replace", record_replace)

    with pytest.raises(OSError, match="identity changed"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert not replace_called
    assert len(quarantine_directories) == 1
    assert (
        quarantine_directories[0] / "private" / "entry"
    ).read_bytes() == foreign


def test_foreign_temp_is_quarantined_without_clobbering_siblings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    sibling = tmp_path / ".solution.json.unrelated.tmp"
    original = b"original\n"
    foreign = b"foreign replacement\n"
    blocker = b"new unrelated path entry\n"
    path.write_bytes(original)
    sibling.write_bytes(blocker)
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    quarantine_directories: list[Path] = []

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def swap_then_fail(
        source: object,
        _destination: object,
        *_args: object,
        **kwargs: object,
    ) -> None:
        _replace_private_source_with_bytes(source, kwargs, foreign)
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert sibling.read_bytes() == blocker
    assert len(quarantine_directories) == 1
    assert (
        quarantine_directories[0] / "private" / "entry"
    ).read_bytes() == foreign


def test_failure_cleanup_never_unlinks_foreign_quarantine_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    foreign = b"foreign replacement\n"
    path.write_bytes(original)
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    real_unlink = ledger_module.os.unlink
    quarantine_directories: list[Path] = []
    foreign_installed = False
    cleanup_unlink_attempted = False

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def swap_then_fail(
        source: object,
        _destination: object,
        *_args: object,
        **kwargs: object,
    ) -> None:
        nonlocal foreign_installed
        _replace_private_source_with_bytes(source, kwargs, foreign)
        foreign_installed = True
        raise OSError("synthetic replace failure")

    def record_unlink(
        raw_path: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal cleanup_unlink_attempted
        if foreign_installed and raw_path == "entry":
            cleanup_unlink_attempted = True
        real_unlink(raw_path, *args, **kwargs)

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)
    monkeypatch.setattr(ledger_module.os, "unlink", record_unlink)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert not cleanup_unlink_attempted
    assert len(quarantine_directories) == 1
    assert (
        quarantine_directories[0] / "private" / "entry"
    ).read_bytes() == foreign


def test_swapped_symlink_inode_remains_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    target = tmp_path / "foreign-target"
    target.write_bytes(b"foreign target content")
    path.write_bytes(original)
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    quarantine_directories: list[Path] = []
    foreign_inodes: list[int] = []

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def swap_then_fail(
        source: object,
        _destination: object,
        *_args: object,
        **kwargs: object,
    ) -> None:
        source_directory_fd = kwargs.get("src_dir_fd")
        assert type(source_directory_fd) is int
        os.unlink(source, dir_fd=source_directory_fd)
        os.symlink(target, source, dir_fd=source_directory_fd)
        foreign_inodes.append(
            os.stat(
                source,
                dir_fd=source_directory_fd,
                follow_symlinks=False,
            ).st_ino
        )
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert len(quarantine_directories) == 1
    quarantined_entry = quarantine_directories[0] / "private" / "entry"
    assert quarantined_entry.is_symlink()
    assert os.lstat(quarantined_entry).st_ino == foreign_inodes[0]
    assert quarantined_entry.read_bytes() == b"foreign target content"


def test_swapped_fifo_inode_remains_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    quarantine_directories: list[Path] = []
    foreign_inodes: list[int] = []

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def swap_then_fail(
        source: object,
        _destination: object,
        *_args: object,
        **kwargs: object,
    ) -> None:
        source_directory_fd = kwargs.get("src_dir_fd")
        assert type(source_directory_fd) is int
        os.unlink(source, dir_fd=source_directory_fd)
        os.mkfifo(source, dir_fd=source_directory_fd)
        foreign_inodes.append(
            os.stat(
                source,
                dir_fd=source_directory_fd,
                follow_symlinks=False,
            ).st_ino
        )
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert len(quarantine_directories) == 1
    quarantined_entry = quarantine_directories[0] / "private" / "entry"
    assert stat.S_ISFIFO(os.lstat(quarantined_entry).st_mode)
    assert os.lstat(quarantined_entry).st_ino == foreign_inodes[0]


def test_swapped_directory_stays_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "solution.json"
    original = b"original\n"
    path.write_bytes(original)
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    quarantine_directories: list[Path] = []
    foreign_inodes: list[int] = []

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def swap_then_fail(
        source: object,
        _destination: object,
        *_args: object,
        **kwargs: object,
    ) -> None:
        source_directory_fd = kwargs.get("src_dir_fd")
        assert type(source_directory_fd) is int
        os.unlink(source, dir_fd=source_directory_fd)
        os.mkdir(source, dir_fd=source_directory_fd)
        foreign_directory_fd = os.open(
            source,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=source_directory_fd,
        )
        try:
            marker_fd = os.open(
                "marker",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=foreign_directory_fd,
            )
            try:
                marker = b"foreign directory content"
                assert os.write(marker_fd, marker) == len(marker)
            finally:
                os.close(marker_fd)
        finally:
            os.close(foreign_directory_fd)
        foreign_inodes.append(
            os.stat(
                source,
                dir_fd=source_directory_fd,
                follow_symlinks=False,
            ).st_ino
        )
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
    monkeypatch.setattr(ledger_module.os, "replace", swap_then_fail)

    with pytest.raises(OSError, match="synthetic replace failure"):
        write_ledger_atomic(path, Ledger(schema_version=1, solutions={}))

    assert path.read_bytes() == original
    assert len(quarantine_directories) == 1
    quarantined_entry = quarantine_directories[0] / "private" / "entry"
    assert os.lstat(quarantined_entry).st_ino == foreign_inodes[0]
    assert quarantined_entry.is_dir()
    assert (quarantined_entry / "marker").read_bytes() == (
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

    def fail_replace(
        _source: object,
        _destination: object,
        *_args: object,
        **_kwargs: object,
    ) -> None:
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
    real_mkdtemp = ledger_module.tempfile.mkdtemp
    real_fsync = ledger_module.os.fsync
    real_replace = ledger_module.os.replace
    events: list[str] = []
    quarantine_directories: list[Path] = []

    def capture_mkdtemp(*args: object, **kwargs: object) -> str:
        directory = real_mkdtemp(*args, **kwargs)
        quarantine_directories.append(Path(directory))
        return directory

    def record_fsync(file_descriptor: int) -> None:
        kind = (
            "fsync_directory"
            if stat.S_ISDIR(os.fstat(file_descriptor).st_mode)
            else "fsync_file"
        )
        events.append(kind)
        real_fsync(file_descriptor)

    def record_replace(
        source: object,
        destination: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        source_directory_fd = kwargs.get("src_dir_fd")
        destination_directory_fd = kwargs.get("dst_dir_fd")
        assert type(source_directory_fd) is int
        assert type(destination_directory_fd) is int
        assert source == "entry"
        assert destination == path.name
        source_metadata = os.stat(
            source,
            dir_fd=source_directory_fd,
            follow_symlinks=False,
        )
        assert stat.S_ISREG(source_metadata.st_mode)
        assert stat.S_IMODE(source_metadata.st_mode) == 0o600
        assert stat.S_IMODE(
            quarantine_directories[-1].stat().st_mode
        ) == 0
        assert (
            os.fstat(destination_directory_fd).st_ino
            == path.parent.stat().st_ino
        )
        events.append("replace")
        real_replace(source, destination, *args, **kwargs)

    monkeypatch.setattr(ledger_module.tempfile, "mkdtemp", capture_mkdtemp)
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
    assert len({directory.name for directory in quarantine_directories}) == 2
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


def test_add_solution_cli_sanitizes_missing_public_package(
    tmp_path: Path, task_dir: Path
) -> None:
    source = task_dir / "harbor" / "app" / "add_solution.py"
    copied_app = tmp_path / "copied-app"
    copied_app.mkdir()
    copied_script = copied_app / "add_solution.py"
    copied_script.write_bytes(source.read_bytes())
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)

    result = subprocess.run(
        [sys.executable, str(copied_script), "private-id", "123456789"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=10,
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "error: unable to update ledger\n"
    assert "Traceback" not in result.stderr
    assert str(copied_script) not in result.stderr


def test_add_solution_programmatic_import_propagates_missing_public_package(
    tmp_path: Path, task_dir: Path
) -> None:
    source = task_dir / "harbor" / "app" / "add_solution.py"
    copied_app = tmp_path / "copied-app"
    copied_app.mkdir()
    copied_script = copied_app / "add_solution.py"
    copied_script.write_bytes(source.read_bytes())
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import runpy,sys;"
                "runpy.run_path(sys.argv[1],run_name='copied_add_solution')"
            ),
            str(copied_script),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=10,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert "Traceback" in result.stderr
    assert "ModuleNotFoundError" in result.stderr


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


def test_cli_transaction_stays_in_locked_parent_after_ancestor_rotation(
    tmp_path: Path,
    task_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    live_parent = tmp_path / "live"
    stale_parent = tmp_path / "stale"
    live_parent.mkdir()
    path = live_parent / "solution.json"
    path.write_bytes(
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"old","secret":[1]}]}\n'
    )
    replacement = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"live","secret":[9]}]}\n'
    )
    real_merge = ledger_module.merge_witness
    rotated = False
    live_lock_descriptors: list[int] = []

    def rotate_then_merge(
        current: Ledger, **kwargs: object
    ) -> Ledger:
        nonlocal rotated
        assert dict(current.solutions) == {"old": (1,)}
        live_parent.rename(stale_parent)
        live_parent.mkdir()
        (live_parent / "solution.json").write_bytes(replacement)
        live_lock_fd = os.open(
            live_parent / "solution.json.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        ledger_module.fcntl.flock(live_lock_fd, ledger_module.fcntl.LOCK_EX)
        live_lock_descriptors.append(live_lock_fd)
        assert (
            os.fstat(live_lock_fd).st_ino
            != (stale_parent / "solution.json.lock").stat().st_ino
        )
        rotated = True
        return real_merge(current, **kwargs)

    script = task_dir / "harbor" / "app" / "add_solution.py"
    namespace = runpy.run_path(
        str(script), run_name="lwe_add_solution_rotation_test"
    )
    monkeypatch.setattr(ledger_module, "merge_witness", rotate_then_merge)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(script), "--ledger", str(path), "new", "2"],
    )

    try:
        result = namespace["main"]()
    finally:
        for descriptor in live_lock_descriptors:
            ledger_module.fcntl.flock(
                descriptor, ledger_module.fcntl.LOCK_UN
            )
            os.close(descriptor)
    captured = capsys.readouterr()

    assert result == 0
    assert captured.out == "2\n"
    assert captured.err == ""
    assert rotated
    assert (live_parent / "solution.json").read_bytes() == replacement
    assert dict(load_ledger(stale_parent / "solution.json").solutions) == {
        "new": (2,),
        "old": (1,),
    }


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
