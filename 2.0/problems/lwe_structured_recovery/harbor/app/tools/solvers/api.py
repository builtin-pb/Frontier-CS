"""Fail-closed protocol shared by all exact-recovery solvers.

This module deliberately knows only the stable public instance facade.  Solver
implementations return a private :class:`SolveResult`; callers that persist
results must first pass it through :func:`scrub_result`.
"""

from __future__ import annotations

import fcntl
import json
import math
import os
import re
import secrets
import stat
import sys
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from time import monotonic
from types import MappingProxyType
from typing import Protocol, final

_MAX_DEPTH = 8
_MAX_NODES = 2_048
_MAX_STRING_BYTES = 4_096
_MAX_ARRAY_ITEMS = 1_024
_MAX_PROGRESS_BYTES = 16 * 1024 * 1024
_MAX_CHECKPOINT_BYTES = 128 * 1024 * 1024
_MAPPING_PROXY_TYPE = type(MappingProxyType({}))
_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_PROGRESS_KEYS = frozenset(
    {
        "solver_id",
        "instance_id",
        "elapsed_seconds",
        "work_units",
        "phase",
        "peak_rss_bytes",
        "checkpoint_count",
    }
)
_CHECKPOINT_KEYS = frozenset(
    {
        "schema_version",
        "solver_id",
        "solver_revision",
        "instance_digest",
        "seed",
        "work_units",
        "state",
    }
)
_PUBLIC_DETAIL_KEYS = frozenset(
    {
        "certificate_digest",
        "certificate_id",
        "code",
        "public_parameters",
        "reason",
    }
)
_POSITIVE_PUBLIC_INTS = frozenset(
    {
        "alphabet_size",
        "bucket_width",
        "checkpoint_interval",
        "domain_size",
        "m",
        "n",
        "q",
    }
)
_NONNEGATIVE_PUBLIC_INTS = frozenset(
    {
        "candidate_count",
        "collision_count",
        "covered_work_units",
        "error_bound",
        "memory_cap_bytes",
        "range_start",
        "range_stop",
        "rank",
        "row_count",
        "row_weight",
        "seed",
        "subset_size",
        "support_count",
        "tested_count",
        "weight",
        "work_unit_cap",
    }
)
_CAP_UNITS = frozenset(
    {"bytes", "candidates", "seconds", "subsets", "work_units"}
)
_PUBLIC_PARAMETER_KEYS = frozenset(
    {
        "alphabet_size",
        "bucket_width",
        "candidate_count",
        "cap",
        "cap_unit",
        "checkpoint_interval",
        "collision_count",
        "covered_work_units",
        "domain_size",
        "error_bound",
        "m",
        "max_seconds",
        "memory_cap_bytes",
        "n",
        "q",
        "range_start",
        "range_stop",
        "rank",
        "row_count",
        "row_weight",
        "seed",
        "subset_size",
        "support_count",
        "tested_count",
        "weight",
        "work_unit_cap",
    }
)


class SolverContractError(ValueError):
    """A solver request, result, checkpoint, or public log is invalid."""


class SolveStatus(StrEnum):
    SUCCESS = "success"
    EXHAUSTED = "exhausted"
    CENSORED = "censored"
    ERROR = "error"


class PublicWitnessVerdict(Protocol):
    ok: bool
    code: str


class ExactProblem(Protocol):
    instance_id: str
    instance_digest: str
    n: int
    m: int
    q: int
    b: tuple[int, ...]
    family: str
    tier: str
    cohort: str
    runtime_bin: str
    octave: int | None
    matrix_kind: str
    matrix_alphabet: tuple[int, ...]
    matrix_row_weight: int | None
    secret_distribution_kind: str
    secret_predicate_kind: str
    secret_alphabet: tuple[int, ...]
    secret_weight: int | None
    secret_eta: int | None
    secret_min_nonzero: int
    secret_max_nonzero: int
    error_distribution_kind: str
    error_sigma: float | None
    error_eta: int | None
    error_bound: int
    error_weight: int | None
    error_max_abs: int
    error_max_l1: int | None
    error_max_l2_squared: int | None
    error_max_nonzero: int | None

    def iter_rows(self) -> Iterator[tuple[int, ...]]: ...

    def materialize_row_block(
        self, start: int, stop: int
    ) -> tuple[tuple[int, ...], ...]: ...

    def materialize_rows(self) -> tuple[tuple[int, ...], ...]: ...

    def matvec(self, secret: Sequence[int]) -> tuple[int, ...]: ...

    def validate_secret(self, secret: Sequence[int]) -> PublicWitnessVerdict: ...


def _exact_nonnegative_int(value: object, where: str) -> int:
    if type(value) is not int or value < 0:
        raise SolverContractError(f"{where} must be a non-negative integer")
    return value


def _exact_positive_int(value: object, where: str) -> int:
    result = _exact_nonnegative_int(value, where)
    if result == 0:
        raise SolverContractError(f"{where} must be positive")
    return result


def _finite_nonnegative(value: object, where: str) -> float:
    if type(value) not in (int, float):
        raise SolverContractError(f"{where} must be a finite non-negative number")
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise SolverContractError(
            f"{where} must be a finite non-negative number"
        ) from exc
    if not math.isfinite(result) or result < 0.0:
        raise SolverContractError(f"{where} must be a finite non-negative number")
    return result


def _finite_positive(value: object, where: str) -> float:
    result = _finite_nonnegative(value, where)
    if result == 0.0:
        raise SolverContractError(f"{where} must be positive")
    return result


@dataclass(slots=True)
class _Budget:
    nodes: int = 0


def _freeze_json(
    value: object,
    *,
    where: str,
    depth: int = 0,
    budget: _Budget | None = None,
    forbidden: frozenset[str] = frozenset(),
    max_depth: int = _MAX_DEPTH,
    max_nodes: int = _MAX_NODES,
    max_string_bytes: int = _MAX_STRING_BYTES,
    max_array_items: int = _MAX_ARRAY_ITEMS,
) -> object:
    """Validate JSON-native data and return an alias-free immutable value."""

    active_budget = budget if budget is not None else _Budget()
    active_budget.nodes += 1
    if active_budget.nodes > max_nodes:
        raise SolverContractError(f"{where} exceeds the node limit")
    if depth > max_depth:
        raise SolverContractError(f"{where} exceeds the nesting limit")

    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise SolverContractError(f"{where} contains a non-finite number")
        return value
    if type(value) is str:
        try:
            encoded_value = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise SolverContractError(
                f"{where} contains invalid Unicode"
            ) from exc
        if len(encoded_value) > max_string_bytes:
            raise SolverContractError(f"{where} contains an oversized string")
        return value
    if type(value) in (list, tuple):
        if len(value) > max_array_items:
            raise SolverContractError(f"{where} contains an oversized array")
        return tuple(
            _freeze_json(
                item,
                where=f"{where}[{index}]",
                depth=depth + 1,
                budget=active_budget,
                forbidden=forbidden,
                max_depth=max_depth,
                max_nodes=max_nodes,
                max_string_bytes=max_string_bytes,
                max_array_items=max_array_items,
            )
            for index, item in enumerate(value)
        )
    if type(value) in (dict, _MAPPING_PROXY_TYPE):
        if len(value) > max_array_items:
            raise SolverContractError(f"{where} contains an oversized object")
        frozen: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise SolverContractError(f"{where} contains a non-string key")
            try:
                encoded_key = key.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise SolverContractError(
                    f"{where} contains an invalid Unicode key"
                ) from exc
            if len(encoded_key) > max_string_bytes:
                raise SolverContractError(f"{where} contains an oversized key")
            if key.casefold() in forbidden:
                raise SolverContractError(f"{where} contains forbidden key: {key}")
            frozen[key] = _freeze_json(
                item,
                where=f"{where}.{key}",
                depth=depth + 1,
                budget=active_budget,
                forbidden=forbidden,
                max_depth=max_depth,
                max_nodes=max_nodes,
                max_string_bytes=max_string_bytes,
                max_array_items=max_array_items,
            )
        return MappingProxyType(frozen)
    raise SolverContractError(f"{where} contains a non-JSON-native value")


def _public_json(value: object) -> object:
    """Convert an already validated immutable value to plain JSON containers."""

    if type(value) in (dict, _MAPPING_PROXY_TYPE):
        return {key: _public_json(value[key]) for key in sorted(value)}
    if type(value) is tuple:
        return [_public_json(item) for item in value]
    return value


def _canonical_work_path(value: object, where: str) -> Path:
    if not isinstance(value, Path):
        raise SolverContractError(f"{where} must be a pathlib.Path")
    if value.is_symlink():
        raise SolverContractError(f"{where} must not be a symlink")
    if value.exists() and not value.is_dir():
        raise SolverContractError(f"{where} must be a directory")
    try:
        return value.resolve(strict=False)
    except OSError as exc:
        raise SolverContractError(f"{where} cannot be resolved") from exc


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return path != root


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise SolverContractError("value is not canonical JSON") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SolverContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json_object(data: bytes, where: str) -> dict[str, object]:
    try:
        decoded = data.decode("utf-8")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                SolverContractError(f"non-finite JSON number: {constant}")
            ),
        )
    except (
        UnicodeError,
        ValueError,
        RecursionError,
        SolverContractError,
    ) as exc:
        raise SolverContractError(f"{where} is not strict JSON") from exc
    if type(value) is not dict:
        raise SolverContractError(f"{where} must be a JSON object")
    return value


def _read_regular_at(
    parent_fd: int,
    name: str,
    *,
    where: str,
    max_bytes: int,
) -> bytes:
    try:
        entry = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise SolverContractError(f"cannot inspect {where}") from exc
    if stat.S_ISLNK(entry.st_mode):
        raise SolverContractError(f"{where} must not be a symlink")
    if not stat.S_ISREG(entry.st_mode):
        raise SolverContractError(f"{where} must be a regular file")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise SolverContractError(f"cannot open {where}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SolverContractError(f"{where} must be a regular file")
        if metadata.st_size > max_bytes:
            raise SolverContractError(f"{where} is too large")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise SolverContractError(f"{where} was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise SolverContractError(f"{where} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        raise SolverContractError(
            "secure checkpoint directory operations are unsupported"
        )
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_absolute_directory(path: Path, *, create: bool) -> int:
    """Open an absolute directory through a no-follow component walk."""

    if not path.is_absolute():
        raise SolverContractError("checkpoint directory must be absolute")
    flags = _directory_flags()
    current = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            try:
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=current)
            except OSError as exc:
                raise SolverContractError(
                    "checkpoint directory contains a symlink or non-directory"
                ) from exc
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _open_relative_directory(
    root_fd: int, components: tuple[str, ...], *, create: bool
) -> int:
    flags = _directory_flags()
    current = os.dup(root_fd)
    try:
        for component in components:
            try:
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o700, dir_fd=current)
                except FileExistsError:
                    pass
                child = os.open(component, flags, dir_fd=current)
            except OSError as exc:
                raise SolverContractError(
                    "checkpoint directory contains a symlink or non-directory"
                ) from exc
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _directory_fd_matches_path(descriptor: int, path: Path) -> bool:
    try:
        path_descriptor = _open_absolute_directory(path, create=False)
    except (OSError, SolverContractError):
        return False
    try:
        by_path = os.fstat(path_descriptor)
        by_fd = os.fstat(descriptor)
        return (
            by_path.st_dev == by_fd.st_dev
            and by_path.st_ino == by_fd.st_ino
        )
    finally:
        os.close(path_descriptor)


def _regular_entry_matches_metadata_at(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
) -> bool:
    """Return whether ``name`` still identifies the expected regular inode."""

    try:
        observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISREG(expected.st_mode)
        and stat.S_ISREG(observed.st_mode)
        and observed.st_dev == expected.st_dev
        and observed.st_ino == expected.st_ino
        and observed.st_mode == expected.st_mode
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class SolveRequest:
    seed: int
    max_seconds: float
    work_dir: Path
    single_worker: bool = True
    exclude_secret: tuple[int, ...] | None = field(default=None, repr=False)
    parameters: Mapping[str, object] = field(default_factory=dict)
    resume_checkpoint: Path | None = None
    checkpoint_every_work_units: int = 10_000

    def __post_init__(self) -> None:
        seed = _exact_nonnegative_int(self.seed, "seed")
        max_seconds = _finite_positive(self.max_seconds, "max_seconds")
        if type(self.single_worker) is not bool or not self.single_worker:
            raise SolverContractError("single_worker must be true")
        interval = _exact_positive_int(
            self.checkpoint_every_work_units,
            "checkpoint_every_work_units",
        )
        work_dir = _canonical_work_path(self.work_dir, "work_dir")

        exclude = self.exclude_secret
        if exclude is not None:
            if type(exclude) is not tuple or any(type(item) is not int for item in exclude):
                raise SolverContractError("exclude_secret must be an immutable integer tuple")
            exclude = tuple(exclude)

        frozen_parameters = _freeze_json(self.parameters, where="parameters")
        if not isinstance(frozen_parameters, Mapping):
            raise SolverContractError("parameters must be a JSON object")

        resume = self.resume_checkpoint
        if resume is not None:
            if not isinstance(resume, Path):
                raise SolverContractError("resume_checkpoint must be a pathlib.Path")
            if resume.is_symlink():
                raise SolverContractError(
                    "resume_checkpoint must be a regular non-symlink file"
                )
            if resume.exists() and not resume.is_file():
                raise SolverContractError(
                    "resume_checkpoint must be a regular non-symlink file"
                )
            resume = resume.resolve(strict=False)
            if not _path_within(resume, work_dir):
                raise SolverContractError(
                    "resume_checkpoint must remain inside work_dir"
                )

        object.__setattr__(self, "seed", seed)
        object.__setattr__(self, "max_seconds", max_seconds)
        object.__setattr__(self, "work_dir", work_dir)
        object.__setattr__(self, "exclude_secret", exclude)
        object.__setattr__(self, "parameters", frozen_parameters)
        object.__setattr__(self, "resume_checkpoint", resume)
        object.__setattr__(self, "checkpoint_every_work_units", interval)


@dataclass(frozen=True, slots=True, init=False)
class SolveResult:
    status: SolveStatus
    secret: tuple[int, ...] | None = field(repr=False)
    elapsed_seconds: float
    work_units: int
    peak_rss_bytes: int
    checkpoint_count: int
    detail: Mapping[str, object] = field(repr=False)

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("SolveResult must be constructed through a status factory")

    @classmethod
    def _create(
        cls,
        *,
        status: SolveStatus,
        secret: tuple[int, ...] | None,
        elapsed_seconds: float,
        work_units: int,
        peak_rss_bytes: int,
        checkpoint_count: int,
        detail: Mapping[str, object] | None,
    ) -> "SolveResult":
        if type(status) is not SolveStatus:
            raise SolverContractError("status must be a SolveStatus")
        elapsed = _finite_nonnegative(elapsed_seconds, "elapsed_seconds")
        work = _exact_nonnegative_int(work_units, "work_units")
        peak = _exact_nonnegative_int(peak_rss_bytes, "peak_rss_bytes")
        checkpoints = _exact_nonnegative_int(
            checkpoint_count, "checkpoint_count"
        )
        if status is SolveStatus.SUCCESS:
            if type(secret) is not tuple or any(
                type(item) is not int for item in secret
            ):
                raise SolverContractError(
                    "SUCCESS requires an immutable integer secret"
                )
            frozen_secret: tuple[int, ...] | None = tuple(secret)
        else:
            if secret is not None:
                raise SolverContractError(
                    "only SUCCESS may contain a secret"
                )
            frozen_secret = None
        frozen_detail = _freeze_json(
            {} if detail is None else detail,
            where="detail",
        )
        if not isinstance(frozen_detail, Mapping):
            raise SolverContractError("detail must be a JSON object")

        result = object.__new__(cls)
        object.__setattr__(result, "status", status)
        object.__setattr__(result, "secret", frozen_secret)
        object.__setattr__(result, "elapsed_seconds", elapsed)
        object.__setattr__(result, "work_units", work)
        object.__setattr__(result, "peak_rss_bytes", peak)
        object.__setattr__(result, "checkpoint_count", checkpoints)
        object.__setattr__(result, "detail", frozen_detail)
        return result

    @classmethod
    def success(
        cls,
        *,
        secret: tuple[int, ...],
        elapsed_seconds: float,
        work_units: int,
        peak_rss_bytes: int = 0,
        checkpoint_count: int = 0,
        detail: Mapping[str, object] | None = None,
    ) -> "SolveResult":
        return cls._create(
            status=SolveStatus.SUCCESS,
            secret=secret,
            elapsed_seconds=elapsed_seconds,
            work_units=work_units,
            peak_rss_bytes=peak_rss_bytes,
            checkpoint_count=checkpoint_count,
            detail=detail,
        )

    @classmethod
    def exhausted(
        cls,
        *,
        elapsed_seconds: float,
        work_units: int,
        peak_rss_bytes: int = 0,
        checkpoint_count: int = 0,
        detail: Mapping[str, object] | None = None,
    ) -> "SolveResult":
        return cls._create(
            status=SolveStatus.EXHAUSTED,
            secret=None,
            elapsed_seconds=elapsed_seconds,
            work_units=work_units,
            peak_rss_bytes=peak_rss_bytes,
            checkpoint_count=checkpoint_count,
            detail=detail,
        )

    @classmethod
    def censored(
        cls,
        *,
        elapsed_seconds: float,
        work_units: int,
        peak_rss_bytes: int = 0,
        checkpoint_count: int = 0,
        detail: Mapping[str, object] | None = None,
    ) -> "SolveResult":
        return cls._create(
            status=SolveStatus.CENSORED,
            secret=None,
            elapsed_seconds=elapsed_seconds,
            work_units=work_units,
            peak_rss_bytes=peak_rss_bytes,
            checkpoint_count=checkpoint_count,
            detail=detail,
        )

    @classmethod
    def error(
        cls,
        *,
        elapsed_seconds: float,
        work_units: int,
        peak_rss_bytes: int = 0,
        checkpoint_count: int = 0,
        detail: Mapping[str, object] | None = None,
    ) -> "SolveResult":
        return cls._create(
            status=SolveStatus.ERROR,
            secret=None,
            elapsed_seconds=elapsed_seconds,
            work_units=work_units,
            peak_rss_bytes=peak_rss_bytes,
            checkpoint_count=checkpoint_count,
            detail=detail,
        )


class ExactSolver(Protocol):
    solver_id: str

    def solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult: ...


def _peak_rss_bytes() -> int:
    try:
        import resource

        observed = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except (ImportError, OSError, ValueError):
        return 0
    return observed if sys.platform == "darwin" else observed * 1024


def _request_memory_cap(request: SolveRequest) -> int | None:
    keys = tuple(
        key
        for key in ("memory_cap_bytes", "mitm_memory_cap_bytes")
        if key in request.parameters
    )
    if len(keys) > 1:
        raise SolverContractError("memory cap aliases are mutually exclusive")
    if not keys:
        return None
    value = request.parameters[keys[0]]
    if type(value) is not int or value <= 0:
        raise SolverContractError("memory cap must be a positive integer")
    return value


class ValidatedExactSolver:
    solver_id: str

    @final
    def solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult:
        if not isinstance(request, SolveRequest):
            raise SolverContractError("request must be a SolveRequest")
        wrapper_started = monotonic()
        result = self._solve(instance, request)
        validation_started = monotonic()
        validated = validate_solve_result(instance, request, result)
        finished = monotonic()
        observed_elapsed = max(
            validated.elapsed_seconds
            + max(0.0, finished - validation_started),
            max(0.0, finished - wrapper_started),
        )
        observed_peak_rss = max(
            validated.peak_rss_bytes,
            _peak_rss_bytes(),
        )
        memory_cap = _request_memory_cap(request)
        if (
            validated.status in (SolveStatus.SUCCESS, SolveStatus.EXHAUSTED)
            and memory_cap is not None
            and observed_peak_rss > memory_cap
        ):
            return SolveResult.censored(
                elapsed_seconds=observed_elapsed,
                work_units=validated.work_units,
                peak_rss_bytes=observed_peak_rss,
                checkpoint_count=validated.checkpoint_count,
                detail={
                    "reason": "memory_cap",
                    "public_parameters": {
                        "cap": memory_cap,
                        "cap_unit": "bytes",
                        "memory_cap_bytes": memory_cap,
                    },
                },
            )
        if (
            validated.status in (SolveStatus.SUCCESS, SolveStatus.EXHAUSTED)
            and observed_elapsed >= request.max_seconds
        ):
            return SolveResult.censored(
                elapsed_seconds=observed_elapsed,
                work_units=validated.work_units,
                peak_rss_bytes=observed_peak_rss,
                checkpoint_count=validated.checkpoint_count,
                detail={
                    "reason": "time_cap",
                    "public_parameters": {
                        "cap": request.max_seconds,
                        "cap_unit": "seconds",
                        "max_seconds": request.max_seconds,
                    },
                },
            )
        common = {
            "elapsed_seconds": observed_elapsed,
            "work_units": validated.work_units,
            "peak_rss_bytes": observed_peak_rss,
            "checkpoint_count": validated.checkpoint_count,
            "detail": validated.detail,
        }
        if validated.status is SolveStatus.SUCCESS:
            secret = validated.secret
            assert secret is not None
            return SolveResult.success(secret=secret, **common)
        if validated.status is SolveStatus.EXHAUSTED:
            return SolveResult.exhausted(**common)
        if validated.status is SolveStatus.CENSORED:
            return SolveResult.censored(**common)
        assert validated.status is SolveStatus.ERROR
        return SolveResult.error(**common)

    def _solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult:
        raise NotImplementedError


def validate_solve_result(
    instance: ExactProblem, request: SolveRequest, result: SolveResult
) -> SolveResult:
    """Validate the private solver boundary before exposing a result."""

    if not isinstance(request, SolveRequest):
        raise SolverContractError("request must be a SolveRequest")
    if not isinstance(result, SolveResult):
        raise SolverContractError("solver body must return SolveResult")
    if result.status is SolveStatus.SUCCESS:
        secret = result.secret
        if secret is None:
            raise SolverContractError("SUCCESS did not contain a secret")
        if request.exclude_secret is not None and secret == request.exclude_secret:
            raise SolverContractError("solver returned the excluded witness")
        try:
            verdict = instance.validate_secret(secret)
        except Exception as exc:
            raise SolverContractError(
                "solver success did not produce an accepted witness"
            ) from exc
        if getattr(verdict, "ok", None) is not True:
            raise SolverContractError(
                "solver success did not produce an accepted witness"
            )
    return result


def scrub_public_detail(
    detail: Mapping[str, object],
    *,
    max_depth: int = _MAX_DEPTH,
    max_nodes: int = _MAX_NODES,
    max_string_bytes: int = _MAX_STRING_BYTES,
    max_array_items: int = _MAX_ARRAY_ITEMS,
) -> dict[str, object]:
    """Return a JSON-native, witness-free copy of solver detail.

    The explicit limit arguments document the public contract.  Only the fixed
    protocol limits are accepted so a caller cannot accidentally weaken it.
    """

    if (
        max_depth,
        max_nodes,
        max_string_bytes,
        max_array_items,
    ) != (_MAX_DEPTH, _MAX_NODES, _MAX_STRING_BYTES, _MAX_ARRAY_ITEMS):
        raise SolverContractError("public detail limits are protocol constants")
    frozen = _freeze_json(detail, where="detail")
    if not isinstance(frozen, Mapping):
        raise SolverContractError("detail must be a JSON object")
    _validate_public_detail(frozen)
    public = _public_json(frozen)
    assert isinstance(public, dict)
    return public


def _validate_public_detail(detail: Mapping[str, object]) -> None:
    unknown = frozenset(detail).difference(_PUBLIC_DETAIL_KEYS)
    if unknown:
        raise SolverContractError(
            f"public detail contains unsupported field: {sorted(unknown)[0]}"
        )
    for stable_field in ("code", "reason", "certificate_id"):
        if stable_field not in detail:
            continue
        value = detail[stable_field]
        if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
            raise SolverContractError(
                f"public detail {stable_field} must be a stable ASCII identifier"
            )
    if "certificate_digest" in detail:
        value = detail["certificate_digest"]
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise SolverContractError(
                "public detail certificate_digest must be lowercase SHA-256"
            )
    if "public_parameters" in detail:
        parameters = detail["public_parameters"]
        if type(parameters) is not _MAPPING_PROXY_TYPE:
            raise SolverContractError(
                "public detail public_parameters must be a JSON object"
            )
        unknown_parameters = frozenset(parameters).difference(
            _PUBLIC_PARAMETER_KEYS
        )
        if unknown_parameters:
            raise SolverContractError(
                "public detail contains unsupported public parameter: "
                f"{sorted(unknown_parameters)[0]}"
            )
        for key, value in parameters.items():
            _validate_public_parameter_value(key, value)
        if (
            "range_start" in parameters
            and "range_stop" in parameters
            and parameters["range_stop"] < parameters["range_start"]
        ):
            raise SolverContractError(
                "public detail range_stop must not precede range_start"
            )


def _validate_public_parameter_value(key: str, value: object) -> None:
    where = f"public_parameters.{key}"
    if key in _POSITIVE_PUBLIC_INTS:
        if type(value) is not int or value <= 0:
            raise SolverContractError(
                f"public detail {where} must be a positive integer"
            )
        return
    if key in _NONNEGATIVE_PUBLIC_INTS:
        if type(value) is not int or value < 0:
            raise SolverContractError(
                f"public detail {where} must be a non-negative integer"
            )
        return
    if key in {"cap", "max_seconds"}:
        valid = type(value) in (int, float)
        if valid:
            try:
                observed = float(value)
            except (OverflowError, ValueError):
                valid = False
            else:
                valid = (
                    math.isfinite(observed)
                    and observed >= 0
                    and not (key == "max_seconds" and observed == 0)
                )
        if not valid:
            qualifier = "positive" if key == "max_seconds" else "non-negative"
            raise SolverContractError(
                f"public detail {where} must be a finite {qualifier} number"
            )
        return
    if key == "cap_unit":
        if type(value) is not str or value not in _CAP_UNITS:
            raise SolverContractError(
                f"public detail {where} is not an allowed unit"
            )
        return
    raise SolverContractError(f"public detail {where} has no value schema")


def scrub_result(result: SolveResult) -> dict[str, object]:
    if not isinstance(result, SolveResult):
        raise SolverContractError("result must be a SolveResult")
    detail = scrub_public_detail(result.detail)
    return {
        "status": result.status.value,
        "elapsed_seconds": result.elapsed_seconds,
        "work_units": result.work_units,
        "peak_rss_bytes": result.peak_rss_bytes,
        "checkpoint_count": result.checkpoint_count,
        "detail": detail,
    }


@dataclass(frozen=True, slots=True, kw_only=True)
class ProgressEvent:
    solver_id: str
    instance_id: str
    elapsed_seconds: float
    work_units: int
    phase: str
    peak_rss_bytes: int = 0
    checkpoint_count: int = 0

    def __post_init__(self) -> None:
        for name in ("solver_id", "instance_id", "phase"):
            value = getattr(self, name)
            if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
                raise SolverContractError(f"{name} must be a stable ASCII identifier")
        object.__setattr__(
            self,
            "elapsed_seconds",
            _finite_nonnegative(self.elapsed_seconds, "elapsed_seconds"),
        )
        object.__setattr__(
            self, "work_units", _exact_nonnegative_int(self.work_units, "work_units")
        )
        object.__setattr__(
            self,
            "peak_rss_bytes",
            _exact_nonnegative_int(self.peak_rss_bytes, "peak_rss_bytes"),
        )
        object.__setattr__(
            self,
            "checkpoint_count",
            _exact_nonnegative_int(self.checkpoint_count, "checkpoint_count"),
        )

    def to_public_dict(self) -> dict[str, object]:
        return {
            "solver_id": self.solver_id,
            "instance_id": self.instance_id,
            "elapsed_seconds": self.elapsed_seconds,
            "work_units": self.work_units,
            "phase": self.phase,
            "peak_rss_bytes": self.peak_rss_bytes,
            "checkpoint_count": self.checkpoint_count,
        }


def append_progress(path: Path, event: ProgressEvent) -> None:
    """Append one canonical, monotone, secret-free progress event."""

    if not isinstance(path, Path):
        raise SolverContractError("progress path must be a pathlib.Path")
    if not isinstance(event, ProgressEvent):
        raise SolverContractError("progress event must be a ProgressEvent")
    absolute = Path(os.path.abspath(path))
    try:
        parent_fd = _open_absolute_directory(absolute.parent, create=True)
    except OSError as exc:
        raise SolverContractError("cannot open progress directory") from exc

    try:
        try:
            entry = os.stat(
                absolute.name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(entry.st_mode):
                raise SolverContractError("progress log must not be a symlink")
            if not stat.S_ISREG(entry.st_mode):
                raise SolverContractError("progress log must be a regular file")

        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                absolute.name,
                flags,
                0o600,
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise SolverContractError("cannot open progress log") from exc
        locked = False
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise SolverContractError("progress log must be a regular file")
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            locked = True

            metadata = os.fstat(descriptor)
            if metadata.st_size > _MAX_PROGRESS_BYTES:
                raise SolverContractError("progress log is too large")
            os.lseek(descriptor, 0, os.SEEK_SET)
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise SolverContractError(
                        "progress log was truncated while reading"
                    )
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise SolverContractError("progress log changed while reading")
            data = b"".join(chunks)
            if data and not data.endswith(b"\n"):
                raise SolverContractError("progress log contains a partial record")

            previous: ProgressEvent | None = None
            for line in data.splitlines():
                raw = _strict_json_object(line, "progress record")
                if frozenset(raw) != _PROGRESS_KEYS:
                    raise SolverContractError(
                        "progress record has unexpected fields"
                    )
                try:
                    parsed = ProgressEvent(**raw)  # type: ignore[arg-type]
                except (TypeError, SolverContractError) as exc:
                    raise SolverContractError(
                        "progress record is malformed"
                    ) from exc
                if previous is not None:
                    _validate_progress_successor(previous, parsed)
                previous = parsed
            if previous is not None:
                _validate_progress_successor(previous, event)

            encoded = _canonical_json_bytes(event.to_public_dict())
            if metadata.st_size + len(encoded) > _MAX_PROGRESS_BYTES:
                raise SolverContractError("progress log is too large")
            os.lseek(descriptor, 0, os.SEEK_END)
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise SolverContractError(
                        "progress record write was incomplete"
                    )
                offset += written
            os.fsync(descriptor)
            os.fsync(parent_fd)
            if not _directory_fd_matches_path(parent_fd, absolute.parent):
                raise SolverContractError(
                    "progress parent directory changed during write"
                )
            if not _regular_entry_matches_metadata_at(
                parent_fd,
                absolute.name,
                os.fstat(descriptor),
            ):
                raise SolverContractError("progress log changed during write")
        except OSError as exc:
            raise SolverContractError("progress transaction failed") from exc
        finally:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _validate_progress_successor(
    previous: ProgressEvent, current: ProgressEvent
) -> None:
    if (
        current.solver_id != previous.solver_id
        or current.instance_id != previous.instance_id
    ):
        raise SolverContractError("progress identity changed")
    monotone = (
        ("elapsed_seconds", current.elapsed_seconds, previous.elapsed_seconds),
        ("work_units", current.work_units, previous.work_units),
        ("peak_rss_bytes", current.peak_rss_bytes, previous.peak_rss_bytes),
        (
            "checkpoint_count",
            current.checkpoint_count,
            previous.checkpoint_count,
        ),
    )
    for field_name, observed, prior in monotone:
        if observed < prior:
            raise SolverContractError(f"progress {field_name} regressed")


@dataclass(frozen=True, slots=True, kw_only=True)
class CheckpointStore:
    work_dir: Path
    solver_id: str
    solver_revision: str
    instance_digest: str
    seed: int

    def __post_init__(self) -> None:
        work_dir = _canonical_work_path(self.work_dir, "checkpoint work_dir")
        for name in ("solver_id", "solver_revision"):
            value = getattr(self, name)
            if type(value) is not str or _SAFE_ID.fullmatch(value) is None:
                raise SolverContractError(
                    f"checkpoint {name} must be a stable ASCII identifier"
                )
        if (
            type(self.instance_digest) is not str
            or _SHA256.fullmatch(self.instance_digest) is None
        ):
            raise SolverContractError(
                "checkpoint instance_digest must be lowercase SHA-256"
            )
        seed = _exact_nonnegative_int(self.seed, "checkpoint seed")
        object.__setattr__(self, "work_dir", work_dir)
        object.__setattr__(self, "seed", seed)

    @property
    def default_path(self) -> Path:
        return self.work_dir / f"{self.solver_id}.checkpoint.json"

    def _location(
        self, path: Path | None
    ) -> tuple[Path, tuple[str, ...], str]:
        selected = self.default_path if path is None else path
        if not isinstance(selected, Path):
            raise SolverContractError("checkpoint path must be a pathlib.Path")
        absolute = Path(os.path.abspath(selected))
        try:
            relative = absolute.relative_to(self.work_dir)
        except ValueError:
            raise SolverContractError("checkpoint path must remain inside work_dir")
        if not relative.parts or relative.name in ("", ".", ".."):
            raise SolverContractError("checkpoint path must name a file")
        return absolute, tuple(relative.parts[:-1]), relative.name

    def _open_parent(
        self, components: tuple[str, ...], *, create: bool
    ) -> int:
        root_fd = _open_absolute_directory(self.work_dir, create=create)
        try:
            return _open_relative_directory(root_fd, components, create=create)
        finally:
            os.close(root_fd)

    def _validated_payload_at(
        self, parent_fd: int, name: str
    ) -> dict[str, object]:
        try:
            data = _read_regular_at(
                parent_fd,
                name,
                where="checkpoint",
                max_bytes=_MAX_CHECKPOINT_BYTES,
            )
        except FileNotFoundError as exc:
            raise SolverContractError("checkpoint does not exist") from exc
        raw = _strict_json_object(data, "checkpoint")
        if frozenset(raw) != _CHECKPOINT_KEYS:
            raise SolverContractError("checkpoint has unexpected fields")
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise SolverContractError("checkpoint schema_version must be integer 1")
        expected_binding = {
            "solver_id": self.solver_id,
            "solver_revision": self.solver_revision,
            "instance_digest": self.instance_digest,
            "seed": self.seed,
        }
        if any(
            type(raw[key]) is not type(value) or raw[key] != value
            for key, value in expected_binding.items()
        ):
            raise SolverContractError("checkpoint binding does not match this run")
        _exact_nonnegative_int(raw["work_units"], "checkpoint work_units")
        frozen_state = _freeze_json(
            raw["state"],
            where="checkpoint state",
            max_depth=64,
            max_nodes=1_000_000,
            max_string_bytes=1_048_576,
            max_array_items=1_000_000,
        )
        if not isinstance(frozen_state, Mapping):
            raise SolverContractError("checkpoint state must be a JSON object")
        raw["state"] = frozen_state
        return raw

    def save(
        self, state: Mapping[str, object], *, work_units: int, path: Path | None = None
    ) -> Path:
        destination, parent_components, destination_name = self._location(path)
        work = _exact_nonnegative_int(work_units, "checkpoint work_units")
        frozen_state = _freeze_json(
            state,
            where="checkpoint state",
            max_depth=64,
            max_nodes=1_000_000,
            max_string_bytes=1_048_576,
            max_array_items=1_000_000,
        )
        if not isinstance(frozen_state, Mapping):
            raise SolverContractError("checkpoint state must be a JSON object")

        try:
            parent_fd = self._open_parent(parent_components, create=True)
        except OSError as exc:
            raise SolverContractError("cannot open checkpoint directory") from exc
        try:
            fcntl.flock(parent_fd, fcntl.LOCK_EX)
        except OSError as exc:
            os.close(parent_fd)
            raise SolverContractError(
                "cannot lock checkpoint transaction"
            ) from exc
        try:
            try:
                prior = self._validated_payload_at(parent_fd, destination_name)
            except SolverContractError as exc:
                if exc.__cause__ is not None and isinstance(
                    exc.__cause__, FileNotFoundError
                ):
                    prior = None
                else:
                    raise
            if prior is not None:
                prior_work = prior["work_units"]
                assert type(prior_work) is int
                if work < prior_work:
                    raise SolverContractError("checkpoint work_units regressed")

            payload = {
                "schema_version": 1,
                "solver_id": self.solver_id,
                "solver_revision": self.solver_revision,
                "instance_digest": self.instance_digest,
                "seed": self.seed,
                "work_units": work,
                "state": _public_json(frozen_state),
            }
            encoded = _canonical_json_bytes(payload)
            if len(encoded) > _MAX_CHECKPOINT_BYTES:
                raise SolverContractError("checkpoint is too large")

            temporary_fd = -1
            temporary_name: str | None = None
            temporary_metadata: os.stat_result | None = None
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                for _ in range(32):
                    candidate_name = (
                        f".{destination_name}.tmp-{secrets.token_hex(12)}"
                    )
                    try:
                        temporary_fd = os.open(
                            candidate_name,
                            flags,
                            0o600,
                            dir_fd=parent_fd,
                        )
                    except FileExistsError:
                        continue
                    temporary_name = candidate_name
                    break
                if temporary_fd < 0 or temporary_name is None:
                    raise SolverContractError(
                        "cannot allocate unique checkpoint temporary file"
                    )
                os.fchmod(temporary_fd, 0o600)
                temporary_metadata = os.fstat(temporary_fd)
                if (
                    not stat.S_ISREG(temporary_metadata.st_mode)
                    or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
                ):
                    raise SolverContractError(
                        "checkpoint temporary file must be regular mode 0600"
                    )
                offset = 0
                while offset < len(encoded):
                    written = os.write(temporary_fd, encoded[offset:])
                    if written <= 0:
                        raise SolverContractError(
                            "checkpoint temporary write was incomplete"
                        )
                    offset += written
                os.fsync(temporary_fd)
                os.close(temporary_fd)
                temporary_fd = -1

                try:
                    destination_stat = os.stat(
                        destination_name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    pass
                else:
                    if not stat.S_ISREG(destination_stat.st_mode):
                        raise SolverContractError(
                            "checkpoint path must be a regular non-symlink file"
                        )
                os.replace(
                    temporary_name,
                    destination_name,
                    src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd,
                )
                temporary_name = None
                os.fsync(parent_fd)
                if not _directory_fd_matches_path(parent_fd, destination.parent):
                    raise SolverContractError(
                        "checkpoint parent directory changed during write"
                    )
                if (
                    temporary_metadata is None
                    or not _regular_entry_matches_metadata_at(
                        parent_fd,
                        destination_name,
                        temporary_metadata,
                    )
                    or stat.S_IMODE(temporary_metadata.st_mode) != 0o600
                ):
                    raise SolverContractError(
                        "checkpoint changed during write"
                    )
            except SolverContractError:
                raise
            except OSError as exc:
                raise SolverContractError(
                    "cannot atomically write checkpoint"
                ) from exc
            finally:
                if temporary_fd >= 0:
                    os.close(temporary_fd)
                if temporary_name is not None:
                    try:
                        os.unlink(temporary_name, dir_fd=parent_fd)
                    except FileNotFoundError:
                        pass
        finally:
            try:
                fcntl.flock(parent_fd, fcntl.LOCK_UN)
            except OSError as exc:
                raise SolverContractError(
                    "cannot unlock checkpoint transaction"
                ) from exc
            finally:
                os.close(parent_fd)
        return destination

    def load(self, path: Path | None = None) -> Mapping[str, object] | None:
        selected, parent_components, selected_name = self._location(path)
        try:
            parent_fd = self._open_parent(parent_components, create=False)
        except FileNotFoundError as exc:
            if path is None:
                return None
            raise SolverContractError("checkpoint does not exist") from exc
        except OSError as exc:
            raise SolverContractError("cannot open checkpoint directory") from exc
        try:
            try:
                payload = self._validated_payload_at(parent_fd, selected_name)
            except SolverContractError as exc:
                if exc.__cause__ is not None and isinstance(
                    exc.__cause__, FileNotFoundError
                ):
                    if path is None:
                        return None
                    raise SolverContractError("checkpoint does not exist") from exc
                raise
            if not _directory_fd_matches_path(parent_fd, selected.parent):
                raise SolverContractError(
                    "checkpoint parent directory changed during read"
                )
            state = payload["state"]
            assert isinstance(state, Mapping)
            return state
        finally:
            os.close(parent_fd)
