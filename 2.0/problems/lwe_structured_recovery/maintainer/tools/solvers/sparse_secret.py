"""Clean-room exact recovery for public exact-weight secret domains.

The module depends only on the stable public instance facade exposed through
the protocol in :mod:`tools.solvers.api`.  Its helpers are deterministic and
side-effect free so exact traversal boundaries can be reviewed without running
secret recovery.
"""

from __future__ import annotations

import hashlib
import fcntl
import json
import os
import secrets
import stat
import sys
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations, islice, product
from math import comb
from pathlib import Path
from time import monotonic

from .api import (
    CheckpointStore,
    ValidatedExactSolver,
    ProgressEvent,
    SolveRequest,
    SolveResult,
    SolverContractError,
    append_progress,
)


def _canonical_nonzero_values(values: Sequence[int]) -> tuple[int, ...]:
    if any(type(value) is not int for value in values):
        raise ValueError("alphabet values must be integers")
    if not values or 0 in values or len(set(values)) != len(values):
        raise ValueError("alphabet must contain distinct nonzero values")
    return tuple(sorted(values))


def iter_exact_weight_candidates(
    n: int, weight: int, nonzero_values: Sequence[int]
) -> Iterator[tuple[int, ...]]:
    """Yield the exact-weight domain in support/alphabet lexicographic order."""

    if type(n) is not int or n < 0:
        raise ValueError("n must be a non-negative integer")
    if type(weight) is not int or not 0 <= weight <= n:
        raise ValueError("weight must be an integer in [0, n]")
    values = _canonical_nonzero_values(nonzero_values)
    for support in combinations(range(n), weight):
        for assignment in product(values, repeat=weight):
            candidate = [0] * n
            for index, value in zip(support, assignment, strict=True):
                candidate[index] = value
            yield tuple(candidate)


def sparse_secret_domain_size(n: int, weight: int, alphabet_size: int) -> int:
    """Return the exact number of support/alphabet candidates."""

    if type(n) is not int or n < 0:
        raise ValueError("n must be a non-negative integer")
    if type(weight) is not int or not 0 <= weight <= n:
        raise ValueError("weight must be an integer in [0, n]")
    if type(alphabet_size) is not int or alphabet_size <= 0:
        raise ValueError("alphabet_size must be a positive integer")
    return comb(n, weight) * alphabet_size**weight


def split_coordinate_ranges(n: int) -> tuple[tuple[int, int], tuple[int, int]]:
    """Split the public coordinate range into deterministic disjoint halves."""

    if type(n) is not int or n < 0:
        raise ValueError("n must be a non-negative integer")
    middle = n // 2
    return ((0, middle), (middle, n))


def mitm_partition_counts(
    n: int, weight: int, alphabet_size: int
) -> tuple[tuple[int, int, int, int], ...]:
    """Return ``(left_weight, left, right, pairs)`` for every exact split."""

    domain_size = sparse_secret_domain_size(n, weight, alphabet_size)
    (left_start, left_stop), (right_start, right_stop) = split_coordinate_ranges(n)
    left_size = left_stop - left_start
    right_size = right_stop - right_start
    partitions: list[tuple[int, int, int, int]] = []
    lower = max(0, weight - right_size)
    upper = min(weight, left_size)
    for left_weight in range(lower, upper + 1):
        right_weight = weight - left_weight
        left_count = comb(left_size, left_weight) * alphabet_size**left_weight
        right_count = comb(right_size, right_weight) * alphabet_size**right_weight
        partitions.append(
            (left_weight, left_count, right_count, left_count * right_count)
        )
    if sum(partition[3] for partition in partitions) != domain_size:
        raise AssertionError("MITM partitions do not conserve the exact domain")
    return tuple(partitions)


def centered_representative(residue: int, q: int) -> int:
    """Return the exact centered representative used by the Phase 2 judge."""

    if type(residue) is not int:
        raise ValueError("residue must be an integer")
    if type(q) is not int or q <= 1:
        raise ValueError("q must be an integer greater than one")
    reduced = residue % q
    return reduced - q if reduced >= (q + 1) // 2 else reduced


def streaming_residual_feasible(
    instance,
    candidate: Sequence[int],
    *,
    charge_work: Callable[[str], None] | None = None,
    check_budget: Callable[[], None] | None = None,
) -> bool:
    """Apply only monotone necessary public residual conditions, row by row.

    This is deliberately not a validator.  A ``True`` result merely allows the
    caller to invoke the facade's authoritative ``validate_secret`` method.
    """

    if len(candidate) != instance.n:
        raise ValueError("candidate length does not match public dimension")
    if any(type(value) is not int for value in candidate):
        raise ValueError("candidate must contain integers")

    max_abs = instance.error_max_abs
    max_l1 = instance.error_max_l1
    max_l2 = instance.error_max_l2_squared
    max_nonzero = instance.error_max_nonzero
    partial_l1 = 0
    partial_l2 = 0
    partial_nonzero = 0
    consumed = 0
    if check_budget is not None:
        check_budget()
    rows = iter(instance.iter_rows())
    for row_index in range(instance.m):
        if check_budget is not None:
            check_budget()
        try:
            row = next(rows)
        except StopIteration as exc:
            raise ValueError("public row stream length does not match m") from exc
        if row_index >= len(instance.b):
            raise ValueError("public row stream exceeds b")
        dot_product = 0
        for coefficient, value in zip(row, candidate, strict=True):
            if charge_work is not None:
                charge_work("residual_coefficient")
            dot_product += coefficient * value
        if charge_work is not None:
            charge_work("residual_row")
        residual = centered_representative(
            instance.b[row_index] - dot_product, instance.q
        )
        consumed += 1
        absolute = abs(residual)
        if absolute > max_abs:
            return False
        partial_l1 += absolute
        if max_l1 is not None and partial_l1 > max_l1:
            return False
        partial_l2 += residual * residual
        if max_l2 is not None and partial_l2 > max_l2:
            return False
        partial_nonzero += residual != 0
        if max_nonzero is not None and partial_nonzero > max_nonzero:
            return False
    if check_budget is not None:
        check_budget()
    try:
        next(rows)
    except StopIteration:
        pass
    else:
        raise ValueError("public row stream exceeds m")
    if consumed != instance.m or len(instance.b) != instance.m:
        raise ValueError("public row stream length does not match m")
    return True


def checkpoint_ranges(total: int, interval: int) -> Iterator[tuple[int, int]]:
    """Lazily yield exact resumable half-open ranges."""

    if type(total) is not int or total < 0:
        raise ValueError("total must be a non-negative integer")
    if type(interval) is not int or interval <= 0:
        raise ValueError("interval must be a positive integer")
    for start in range(0, total, interval):
        yield start, min(total, start + interval)


@dataclass(frozen=True, slots=True)
class CoverageRange:
    """One witness-free half-open range in an ordered traversal ledger."""

    start: int
    stop: int

    def __post_init__(self) -> None:
        if (
            type(self.start) is not int
            or type(self.stop) is not int
            or self.start < 0
            or self.stop <= self.start
        ):
            raise ValueError("coverage range must be a nonempty non-negative interval")


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    """Constant-size commitment to canonical checkpoint range coverage."""

    total: int
    interval: int
    range_count: int
    boundary_sum: int
    digest: str


def _coverage_summary_fields(total: int, interval: int) -> tuple[int, int, str]:
    if type(total) is not int or total < 0:
        raise ValueError("total must be a non-negative integer")
    if type(interval) is not int or interval <= 0:
        raise ValueError("interval must be a positive integer")
    range_count = (total + interval - 1) // interval
    boundary_sum = interval * range_count * (range_count - 1) + total
    payload = {
        "schema_version": 1,
        "total": total,
        "interval": interval,
        "range_count": range_count,
        "boundary_sum": boundary_sum,
    }
    digest = hashlib.sha256(
        json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()
    return range_count, boundary_sum, digest


def coverage_summary(total: int, interval: int) -> CoverageSummary:
    range_count, boundary_sum, digest = _coverage_summary_fields(total, interval)
    return CoverageSummary(
        total=total,
        interval=interval,
        range_count=range_count,
        boundary_sum=boundary_sum,
        digest=digest,
    )


def verify_coverage_summary(summary: CoverageSummary) -> None:
    if type(summary) is not CoverageSummary:
        raise ValueError("coverage summary has the wrong type")
    if (
        type(summary.total) is not int
        or type(summary.interval) is not int
        or type(summary.range_count) is not int
        or type(summary.boundary_sum) is not int
        or type(summary.digest) is not str
    ):
        raise ValueError("coverage summary has noncanonical scalar types")
    if summary != coverage_summary(summary.total, summary.interval):
        raise ValueError("coverage summary is not canonical")


def verify_ordered_ranges(
    ranges: Sequence[CoverageRange], *, total: int, interval: int
) -> None:
    """One-pass verification without constructing an expected range tuple."""

    if type(total) is not int or total < 0:
        raise ValueError("coverage ranges have an invalid total")
    if type(interval) is not int or interval <= 0:
        raise ValueError("coverage ranges have an invalid interval")
    cursor = 0
    for item in ranges:
        expected_stop = min(total, cursor + interval)
        if item.start != cursor or item.stop != expected_stop:
            raise ValueError("coverage ranges are not ordered, gapless, and canonical")
        cursor = item.stop
    if cursor != total:
        raise ValueError("coverage ranges are not ordered, gapless, and canonical")


class _RangeLedger:
    """Record actual ordinal visits before independent range verification."""

    def __init__(self, interval: int) -> None:
        if type(interval) is not int or interval <= 0:
            raise ValueError("interval must be a positive integer")
        self._interval = interval
        self._next = 0
        self._range_start = 0
        self._range_count = 0
        self._boundary_sum = 0

    def record(self, ordinal: int) -> None:
        if type(ordinal) is not int or ordinal != self._next:
            raise ValueError("coverage ordinal is skipped, duplicated, or reordered")
        self._next += 1
        if self._next - self._range_start == self._interval:
            self._range_count += 1
            self._boundary_sum += self._range_start + self._next
            self._range_start = self._next

    def finish(self, total: int) -> CoverageSummary:
        if self._next != total:
            raise ValueError("coverage ledger does not reach the declared total")
        if self._range_start != self._next:
            self._range_count += 1
            self._boundary_sum += self._range_start + self._next
            self._range_start = self._next
        result = coverage_summary(total, self._interval)
        if (
            self._range_count != result.range_count
            or self._boundary_sum != result.boundary_sum
        ):
            raise ValueError("coverage ledger summary is inconsistent")
        return result


def _canonical_digest(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


_SPARSE_PROGRESS_KEYS = frozenset(
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
_MAX_SPARSE_PROGRESS_BYTES = 16 * 1024 * 1024


def _progress_chain_step(previous_digest: str, event: ProgressEvent) -> str:
    return _canonical_digest(
        {
            "previous_digest": previous_digest,
            "event": event.to_public_dict(),
        }
    )


def _validate_sparse_progress_successor(
    previous: ProgressEvent,
    current: ProgressEvent,
) -> None:
    if (
        current.solver_id != previous.solver_id
        or current.instance_id != previous.instance_id
    ):
        raise SolverContractError("progress identity changed")
    for field_name in (
        "elapsed_seconds",
        "work_units",
        "peak_rss_bytes",
        "checkpoint_count",
    ):
        if getattr(current, field_name) < getattr(previous, field_name):
            raise SolverContractError(f"progress {field_name} regressed")


def _read_sparse_progress_events(path: Path) -> tuple[ProgressEvent, ...]:
    """Read a complete locked progress log without following a final symlink."""

    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(absolute, flags)
    except FileNotFoundError as exc:
        raise SolverContractError("progress chain is missing") from exc
    except OSError as exc:
        raise SolverContractError("cannot open progress chain") from exc
    locked = False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SolverContractError("progress chain must be a regular file")
        if metadata.st_size > _MAX_SPARSE_PROGRESS_BYTES:
            raise SolverContractError("progress chain is too large")
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        locked = True
        metadata = os.fstat(descriptor)
        if metadata.st_size > _MAX_SPARSE_PROGRESS_BYTES:
            raise SolverContractError("progress chain is too large")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise SolverContractError("progress chain was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise SolverContractError("progress chain changed while reading")
        data = b"".join(chunks)
        if not data or not data.endswith(b"\n"):
            raise SolverContractError("progress chain is incomplete")

        def reject_duplicate_keys(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise SolverContractError("progress chain has duplicate keys")
                result[key] = value
            return result

        events: list[ProgressEvent] = []
        previous: ProgressEvent | None = None
        for line in data.splitlines():
            try:
                raw = json.loads(
                    line.decode("utf-8"),
                    object_pairs_hook=reject_duplicate_keys,
                    parse_constant=lambda constant: (_ for _ in ()).throw(
                        SolverContractError(
                            f"progress chain has non-finite number: {constant}"
                        )
                    ),
                )
            except (
                UnicodeError,
                ValueError,
                RecursionError,
                SolverContractError,
            ) as exc:
                raise SolverContractError("progress chain is not strict JSON") from exc
            if type(raw) is not dict or frozenset(raw) != _SPARSE_PROGRESS_KEYS:
                raise SolverContractError("progress chain record is malformed")
            try:
                event = ProgressEvent(**raw)
            except (TypeError, SolverContractError) as exc:
                raise SolverContractError("progress chain record is malformed") from exc
            if previous is not None:
                _validate_sparse_progress_successor(previous, event)
            events.append(event)
            previous = event
        return tuple(events)
    except OSError as exc:
        raise SolverContractError("progress chain read failed") from exc
    finally:
        if locked:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _progress_identity_state(
    *,
    store: CheckpointStore,
    instance_id: str,
    run_id: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "solver_id": store.solver_id,
        "instance_id": instance_id,
        "work_dir": str(store.work_dir),
        "run_id": run_id,
    }


def _load_or_create_progress_identity(
    *,
    store: CheckpointStore,
    instance_id: str,
    resume: bool,
) -> str:
    identity_path = store.work_dir / f"{store.solver_id}.progress-identity.json"
    if resume:
        try:
            state = store.load(identity_path)
        except SolverContractError as exc:
            raise SolverContractError("progress identity is missing or invalid") from exc
        if state is None:
            raise SolverContractError("progress identity is missing or invalid")
        expected_keys = {
            "schema_version",
            "solver_id",
            "instance_id",
            "work_dir",
            "run_id",
        }
        if frozenset(state) != expected_keys:
            raise SolverContractError("progress identity is malformed")
        run_id = state["run_id"]
        if (
            state["schema_version"] != 1
            or state["solver_id"] != store.solver_id
            or state["instance_id"] != instance_id
            or state["work_dir"] != str(store.work_dir)
            or type(run_id) is not str
            or len(run_id) != 64
            or any(character not in "0123456789abcdef" for character in run_id)
        ):
            raise SolverContractError("progress identity does not match this run")
        identity = _progress_identity_state(
            store=store,
            instance_id=instance_id,
            run_id=run_id,
        )
    else:
        identity = _progress_identity_state(
            store=store,
            instance_id=instance_id,
            run_id=secrets.token_hex(32),
        )
        try:
            store.save(identity, work_units=0, path=identity_path)
        except SolverContractError as exc:
            raise SolverContractError("cannot persist progress identity") from exc
    return _canonical_digest(identity)


@dataclass(slots=True)
class _SparseRunProtocol:
    """Typed, solver-bound checkpoint and progress protocol for Task 4.

    Checkpoints are performance hints, never exhaustion evidence.  The caller
    still has to replay a public certificate from ordinal zero before emitting
    ``EXHAUSTED``.
    """

    request: SolveRequest
    store: CheckpointStore
    solver_id: str
    instance_id: str
    search_digest: str
    domain_size: int
    minimum_work: Callable[[int], int]
    phase_sizes: tuple[tuple[str, int], ...]
    progress_identity_digest: str
    progress_genesis_digest: str
    progress_digest: str
    started: float
    elapsed_base: float = 0.0
    next_ordinal: int = 0
    work_units: int = 0
    checkpoint_count: int = 0
    peak_rss_base: int = 0
    last_checkpoint_work: int = 0
    checkpoint_path: Path | None = None

    @classmethod
    def create(
        cls,
        *,
        instance,
        request: SolveRequest,
        solver_id: str,
        solver_revision: str,
        search_descriptor: Mapping[str, object],
        domain_size: int,
        minimum_work: Callable[[int], int],
        phase_sizes: tuple[tuple[str, int], ...] | None = None,
    ) -> "_SparseRunProtocol":
        if type(domain_size) is not int or domain_size < 0:
            raise SolverContractError("checkpoint domain size is malformed")
        phases = (
            (("search", domain_size),)
            if phase_sizes is None
            else phase_sizes
        )
        if (
            type(phases) is not tuple
            or not phases
            or any(
                type(item) is not tuple
                or len(item) != 2
                or type(item[0]) is not str
                or not item[0]
                or not item[0].isascii()
                or not all(
                    character.isalnum() or character == "_"
                    for character in item[0]
                )
                or type(item[1]) is not int
                or item[1] < 0
                for item in phases
            )
            or len({item[0] for item in phases}) != len(phases)
            or sum(item[1] for item in phases) != domain_size
        ):
            raise SolverContractError("checkpoint phase layout is malformed")
        store = CheckpointStore(
            work_dir=request.work_dir,
            solver_id=solver_id,
            solver_revision=solver_revision,
            instance_digest=instance.instance_digest,
            seed=request.seed,
        )
        progress_identity_digest = _load_or_create_progress_identity(
            store=store,
            instance_id=instance.instance_id,
            resume=request.resume_checkpoint is not None,
        )
        progress_genesis_digest = _canonical_digest(
            {
                "schema_version": 1,
                "progress_identity_digest": progress_identity_digest,
            }
        )
        descriptor = {
            "schema_version": 3,
            "solver_id": solver_id,
            "work_dir": str(store.work_dir),
            "progress_identity_digest": progress_identity_digest,
            "search": dict(search_descriptor),
            "phase_sizes": phases,
            "exclude_digest": _canonical_digest(
                {"exclude_secret": request.exclude_secret}
            ),
        }
        search_digest = _canonical_digest(descriptor)
        protocol = cls(
            request=request,
            store=store,
            solver_id=solver_id,
            instance_id=instance.instance_id,
            search_digest=search_digest,
            domain_size=domain_size,
            minimum_work=minimum_work,
            phase_sizes=phases,
            progress_identity_digest=progress_identity_digest,
            progress_genesis_digest=progress_genesis_digest,
            progress_digest=progress_genesis_digest,
            started=monotonic(),
            checkpoint_path=request.resume_checkpoint,
        )
        if request.resume_checkpoint is not None:
            loaded = store.load(request.resume_checkpoint)
            if loaded is None:
                raise SolverContractError("checkpoint does not exist")
            protocol._restore(loaded)
            protocol._reconcile_resume_progress()
        return protocol

    def _restore(self, state: Mapping[str, object]) -> None:
        expected_keys = {
            "schema_version",
            "search_digest",
            "domain_size",
            "phase",
            "phase_ordinal",
            "next_ordinal",
            "work_units",
            "elapsed_seconds",
            "checkpoint_count",
            "peak_rss_bytes",
            "progress_identity_digest",
            "progress_event_digest",
        }
        if frozenset(state) != expected_keys:
            raise SolverContractError("checkpoint search state is malformed")
        scalar_ints = (
            "schema_version",
            "domain_size",
            "phase_ordinal",
            "next_ordinal",
            "work_units",
            "checkpoint_count",
            "peak_rss_bytes",
        )
        if any(type(state[key]) is not int for key in scalar_ints):
            raise SolverContractError("checkpoint search state is malformed")
        if (
            state["schema_version"] != 3
            or type(state["search_digest"]) is not str
            or state["search_digest"] != self.search_digest
            or state["domain_size"] != self.domain_size
            or type(state["progress_identity_digest"]) is not str
            or state["progress_identity_digest"]
            != self.progress_identity_digest
            or type(state["progress_event_digest"]) is not str
            or len(state["progress_event_digest"]) != 64
            or any(
                character not in "0123456789abcdef"
                for character in state["progress_event_digest"]
            )
        ):
            raise SolverContractError("checkpoint search binding does not match")
        next_ordinal = state["next_ordinal"]
        work_units = state["work_units"]
        checkpoint_count = state["checkpoint_count"]
        peak_rss_bytes = state["peak_rss_bytes"]
        elapsed = state["elapsed_seconds"]
        assert type(next_ordinal) is int
        assert type(work_units) is int
        assert type(checkpoint_count) is int
        assert type(peak_rss_bytes) is int
        canonical_phase, canonical_phase_ordinal = self._phase_position(next_ordinal)
        if (
            not 0 <= next_ordinal <= self.domain_size
            or type(state["phase"]) is not str
            or state["phase"] != canonical_phase
            or state["phase_ordinal"] != canonical_phase_ordinal
            or work_units < self.minimum_work(next_ordinal)
            or checkpoint_count < 0
            or peak_rss_bytes < 0
            or type(elapsed) not in (int, float)
            or isinstance(elapsed, bool)
            or not 0 <= float(elapsed) < float("inf")
        ):
            raise SolverContractError("checkpoint search state is malformed")
        self.next_ordinal = next_ordinal
        self.work_units = work_units
        self.elapsed_base = float(elapsed)
        self.checkpoint_count = checkpoint_count
        self.peak_rss_base = peak_rss_bytes
        self.last_checkpoint_work = work_units
        self.progress_digest = state["progress_event_digest"]

    def _reconcile_resume_progress(self) -> None:
        progress_path = (
            self.request.work_dir / f"{self.solver_id}.progress.jsonl"
        )
        events = _read_sparse_progress_events(progress_path)
        chain_digest = self.progress_genesis_digest
        checkpoint_event: ProgressEvent | None = None
        for event in events:
            if (
                event.solver_id != self.solver_id
                or event.instance_id != self.instance_id
            ):
                raise SolverContractError("progress identity changed")
            chain_digest = _progress_chain_step(chain_digest, event)
            if chain_digest == self.progress_digest:
                checkpoint_event = event
        if checkpoint_event is None:
            raise SolverContractError("checkpoint is orphaned from progress chain")
        if (
            checkpoint_event.elapsed_seconds != self.elapsed_base
            or checkpoint_event.work_units != self.work_units
            or checkpoint_event.peak_rss_bytes != self.peak_rss_base
            or checkpoint_event.checkpoint_count != self.checkpoint_count
        ):
            raise SolverContractError(
                "checkpoint counters do not match progress chain"
            )

        latest = events[-1]
        self.elapsed_base = max(self.elapsed_base, latest.elapsed_seconds)
        self.work_units = max(self.work_units, latest.work_units)
        self.checkpoint_count = max(
            self.checkpoint_count, latest.checkpoint_count
        )
        self.peak_rss_base = max(
            self.peak_rss_base, latest.peak_rss_bytes
        )
        self.last_checkpoint_work = self.work_units
        self.progress_digest = chain_digest
        peak = max(self.peak_rss_base, _peak_rss_bytes())
        resume_event = ProgressEvent(
            solver_id=self.solver_id,
            instance_id=self.instance_id,
            elapsed_seconds=self.elapsed_seconds,
            work_units=self.work_units,
            phase="resume",
            peak_rss_bytes=peak,
            checkpoint_count=self.checkpoint_count,
        )
        append_progress(progress_path, resume_event)
        self.progress_digest = _progress_chain_step(
            self.progress_digest, resume_event
        )
        self.peak_rss_base = peak

    def _phase_position(self, next_ordinal: int) -> tuple[str, int]:
        offset = 0
        for phase, size in self.phase_sizes:
            if next_ordinal < offset + size:
                return phase, next_ordinal - offset
            offset += size
        if next_ordinal == self.domain_size:
            return "complete", 0
        raise SolverContractError("checkpoint traversal position is malformed")

    @property
    def elapsed_seconds(self) -> float:
        return self.elapsed_base + max(0.0, monotonic() - self.started)

    def checkpoint_state(
        self,
        *,
        next_ordinal: int,
        work_units: int,
        checkpoint_count: int,
        elapsed_seconds: float | None = None,
        peak_rss_bytes: int | None = None,
        progress_event_digest: str | None = None,
    ) -> dict[str, object]:
        if (
            type(next_ordinal) is not int
            or not 0 <= next_ordinal <= self.domain_size
            or type(work_units) is not int
            or work_units < self.minimum_work(next_ordinal)
            or type(checkpoint_count) is not int
            or checkpoint_count < 0
        ):
            raise SolverContractError("checkpoint search state is malformed")
        elapsed = self.elapsed_seconds if elapsed_seconds is None else elapsed_seconds
        if (
            type(elapsed) not in (int, float)
            or isinstance(elapsed, bool)
            or not 0 <= float(elapsed) < float("inf")
        ):
            raise SolverContractError("checkpoint elapsed time is malformed")
        peak = (
            max(self.peak_rss_base, _peak_rss_bytes())
            if peak_rss_bytes is None
            else peak_rss_bytes
        )
        if type(peak) is not int or peak < 0:
            raise SolverContractError("checkpoint peak RSS is malformed")
        phase, phase_ordinal = self._phase_position(next_ordinal)
        event_digest = (
            self.progress_digest
            if progress_event_digest is None
            else progress_event_digest
        )
        if (
            type(event_digest) is not str
            or len(event_digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in event_digest
            )
        ):
            raise SolverContractError("checkpoint progress digest is malformed")
        return {
            "schema_version": 3,
            "search_digest": self.search_digest,
            "domain_size": self.domain_size,
            "phase": phase,
            "phase_ordinal": phase_ordinal,
            "next_ordinal": next_ordinal,
            "work_units": work_units,
            "elapsed_seconds": float(elapsed),
            "checkpoint_count": checkpoint_count,
            "peak_rss_bytes": peak,
            "progress_identity_digest": self.progress_identity_digest,
            "progress_event_digest": event_digest,
        }

    def advance(self, *, next_ordinal: int, work_units: int, phase: str) -> None:
        del phase
        if (
            type(next_ordinal) is not int
            or next_ordinal < self.next_ordinal
            or next_ordinal > self.domain_size
            or type(work_units) is not int
            or work_units < self.work_units
            or work_units < self.minimum_work(next_ordinal)
        ):
            raise SolverContractError("checkpoint traversal regressed")
        self.next_ordinal = next_ordinal
        self.work_units = work_units

    def checkpoint(
        self, *, force: bool = False, phase: str = "checkpoint"
    ) -> Path | None:
        if (
            not force
            and self.work_units - self.last_checkpoint_work
            < self.request.checkpoint_every_work_units
        ):
            return self.checkpoint_path
        next_count = self.checkpoint_count + 1
        event_elapsed = self.elapsed_seconds
        event_peak = max(self.peak_rss_base, _peak_rss_bytes())
        event = ProgressEvent(
            solver_id=self.solver_id,
            instance_id=self.instance_id,
            elapsed_seconds=event_elapsed,
            work_units=self.work_units,
            phase=phase,
            peak_rss_bytes=event_peak,
            checkpoint_count=next_count,
        )
        event_digest = _progress_chain_step(self.progress_digest, event)
        state = self.checkpoint_state(
            next_ordinal=self.next_ordinal,
            work_units=self.work_units,
            checkpoint_count=next_count,
            elapsed_seconds=event_elapsed,
            peak_rss_bytes=event_peak,
            progress_event_digest=event_digest,
        )
        append_progress(
            self.request.work_dir / f"{self.solver_id}.progress.jsonl",
            event,
        )
        self.checkpoint_path = self.store.save(
            state,
            work_units=self.work_units,
            path=self.checkpoint_path,
        )
        self.checkpoint_count = next_count
        self.last_checkpoint_work = self.work_units
        self.progress_digest = event_digest
        self.peak_rss_base = event_peak
        return self.checkpoint_path


def _cumulative_deadline(protocol: _SparseRunProtocol) -> float:
    """Return the absolute deadline after subtracting resumed prior runtime."""

    remaining = max(0.0, protocol.request.max_seconds - protocol.elapsed_base)
    return protocol.started + remaining


def complete_domain_certificate(
    *,
    solver_id: str,
    n: int,
    weight: int,
    alphabet_size: int,
    tested_count: int,
    traversal_ranges: CoverageSummary,
    checkpoint_interval: int,
    excluded_count: int,
) -> dict[str, object]:
    """Build the closed public evidence for complete exact-weight traversal."""

    domain_size = sparse_secret_domain_size(n, weight, alphabet_size)
    if type(tested_count) is not int or tested_count != domain_size:
        raise ValueError("a complete certificate requires the full domain count")
    verify_coverage_summary(traversal_ranges)
    if (
        traversal_ranges.total != domain_size
        or traversal_ranges.interval != checkpoint_interval
    ):
        raise ValueError("coverage summary is bound to different traversal parameters")
    if type(excluded_count) is not int or excluded_count != 0:
        raise ValueError("excluded count must be zero")
    support_count = comb(n, weight)
    committed = {
        "schema_version": 1,
        "solver_id": solver_id,
        "n": n,
        "weight": weight,
        "alphabet_size": alphabet_size,
        "support_count": support_count,
        "range_start": 0,
        "range_stop": domain_size,
        "tested_count": tested_count,
        "checkpoint_interval": checkpoint_interval,
        "traversal_summary": {
            "range_count": traversal_ranges.range_count,
            "boundary_sum": traversal_ranges.boundary_sum,
            "digest": traversal_ranges.digest,
        },
        "excluded_count": excluded_count,
    }
    return {
        "certificate_id": "complete_exact_weight_domain_v1",
        "certificate_digest": _canonical_digest(committed),
        "public_parameters": {
            "alphabet_size": alphabet_size,
            "candidate_count": tested_count - excluded_count,
            "checkpoint_interval": checkpoint_interval,
            "covered_work_units": domain_size,
            "domain_size": domain_size,
            "n": n,
            "range_start": 0,
            "range_stop": domain_size,
            "support_count": support_count,
            "tested_count": tested_count,
            "weight": weight,
        },
    }


def _secret_parameters(instance) -> tuple[int, tuple[int, ...]]:
    if instance.secret_distribution_kind not in {
        "exact_weight_alphabet",
        "balanced_exact_weight_signed",
    }:
        raise ValueError("not_exact_weight")
    weight = instance.secret_weight
    if type(weight) is not int or not 0 <= weight <= instance.n:
        raise ValueError("invalid_exact_weight")
    try:
        values = _canonical_nonzero_values(
            tuple(value for value in instance.secret_alphabet if value != 0)
        )
    except ValueError as exc:
        raise ValueError("invalid_secret_alphabet") from exc
    return weight, values


def _require_exact_certificate_value(
    actual: object,
    expected: object,
    *,
    certificate_kind: str,
) -> None:
    """Reject Python values that only compare equal to canonical JSON values."""

    if type(actual) is not type(expected):
        raise ValueError(
            f"{certificate_kind} certificate contains non-canonical JSON types"
        )
    if type(expected) is dict:
        actual_object = actual
        expected_object = expected
        if actual_object.keys() != expected_object.keys():
            raise ValueError(
                f"{certificate_kind} certificate does not replay from public inputs"
            )
        for key in expected_object:
            if type(key) is not str:
                raise ValueError(
                    f"{certificate_kind} certificate contains non-canonical JSON types"
                )
            _require_exact_certificate_value(
                actual_object[key],
                expected_object[key],
                certificate_kind=certificate_kind,
            )
        return
    if type(expected) is list:
        actual_array = actual
        expected_array = expected
        if len(actual_array) != len(expected_array):
            raise ValueError(
                f"{certificate_kind} certificate does not replay from public inputs"
            )
        for actual_item, expected_item in zip(
            actual_array, expected_array, strict=True
        ):
            _require_exact_certificate_value(
                actual_item,
                expected_item,
                certificate_kind=certificate_kind,
            )
        return
    if actual != expected:
        raise ValueError(
            f"{certificate_kind} certificate does not replay from public inputs"
        )


def verify_public_enum_certificate(
    instance,
    request: SolveRequest,
    certificate: Mapping[str, object],
    *,
    charge_work: Callable[[str], None] | None = None,
    check_budget: Callable[[], None] | None = None,
) -> None:
    """Replay an enum exhaustion certificate from public inputs only."""

    if request.exclude_secret is not None:
        raise ValueError("an exclusion cannot support public enum exhaustion")
    if type(certificate) is not dict:
        raise ValueError("enum certificate must be a canonical JSON object")
    weight, values = _secret_parameters(instance)
    domain_size = sparse_secret_domain_size(instance.n, weight, len(values))
    replay = iter(iter_exact_weight_candidates(instance.n, weight, values))
    for _ in range(domain_size):
        if check_budget is not None:
            check_budget()
        try:
            candidate = next(replay)
        except StopIteration as exc:
            raise ValueError("enum replay ended before its exact domain") from exc
        if charge_work is not None:
            charge_work("enum_certificate_candidate")
        if streaming_residual_feasible(
            instance,
            candidate,
            charge_work=charge_work,
            check_budget=check_budget,
        ):
            if charge_work is not None:
                charge_work("enum_certificate_validation")
            verdict = instance.validate_secret(candidate)
            if check_budget is not None:
                check_budget()
            if getattr(verdict, "ok", None) is True:
                raise ValueError("enum exhaustion replay found a public valid witness")
    if check_budget is not None:
        check_budget()
    try:
        next(replay)
    except StopIteration:
        pass
    else:
        raise ValueError("enum replay exceeded its exact domain")
    expected = complete_domain_certificate(
        solver_id="sparse_secret_enum",
        n=instance.n,
        weight=weight,
        alphabet_size=len(values),
        tested_count=domain_size,
        traversal_ranges=coverage_summary(
            domain_size, request.checkpoint_every_work_units
        ),
        checkpoint_interval=request.checkpoint_every_work_units,
        excluded_count=0,
    )
    _require_exact_certificate_value(
        certificate,
        expected,
        certificate_kind="enum",
    )


def enumerator_applicability(
    instance, request: SolveRequest | None = None
) -> tuple[bool, str, dict[str, int]]:
    """Describe exact enumerator applicability without running recovery."""

    del request
    try:
        weight, values = _secret_parameters(instance)
    except ValueError as exc:
        return False, str(exc), {}
    return (
        True,
        "applicable",
        {
            "alphabet_size": len(values),
            "domain_size": sparse_secret_domain_size(
                instance.n, weight, len(values)
            ),
            "n": instance.n,
            "weight": weight,
        },
    )


def _request_parameter(
    request: SolveRequest | None, key: str, default: int
) -> int:
    if request is None or key not in request.parameters:
        return default
    value = request.parameters[key]
    if type(value) is not int:
        raise ValueError(f"{key} must be an integer")
    return value


def select_mitm_rows(instance, request: SolveRequest | None = None) -> tuple[int, ...]:
    """Choose a deterministic contiguous public row prefix for MITM bucketing."""

    default = min(instance.m, 4)
    row_count = _request_parameter(request, "mitm_row_count", default)
    if row_count <= 0 or row_count > instance.m:
        raise ValueError("mitm_row_count must be in [1, m]")
    return tuple(range(row_count))


def mitm_applicability(
    instance, request: SolveRequest | None = None
) -> tuple[bool, str, dict[str, int]]:
    """Describe the public MITM row choice and bucket geometry."""

    applicable, reason, _ = enumerator_applicability(instance, request)
    if not applicable:
        return False, reason, {}
    if type(instance.error_max_abs) is not int or instance.error_max_abs < 0:
        return False, "invalid_error_bound", {}
    try:
        rows = select_mitm_rows(instance, request)
    except ValueError:
        return False, "invalid_row_subset", {}
    seed = request.seed if request is not None else 0
    return (
        True,
        "applicable",
        {
            "bucket_width": 2 * instance.error_max_abs + 1,
            "range_start": rows[0],
            "range_stop": rows[-1] + 1,
            "row_count": len(rows),
            "seed": seed,
            "subset_size": len(rows),
        },
    )


def cyclic_bucket_index(residue: int, *, q: int, bucket_width: int) -> int:
    """Map any integer to its cyclic modulo-q bucket."""

    if type(q) is not int or q <= 1:
        raise ValueError("q must be an integer greater than one")
    if type(bucket_width) is not int or bucket_width <= 0:
        raise ValueError("bucket_width must be a positive integer")
    if type(residue) is not int:
        raise ValueError("residue must be an integer")
    return (residue % q) // bucket_width


class _TraversalCensored(RuntimeError):
    pass


class _MemoryCensored(RuntimeError):
    pass


class _WorkCensored(RuntimeError):
    pass


@dataclass(slots=True)
class _TraversalBudget:
    """One global deadline/work counter shared by search and verification."""

    deadline: float
    work_unit_cap: int
    work_units: int = 0
    memory_cap_bytes: int | None = None
    clock: Callable[[], float] = monotonic
    rss_reader: Callable[[], int] = lambda: _peak_rss_bytes()

    def __post_init__(self) -> None:
        if (
            type(self.work_unit_cap) is not int
            or self.work_unit_cap < 0
            or type(self.work_units) is not int
            or self.work_units < 0
            or self.work_units > self.work_unit_cap
        ):
            raise ValueError("invalid work-unit budget")

    def check(self, *, allocation_bytes: int = 0) -> None:
        if type(allocation_bytes) is not int or allocation_bytes < 0:
            raise ValueError("allocation estimate must be non-negative")
        if (
            self.memory_cap_bytes is not None
            and self.rss_reader() + allocation_bytes > self.memory_cap_bytes
        ):
            raise _MemoryCensored
        if self.clock() >= self.deadline:
            raise _TraversalCensored

    def charge(self, phase: str, units: int = 1) -> None:
        del phase
        self.check()
        if type(units) is not int or units <= 0:
            raise ValueError("work charge must be a positive integer")
        if self.work_units + units > self.work_unit_cap:
            raise _WorkCensored
        self.work_units += units
        self.check()


def _work_unit_cap(request: SolveRequest) -> int:
    value = request.parameters.get("work_unit_cap", 2_000_000)
    if type(value) is not int or value <= 0:
        raise ValueError("work_unit_cap must be a positive integer")
    return value


def _memory_cap(request: SolveRequest) -> int | None:
    keys = tuple(
        key
        for key in ("memory_cap_bytes", "mitm_memory_cap_bytes")
        if key in request.parameters
    )
    if len(keys) > 1:
        raise ValueError("memory cap aliases are mutually exclusive")
    if not keys:
        return None
    value = request.parameters[keys[0]]
    if type(value) is not int or value <= 0:
        raise ValueError("memory cap must be a positive integer")
    return value


def _iter_centered_error_vectors(
    length: int,
    *,
    lower: int,
    upper: int,
    max_l1: int | None,
    max_l2_squared: int | None,
    max_nonzero: int | None,
    should_stop: Callable[[], bool] | None,
    should_stop_memory: Callable[[], bool] | None,
    charge_work: Callable[[str], None] | None = None,
) -> Iterator[tuple[int, ...]]:
    """Lazily enumerate capped centered errors with an iterative DFS."""

    _raise_for_helper_budget(
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
    )
    if type(length) is not int or length < 0:
        raise ValueError("error-vector length must be a non-negative integer")
    if length == 0:
        yield ()
        return

    prefix: list[int] = []
    iterators: list[Iterator[int]] = [iter(range(lower, upper + 1))]
    l1 = 0
    l2 = 0
    nonzero = 0
    while iterators:
        _raise_for_helper_budget(
            should_stop=should_stop,
            should_stop_memory=should_stop_memory,
        )
        try:
            error = next(iterators[-1])
        except StopIteration:
            iterators.pop()
            if prefix:
                removed = prefix.pop()
                l1 -= abs(removed)
                l2 -= removed * removed
                nonzero -= removed != 0
            continue
        if charge_work is not None:
            charge_work("error_neighborhood_node")

        next_l1 = l1 + abs(error)
        if max_l1 is not None and next_l1 > max_l1:
            continue
        next_l2 = l2 + error * error
        if max_l2_squared is not None and next_l2 > max_l2_squared:
            continue
        next_nonzero = nonzero + (error != 0)
        if max_nonzero is not None and next_nonzero > max_nonzero:
            continue

        prefix.append(error)
        l1 = next_l1
        l2 = next_l2
        nonzero = next_nonzero
        if len(prefix) == length:
            _raise_for_helper_budget(
                should_stop=should_stop,
                should_stop_memory=should_stop_memory,
            )
            yield tuple(prefix)
            removed = prefix.pop()
            l1 -= abs(removed)
            l2 -= removed * removed
            nonzero -= removed != 0
        else:
            iterators.append(iter(range(lower, upper + 1)))


def iter_cyclic_neighborhood_bucket_keys(
    targets: Sequence[int],
    *,
    q: int,
    max_abs: int,
    bucket_width: int,
    max_l1: int | None = None,
    max_l2_squared: int | None = None,
    max_nonzero: int | None = None,
    should_stop: Callable[[], bool] | None = None,
    should_stop_memory: Callable[[], bool] | None = None,
    charge_work: Callable[[str], None] | None = None,
    retain_memory: Callable[[int], None] | None = None,
    release_memory: Callable[[int], None] | None = None,
) -> Iterator[tuple[int, ...]]:
    """Enumerate every bucket key compatible with selected-row predicates.

    ``targets[i]`` is ``b_i - right_syndrome_i`` modulo ``q``.  For every
    centered residual vector allowed by all monotone public caps, the matching
    left syndrome bucket is included.  Deduplication removes bucket aliases but
    never a possible left assignment.
    """

    _raise_for_helper_budget(
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
    )
    if type(q) is not int or q <= 1:
        raise ValueError("q must be an integer greater than one")
    if type(bucket_width) is not int or bucket_width <= 0:
        raise ValueError("bucket_width must be a positive integer")
    if type(max_abs) is not int or max_abs < 0:
        raise ValueError("max_abs must be a non-negative integer")
    if any(type(target) is not int for target in targets):
        raise ValueError("targets must contain integers")
    lower = max(-(q // 2), -max_abs)
    upper = min((q - 1) // 2, max_abs)
    # Bucket-set header plus the iterative DFS prefix/iterator stacks.
    retained_bytes = 192 + 128 * len(targets)
    if retain_memory is not None:
        retain_memory(retained_bytes)
    keys: set[tuple[int, ...]] = set()
    for errors in _iter_centered_error_vectors(
        len(targets),
        lower=lower,
        upper=upper,
        max_l1=max_l1,
        max_l2_squared=max_l2_squared,
        max_nonzero=max_nonzero,
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
        charge_work=charge_work,
    ):
        key_parts: list[int] = []
        for target, error in zip(targets, errors, strict=True):
            if charge_work is not None:
                charge_work("error_neighborhood_bucket")
            key_parts.append(
                cyclic_bucket_index(
                    target - error, q=q, bucket_width=bucket_width
                )
            )
        key = tuple(key_parts)
        _raise_for_helper_budget(
            should_stop=should_stop,
            should_stop_memory=should_stop_memory,
        )
        if key not in keys:
            key_bytes = 136 + 36 * len(key)
            if retain_memory is not None:
                retain_memory(key_bytes)
                retained_bytes += key_bytes
            keys.add(key)
            _raise_for_helper_budget(
                should_stop=should_stop,
                should_stop_memory=should_stop_memory,
            )
            yield key
    if release_memory is not None:
        release_memory(retained_bytes)


def cyclic_neighborhood_bucket_keys(
    targets: Sequence[int],
    *,
    q: int,
    max_abs: int,
    bucket_width: int,
    max_l1: int | None = None,
    max_l2_squared: int | None = None,
    max_nonzero: int | None = None,
    should_stop: Callable[[], bool] | None = None,
    should_stop_memory: Callable[[], bool] | None = None,
    charge_work: Callable[[str], None] | None = None,
    retain_memory: Callable[[int], None] | None = None,
    release_memory: Callable[[int], None] | None = None,
) -> tuple[tuple[int, ...], ...]:
    """Materialize the exact helper result for bounded STATIC inspection."""

    return tuple(
        iter_cyclic_neighborhood_bucket_keys(
            targets,
            q=q,
            max_abs=max_abs,
            bucket_width=bucket_width,
            max_l1=max_l1,
            max_l2_squared=max_l2_squared,
            max_nonzero=max_nonzero,
            should_stop=should_stop,
            should_stop_memory=should_stop_memory,
            charge_work=charge_work,
            retain_memory=retain_memory,
            release_memory=release_memory,
        )
    )


def _peak_rss_bytes() -> int:
    try:
        import resource

        rss = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except (ImportError, OSError, ValueError):
        return 0
    return rss if sys.platform == "darwin" else rss * 1024


def _preflight_memory_allocation(
    estimated_bytes: int,
    *,
    memory_cap_bytes: int | None,
    rss_reader: Callable[[], int],
) -> None:
    if (
        memory_cap_bytes is not None
        and rss_reader() + estimated_bytes > memory_cap_bytes
    ):
        raise _MemoryCensored


@dataclass(slots=True)
class _RetainedMemoryBudget:
    """Conservative logical retained-state accounting layered over RSS."""

    cap_bytes: int | None
    rss_reader: Callable[[], int] = _peak_rss_bytes
    retained_bytes: int = 0

    def __post_init__(self) -> None:
        if self.cap_bytes is not None and (
            type(self.cap_bytes) is not int or self.cap_bytes <= 0
        ):
            raise ValueError("memory cap must be a positive integer")
        if type(self.retained_bytes) is not int or self.retained_bytes < 0:
            raise ValueError("retained bytes must be a non-negative integer")

    def preflight(self, additional_bytes: int) -> None:
        if type(additional_bytes) is not int or additional_bytes < 0:
            raise ValueError("allocation estimate must be a non-negative integer")
        if (
            self.cap_bytes is not None
            and self.rss_reader() + self.retained_bytes + additional_bytes
            > self.cap_bytes
        ):
            raise _MemoryCensored

    def retain(self, additional_bytes: int) -> None:
        self.preflight(additional_bytes)
        self.retained_bytes += additional_bytes

    def release(self, released_bytes: int) -> None:
        if (
            type(released_bytes) is not int
            or released_bytes < 0
            or released_bytes > self.retained_bytes
        ):
            raise ValueError("released bytes exceed retained state")
        self.retained_bytes -= released_bytes


def _materialize_selected_rows(
    instance,
    selected_rows: tuple[int, ...],
    *,
    should_stop: Callable[[], bool] | None,
    should_stop_memory: Callable[[], bool] | None,
    memory_cap_bytes: int | None = None,
    rss_reader: Callable[[], int] = _peak_rss_bytes,
) -> tuple[tuple[int, ...], ...]:
    """Preflight and materialize a contiguous public row block under budget."""

    _raise_for_helper_budget(
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
    )
    if not selected_rows:
        raise ValueError("selected row block must be nonempty")
    row_count = len(selected_rows)
    estimated_bytes = 64 + row_count * (64 + instance.n * 36)
    _preflight_memory_allocation(
        estimated_bytes,
        memory_cap_bytes=memory_cap_bytes,
        rss_reader=rss_reader,
    )
    rows = instance.materialize_row_block(
        selected_rows[0], selected_rows[-1] + 1
    )
    _raise_for_helper_budget(
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
    )
    return rows


def _select_mitm_rows_under_budget(
    instance,
    request: SolveRequest,
    *,
    should_stop: Callable[[], bool] | None,
    should_stop_memory: Callable[[], bool] | None,
    memory_cap_bytes: int | None,
    rss_reader: Callable[[], int] = _peak_rss_bytes,
) -> tuple[int, ...]:
    _raise_for_helper_budget(
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
    )
    row_count = _request_parameter(request, "mitm_row_count", min(instance.m, 4))
    if row_count <= 0 or row_count > instance.m:
        raise ValueError("mitm_row_count must be in [1, m]")
    _preflight_memory_allocation(
        64 + 36 * row_count,
        memory_cap_bytes=memory_cap_bytes,
        rss_reader=rss_reader,
    )
    selected_rows = tuple(range(row_count))
    _raise_for_helper_budget(
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
    )
    return selected_rows


def traversal_stop_reason(
    *,
    started: float,
    max_seconds: float,
    memory_cap_bytes: int | None,
    clock: Callable[[], float] = monotonic,
    rss_reader: Callable[[], int] = _peak_rss_bytes,
) -> str | None:
    """Return the deterministic public reason for stopping an incomplete walk."""

    if memory_cap_bytes is not None and rss_reader() > memory_cap_bytes:
        return "memory_cap"
    if clock() - started >= max_seconds:
        return "time_cap"
    return None


def timeout_result(
    *,
    started: float,
    work_units: int,
    clock: Callable[[], float] = monotonic,
    peak_rss_bytes: int = 0,
    public_parameters: Mapping[str, object] | None = None,
) -> SolveResult:
    """Construct the only valid result for an incomplete timed traversal."""

    elapsed = max(0.0, clock() - started)
    detail: dict[str, object] = {"reason": "time_cap"}
    if public_parameters:
        detail["public_parameters"] = dict(public_parameters)
    return SolveResult.censored(
        elapsed_seconds=elapsed,
        work_units=work_units,
        peak_rss_bytes=peak_rss_bytes,
        detail=detail,
    )


def inapplicable_result(code: str) -> SolveResult:
    """Construct a closed, stable non-applicability result."""

    return SolveResult.error(elapsed_seconds=0.0, work_units=0, detail={"code": code})


def _coverage_error_result(*, started: float, work_units: int) -> SolveResult:
    return SolveResult.error(
        elapsed_seconds=max(0.0, monotonic() - started),
        work_units=work_units,
        peak_rss_bytes=_peak_rss_bytes(),
        detail={"code": "coverage_verification_failed"},
    )


def memory_censored_result(
    *,
    started: float,
    work_units: int,
    memory_cap_bytes: int,
    clock: Callable[[], float] = monotonic,
    rss_reader: Callable[[], int] = _peak_rss_bytes,
) -> SolveResult:
    """Report an incomplete traversal stopped by its public memory cap."""

    return SolveResult.censored(
        elapsed_seconds=max(0.0, clock() - started),
        work_units=work_units,
        peak_rss_bytes=rss_reader(),
        detail={
            "reason": "memory_cap",
            "public_parameters": {
                "cap": memory_cap_bytes,
                "cap_unit": "bytes",
                "memory_cap_bytes": memory_cap_bytes,
            },
        },
    )


def budget_stop_result(
    *,
    started: float,
    max_seconds: float,
    work_units: int,
    memory_cap_bytes: int | None,
    clock: Callable[[], float] = monotonic,
    rss_reader: Callable[[], int] = _peak_rss_bytes,
) -> SolveResult | None:
    """Map a deterministic traversal budget observation to a censored result."""

    reason = traversal_stop_reason(
        started=started,
        max_seconds=max_seconds,
        memory_cap_bytes=memory_cap_bytes,
        clock=clock,
        rss_reader=rss_reader,
    )
    if reason == "memory_cap":
        assert memory_cap_bytes is not None
        return memory_censored_result(
            started=started,
            work_units=work_units,
            memory_cap_bytes=memory_cap_bytes,
            clock=clock,
            rss_reader=rss_reader,
        )
    if reason == "time_cap":
        return timeout_result(
            started=started,
            work_units=work_units,
            clock=clock,
            peak_rss_bytes=rss_reader(),
        )
    return None


def _expired(started: float, request: SolveRequest) -> bool:
    return monotonic() - started >= request.max_seconds


def _memory_exceeded(memory_cap_bytes: int | None) -> bool:
    return memory_cap_bytes is not None and _peak_rss_bytes() > memory_cap_bytes


def _budget_stop_result(
    *,
    started: float,
    request: SolveRequest,
    work_units: int,
    memory_cap_bytes: int | None,
) -> SolveResult | None:
    return budget_stop_result(
        started=started,
        max_seconds=request.max_seconds,
        work_units=work_units,
        memory_cap_bytes=memory_cap_bytes,
    )


class SparseSecretEnumerator(ValidatedExactSolver):
    """Finite exact traversal of a public exact-weight secret domain."""

    solver_id = "sparse_secret_enum"

    def _solve(self, instance, request: SolveRequest) -> SolveResult:
        started = monotonic()
        try:
            weight, values = _secret_parameters(instance)
        except ValueError as exc:
            return inapplicable_result(str(exc))
        try:
            work_cap = _work_unit_cap(request)
            memory_cap = _memory_cap(request)
        except ValueError:
            return inapplicable_result("invalid_public_parameters")
        domain_size = sparse_secret_domain_size(instance.n, weight, len(values))
        try:
            protocol = _SparseRunProtocol.create(
                instance=instance,
                request=request,
                solver_id=self.solver_id,
                solver_revision="task4-enum-v3",
                search_descriptor={
                    "kind": "exact_weight_lexicographic",
                    "n": instance.n,
                    "weight": weight,
                    "values": values,
                    "domain_size": domain_size,
                    "work_unit_cap": work_cap,
                    "memory_cap_bytes": memory_cap,
                    "checkpoint_interval": request.checkpoint_every_work_units,
                },
                domain_size=domain_size,
                minimum_work=lambda ordinal: ordinal,
            )
            budget = _TraversalBudget(
                deadline=_cumulative_deadline(protocol),
                work_unit_cap=work_cap,
                work_units=protocol.work_units,
                memory_cap_bytes=memory_cap,
                rss_reader=_peak_rss_bytes,
            )
        except (SolverContractError, ValueError):
            return inapplicable_result("invalid_checkpoint")

        def finish_censored(reason: str) -> SolveResult:
            try:
                protocol.advance(
                    next_ordinal=protocol.next_ordinal,
                    work_units=budget.work_units,
                    phase="censored",
                )
                protocol.checkpoint(force=True, phase="censored")
            except SolverContractError:
                return inapplicable_result("checkpoint_failure")
            detail: dict[str, object] = {"reason": reason}
            if reason == "work_unit_cap":
                detail["public_parameters"] = {
                    "cap": work_cap,
                    "cap_unit": "work_units",
                    "work_unit_cap": work_cap,
                }
            return SolveResult.censored(
                elapsed_seconds=protocol.elapsed_seconds,
                work_units=budget.work_units,
                peak_rss_bytes=_peak_rss_bytes(),
                checkpoint_count=protocol.checkpoint_count,
                detail=detail,
            )

        candidates = iter(islice(
            iter_exact_weight_candidates(instance.n, weight, values),
            protocol.next_ordinal,
            None,
        ))
        try:
            ordinal = protocol.next_ordinal
            while ordinal < domain_size:
                budget.check(allocation_bytes=64 + 36 * instance.n)
                try:
                    candidate = next(candidates)
                except StopIteration as exc:
                    raise ValueError("exact-weight domain ended early") from exc
                budget.charge("enum_candidate")
                if request.exclude_secret != candidate:
                    feasible = streaming_residual_feasible(
                        instance,
                        candidate,
                        charge_work=budget.charge,
                        check_budget=budget.check,
                    )
                    if feasible:
                        budget.charge("enum_validation")
                        verdict = instance.validate_secret(candidate)
                        budget.check()
                        if getattr(verdict, "ok", None) is True:
                            # Keep the witness ordinal pending.  If the process
                            # exits after this checkpoint but before the result
                            # is durably observed, resume must validate it again.
                            protocol.advance(
                                next_ordinal=ordinal,
                                work_units=budget.work_units,
                                phase="success_pending",
                            )
                            protocol.checkpoint(
                                force=True, phase="success_pending"
                            )
                            budget.check()
                            return SolveResult.success(
                                secret=candidate,
                                elapsed_seconds=protocol.elapsed_seconds,
                                work_units=budget.work_units,
                                peak_rss_bytes=_peak_rss_bytes(),
                                checkpoint_count=protocol.checkpoint_count,
                            )
                protocol.advance(
                    next_ordinal=ordinal + 1,
                    work_units=budget.work_units,
                    phase="enumerating",
                )
                protocol.checkpoint(phase="enumerating")
                ordinal += 1
            budget.check(allocation_bytes=64 + 36 * instance.n)
            try:
                next(candidates)
            except StopIteration:
                pass
            else:
                raise ValueError("exact-weight domain exceeded its exact size")
        except _WorkCensored:
            return finish_censored("work_unit_cap")
        except _MemoryCensored:
            return finish_censored("memory_cap")
        except _TraversalCensored:
            return finish_censored("time_cap")
        except ValueError:
            return _coverage_error_result(
                started=started, work_units=budget.work_units
            )
        except SolverContractError:
            return inapplicable_result("checkpoint_failure")

        if request.exclude_secret is not None:
            return finish_censored("exclusion_prevents_public_certificate")

        # Checkpoint ordinals are never trusted as exhaustion evidence.  The
        # public verifier independently replays every candidate from ordinal zero.
        try:
            detail = complete_domain_certificate(
                solver_id=self.solver_id,
                n=instance.n,
                weight=weight,
                alphabet_size=len(values),
                tested_count=domain_size,
                traversal_ranges=coverage_summary(
                    domain_size, request.checkpoint_every_work_units
                ),
                checkpoint_interval=request.checkpoint_every_work_units,
                excluded_count=0,
            )
            verify_public_enum_certificate(
                instance,
                request,
                detail,
                charge_work=budget.charge,
                check_budget=budget.check,
            )
        except _WorkCensored:
            return finish_censored("work_unit_cap")
        except _MemoryCensored:
            return finish_censored("memory_cap")
        except _TraversalCensored:
            return finish_censored("time_cap")
        except ValueError:
            return _coverage_error_result(
                started=started, work_units=budget.work_units
            )
        protocol.advance(
            next_ordinal=domain_size,
            work_units=budget.work_units,
            phase="exhausted",
        )
        try:
            protocol.checkpoint(force=True, phase="exhausted")
            budget.check()
        except _WorkCensored:
            return finish_censored("work_unit_cap")
        except _MemoryCensored:
            return finish_censored("memory_cap")
        except _TraversalCensored:
            return finish_censored("time_cap")
        except SolverContractError:
            return inapplicable_result("checkpoint_failure")
        return SolveResult.exhausted(
            elapsed_seconds=protocol.elapsed_seconds,
            work_units=budget.work_units,
            peak_rss_bytes=_peak_rss_bytes(),
            checkpoint_count=protocol.checkpoint_count,
            detail=detail,
        )


def _iter_half_candidates(
    n: int,
    coordinate_range: tuple[int, int],
    weight: int,
    values: tuple[int, ...],
) -> Iterator[tuple[int, ...]]:
    start, stop = coordinate_range
    for support in combinations(range(start, stop), weight):
        for assignment in product(values, repeat=weight):
            candidate = [0] * n
            for index, value in zip(support, assignment, strict=True):
                candidate[index] = value
            yield tuple(candidate)


def _syndrome(
    rows: Sequence[Sequence[int]],
    candidate: Sequence[int],
    q: int,
    *,
    charge_work: Callable[[str], None] | None = None,
) -> tuple[int, ...]:
    syndrome: list[int] = []
    for row in rows:
        dot_product = 0
        for coefficient, value in zip(row, candidate, strict=True):
            if charge_work is not None:
                charge_work("syndrome_coefficient")
            dot_product += coefficient * value
        if charge_work is not None:
            charge_work("syndrome_row")
        syndrome.append(dot_product % q)
    return tuple(syndrome)


@dataclass(frozen=True, slots=True)
class MitmCoverageManifest:
    """Constant-size public replay summary for an exact MITM traversal."""

    selected_rows: tuple[int, ...]
    partition_left_weights: tuple[int, ...]
    partition_right_counts: tuple[int, ...]
    checkpoint_interval: int
    left_ranges: CoverageSummary
    right_ranges: CoverageSummary
    collision_ranges: CoverageSummary
    event_digest: str
    left_entries: int
    right_entries: int
    collision_count: int
    neighborhood_count: int


def _verify_manifest_structure(manifest: MitmCoverageManifest) -> None:
    if type(manifest) is not MitmCoverageManifest:
        raise ValueError("MITM coverage manifest has the wrong type")
    if (
        type(manifest.selected_rows) is not tuple
        or not manifest.selected_rows
        or any(type(row) is not int or row < 0 for row in manifest.selected_rows)
        or manifest.selected_rows
        != tuple(range(manifest.selected_rows[0], manifest.selected_rows[-1] + 1))
        or type(manifest.partition_left_weights) is not tuple
        or any(
            type(weight) is not int or weight < 0
            for weight in manifest.partition_left_weights
        )
        or type(manifest.partition_right_counts) is not tuple
        or any(
            type(count) is not int or count <= 0
            for count in manifest.partition_right_counts
        )
        or type(manifest.checkpoint_interval) is not int
        or manifest.checkpoint_interval <= 0
        or type(manifest.event_digest) is not str
        or len(manifest.event_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in manifest.event_digest
        )
        or any(
            type(value) is not int or value < 0
            for value in (
                manifest.left_entries,
                manifest.right_entries,
                manifest.collision_count,
                manifest.neighborhood_count,
            )
        )
    ):
        raise ValueError("MITM coverage manifest has noncanonical scalar types")
    for summary, total in (
        (manifest.left_ranges, manifest.left_entries),
        (manifest.right_ranges, manifest.right_entries),
        (manifest.collision_ranges, manifest.collision_count),
    ):
        verify_coverage_summary(summary)
        if summary.total != total or summary.interval != manifest.checkpoint_interval:
            raise ValueError("MITM coverage summary is bound incorrectly")
    if (
        not manifest.partition_left_weights
        or len(manifest.partition_right_counts)
        != len(manifest.partition_left_weights)
        or any(count <= 0 for count in manifest.partition_right_counts)
    ):
        raise ValueError("MITM coverage has no canonical partitions")


def _bucket_digest(key: tuple[int, ...]) -> str:
    return _canonical_digest({"schema_version": 1, "bucket_key": key})


def _raise_for_helper_budget(
    *,
    should_stop: Callable[[], bool] | None,
    should_stop_memory: Callable[[], bool] | None,
) -> None:
    if should_stop_memory is not None and should_stop_memory():
        raise _MemoryCensored
    if should_stop is not None and should_stop():
        raise _TraversalCensored


def build_mitm_coverage_manifest(
    instance,
    request: SolveRequest,
    *,
    should_stop: Callable[[], bool] | None = None,
    should_stop_memory: Callable[[], bool] | None = None,
    charge_work: Callable[[str], None] | None = None,
    check_budget: Callable[[], None] | None = None,
    visit_candidate: Callable[[tuple[int, ...]], None] | None = None,
    memory_cap_bytes: int | None = None,
    rss_reader: Callable[[], int] = _peak_rss_bytes,
) -> MitmCoverageManifest:
    """Stream a canonical public-data MITM replay into constant-size evidence."""

    if check_budget is not None:
        check_budget()
    weight, values = _secret_parameters(instance)
    memory = _RetainedMemoryBudget(memory_cap_bytes, rss_reader=rss_reader)
    selected_rows = _select_mitm_rows_under_budget(
        instance,
        request,
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
        memory_cap_bytes=memory_cap_bytes,
        rss_reader=rss_reader,
    )
    bucket_width = 2 * instance.error_max_abs + 1
    row_bytes = 64 + len(selected_rows) * (64 + instance.n * 36)
    memory.preflight(row_bytes)
    rows = _materialize_selected_rows(
        instance,
        selected_rows,
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
        memory_cap_bytes=None,
        rss_reader=rss_reader,
    )
    memory.retain(row_bytes)
    if charge_work is not None:
        for _ in rows:
            charge_work("mitm_materialized_row")
    memory.preflight(128 + 72 * len(selected_rows))
    selected_b_parts: list[int] = []
    for index in selected_rows:
        if check_budget is not None:
            check_budget()
        if charge_work is not None:
            charge_work("mitm_selected_rhs")
        selected_b_parts.append(instance.b[index])
    selected_b = tuple(selected_b_parts)
    del selected_b_parts
    memory.retain(64 + 36 * len(selected_rows))
    left_range, right_range = split_coordinate_ranges(instance.n)
    partitions = mitm_partition_counts(instance.n, weight, len(values))
    interval = request.checkpoint_every_work_units
    fixed_replay_bytes = (
        1_024 + 72 * len(partitions) + 36 * len(selected_rows)
    )
    memory.retain(fixed_replay_bytes)

    table: dict[
        tuple[int, tuple[int, ...]], list[tuple[int, ...]]
    ] = {}
    table_bytes = 64
    memory.retain(table_bytes)
    left_ledger = _RangeLedger(interval)
    left_entries = 0
    for left_weight, _, _, _ in partitions:
        iterator = _iter_half_candidates(instance.n, left_range, left_weight, values)
        while True:
            if check_budget is not None:
                check_budget()
            _raise_for_helper_budget(
                should_stop=should_stop,
                should_stop_memory=should_stop_memory,
            )
            candidate_bytes = 64 + 36 * instance.n
            memory.preflight(candidate_bytes)
            try:
                left = next(iterator)
            except StopIteration:
                break
            syndrome_bytes = 64 + 36 * len(rows)
            memory.preflight(candidate_bytes + syndrome_bytes)
            syndrome = _syndrome(
                rows, left, instance.q, charge_work=charge_work
            )
            key_bytes = 64 + 36 * len(rows)
            maximum_retained_entry = (
                candidate_bytes + 72 + 128 + 36 * len(rows)
            )
            memory.preflight(
                candidate_bytes
                + syndrome_bytes
                + key_bytes
                + maximum_retained_entry
            )
            key = tuple(
                cyclic_bucket_index(
                    component, q=instance.q, bucket_width=bucket_width
                )
                for component in syndrome
            )
            bucket_key = (left_weight, key)
            new_bucket = bucket_key not in table
            retained_entry = candidate_bytes + 72
            if new_bucket:
                retained_entry += 128 + 36 * len(key)
            memory.retain(retained_entry)
            table.setdefault(bucket_key, []).append(left)
            table_bytes += retained_entry
            left_ledger.record(left_entries)
            left_entries += 1
            if charge_work is not None:
                charge_work("mitm_left_entry")
            _raise_for_helper_budget(
                should_stop=should_stop,
                should_stop_memory=should_stop_memory,
            )

    right_ledger = _RangeLedger(interval)
    collision_ledger = _RangeLedger(interval)
    event_digest = hashlib.sha256()
    right_entries = 0
    collision_count = 0
    neighborhood_count = 0
    for partition_index, (left_weight, _, _, _) in enumerate(partitions):
        right_weight = weight - left_weight
        iterator = enumerate(
            _iter_half_candidates(instance.n, right_range, right_weight, values)
        )
        while True:
            if check_budget is not None:
                check_budget()
            _raise_for_helper_budget(
                should_stop=should_stop,
                should_stop_memory=should_stop_memory,
            )
            candidate_bytes = 64 + 36 * instance.n
            memory.preflight(candidate_bytes)
            try:
                right_index, right = next(iterator)
            except StopIteration:
                break
            right_ordinal = right_entries
            right_ledger.record(right_ordinal)
            right_entries += 1
            syndrome_bytes = 64 + 36 * len(rows)
            memory.preflight(candidate_bytes + syndrome_bytes)
            right_syndrome = _syndrome(
                rows, right, instance.q, charge_work=charge_work
            )
            targets_bytes = 64 + 36 * len(rows)
            right_transient_bytes = (
                candidate_bytes + syndrome_bytes + targets_bytes
            )
            memory.preflight(right_transient_bytes)
            targets = tuple(
                (observed - partial) % instance.q
                for observed, partial in zip(
                    selected_b, right_syndrome, strict=True
                )
            )
            if charge_work is not None:
                charge_work("mitm_right_entry")

            def retain_neighborhood(additional_bytes: int) -> None:
                memory.preflight(right_transient_bytes + additional_bytes)
                memory.retain(additional_bytes)

            neighborhoods = iter_cyclic_neighborhood_bucket_keys(
                targets,
                q=instance.q,
                max_abs=instance.error_max_abs,
                bucket_width=bucket_width,
                max_l1=instance.error_max_l1,
                max_l2_squared=instance.error_max_l2_squared,
                max_nonzero=instance.error_max_nonzero,
                should_stop=should_stop,
                should_stop_memory=should_stop_memory,
                charge_work=charge_work,
                retain_memory=retain_neighborhood,
                release_memory=memory.release,
            )
            for neighborhood_index, key in enumerate(neighborhoods):
                if check_budget is not None:
                    check_budget()
                collision_start = collision_count
                for left in table.get((left_weight, key), ()):
                    if check_budget is not None:
                        check_budget()
                    _raise_for_helper_budget(
                        should_stop=should_stop,
                        should_stop_memory=should_stop_memory,
                    )
                    collision_ledger.record(collision_count)
                    collision_count += 1
                    if visit_candidate is not None:
                        candidate_bytes = 64 + 36 * instance.n
                        memory.preflight(
                            right_transient_bytes + candidate_bytes
                        )
                        candidate = tuple(
                            left_value + right_value
                            for left_value, right_value in zip(
                                left, right, strict=True
                            )
                        )
                        visit_candidate(candidate)
                    if charge_work is not None:
                        charge_work("mitm_collision_replay")
                event = {
                    "partition_index": partition_index,
                    "left_weight": left_weight,
                    "right_index": right_index,
                    "right_range_start": right_ordinal,
                    "right_range_stop": right_ordinal + 1,
                    "neighborhood_index": neighborhood_index,
                    "bucket_digest": _bucket_digest(key),
                    "collision_start": collision_start,
                    "collision_stop": collision_count,
                }
                event_digest.update(
                    json.dumps(
                        event,
                        allow_nan=False,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("ascii")
                )
                event_digest.update(b"\n")
                neighborhood_count += 1
                if charge_work is not None:
                    charge_work("mitm_neighborhood_replay")
                _raise_for_helper_budget(
                    should_stop=should_stop,
                    should_stop_memory=should_stop_memory,
                )

    _raise_for_helper_budget(
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
    )
    return MitmCoverageManifest(
        selected_rows=selected_rows,
        partition_left_weights=tuple(
            partition[0] for partition in partitions
        ),
        partition_right_counts=tuple(
            partition[2] for partition in partitions
        ),
        checkpoint_interval=interval,
        left_ranges=left_ledger.finish(left_entries),
        right_ranges=right_ledger.finish(right_entries),
        collision_ranges=collision_ledger.finish(collision_count),
        event_digest=event_digest.hexdigest(),
        left_entries=left_entries,
        right_entries=right_entries,
        collision_count=collision_count,
        neighborhood_count=neighborhood_count,
    )


def verify_mitm_coverage(
    instance,
    request: SolveRequest,
    manifest: MitmCoverageManifest,
    *,
    should_stop: Callable[[], bool] | None = None,
    should_stop_memory: Callable[[], bool] | None = None,
    charge_work: Callable[[str], None] | None = None,
    check_budget: Callable[[], None] | None = None,
    memory_cap_bytes: int | None = None,
    rss_reader: Callable[[], int] = _peak_rss_bytes,
) -> None:
    """Independently recompute and compare every MITM coverage event."""

    try:
        _verify_manifest_structure(manifest)
        expected = build_mitm_coverage_manifest(
            instance,
            request,
            should_stop=should_stop,
            should_stop_memory=should_stop_memory,
            charge_work=charge_work,
            check_budget=check_budget,
            memory_cap_bytes=memory_cap_bytes,
            rss_reader=rss_reader,
        )
    except ValueError as exc:
        raise ValueError("MITM coverage ranges are invalid") from exc
    if manifest != expected:
        raise ValueError("MITM coverage has a skipped, duplicated, or reordered event")


def _manifest_digest(
    manifest: MitmCoverageManifest,
    *,
    should_stop: Callable[[], bool] | None = None,
    should_stop_memory: Callable[[], bool] | None = None,
    charge_work: Callable[[str], None] | None = None,
) -> str:
    """Hash ordered proof material incrementally without a second full copy."""

    digest = hashlib.sha256()

    def update(value: Mapping[str, object]) -> None:
        _raise_for_helper_budget(
            should_stop=should_stop,
            should_stop_memory=should_stop_memory,
        )
        if charge_work is not None:
            charge_work("mitm_certificate_hash")
        digest.update(
            json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
        )
        digest.update(b"\n")

    update(
        {
            "schema_version": 1,
            "selected_rows": manifest.selected_rows,
            "partition_left_weights": manifest.partition_left_weights,
            "partition_right_counts": manifest.partition_right_counts,
            "checkpoint_interval": manifest.checkpoint_interval,
            "left_entries": manifest.left_entries,
            "right_entries": manifest.right_entries,
            "collision_count": manifest.collision_count,
            "neighborhood_count": manifest.neighborhood_count,
            "event_digest": manifest.event_digest,
        }
    )
    for range_kind, summary in (
        ("left", manifest.left_ranges),
        ("right", manifest.right_ranges),
        ("collision", manifest.collision_ranges),
    ):
        update(
            {
                "kind": range_kind,
                "total": summary.total,
                "interval": summary.interval,
                "range_count": summary.range_count,
                "boundary_sum": summary.boundary_sum,
                "digest": summary.digest,
            }
        )
    return digest.hexdigest()


def complete_mitm_certificate(
    *,
    n: int,
    weight: int,
    alphabet_size: int,
    selected_rows: tuple[int, ...],
    bucket_width: int,
    coverage_manifest: MitmCoverageManifest,
    should_stop: Callable[[], bool] | None = None,
    should_stop_memory: Callable[[], bool] | None = None,
    charge_work: Callable[[str], None] | None = None,
) -> dict[str, object]:
    domain_size = sparse_secret_domain_size(n, weight, alphabet_size)
    partitions = mitm_partition_counts(n, weight, alphabet_size)
    if (
        not selected_rows
        or any(type(row) is not int or row < 0 for row in selected_rows)
        or selected_rows
        != tuple(range(selected_rows[0], selected_rows[-1] + 1))
    ):
        raise ValueError("selected rows must be a nonempty contiguous range")
    if type(bucket_width) is not int or bucket_width <= 0:
        raise ValueError("bucket width must be positive")
    if coverage_manifest.selected_rows != selected_rows:
        raise ValueError("coverage manifest is bound to different selected rows")
    if coverage_manifest.partition_left_weights != tuple(
        partition[0] for partition in partitions
    ):
        raise ValueError("coverage manifest is bound to different partitions")
    if coverage_manifest.partition_right_counts != tuple(
        partition[2] for partition in partitions
    ):
        raise ValueError("coverage manifest is bound to different right partitions")
    _verify_manifest_structure(coverage_manifest)
    left_entries = coverage_manifest.left_entries
    right_entries = coverage_manifest.right_entries
    collision_count = coverage_manifest.collision_count
    neighborhood_count = coverage_manifest.neighborhood_count
    if left_entries != sum(partition[1] for partition in partitions):
        raise ValueError("left traversal does not cover every partition range")
    if right_entries != sum(partition[2] for partition in partitions):
        raise ValueError("right traversal does not cover every partition range")
    if type(collision_count) is not int or not 0 <= collision_count <= domain_size:
        raise ValueError("collision count is outside the exact domain")
    if type(neighborhood_count) is not int or neighborhood_count < 0:
        raise ValueError("neighborhood count must be non-negative")
    committed = {
        "schema_version": 1,
        "solver_id": "sparse_secret_mitm",
        "n": n,
        "weight": weight,
        "alphabet_size": alphabet_size,
        "selected_rows": selected_rows,
        "bucket_width": bucket_width,
        "partitions": partitions,
        "left_entries": left_entries,
        "right_entries": right_entries,
        "collision_count": collision_count,
        "neighborhood_count": neighborhood_count,
        "covered_domain_size": domain_size,
        "coverage_manifest_digest": _manifest_digest(
            coverage_manifest,
            should_stop=should_stop,
            should_stop_memory=should_stop_memory,
            charge_work=charge_work,
        ),
    }
    if charge_work is not None:
        charge_work("mitm_certificate_commit")
    return {
        "certificate_id": "complete_mitm_domain_v1",
        "certificate_digest": _canonical_digest(committed),
        "public_parameters": {
            "alphabet_size": alphabet_size,
            "bucket_width": bucket_width,
            "candidate_count": collision_count,
            "checkpoint_interval": coverage_manifest.checkpoint_interval,
            "collision_count": collision_count,
            "covered_work_units": domain_size,
            "domain_size": domain_size,
            "n": n,
            "range_start": selected_rows[0],
            "range_stop": selected_rows[-1] + 1,
            "row_count": len(selected_rows),
            "subset_size": len(selected_rows),
            "support_count": comb(n, weight),
            "tested_count": collision_count,
            "weight": weight,
        },
    }


def verify_public_mitm_certificate(
    instance,
    request: SolveRequest,
    certificate: Mapping[str, object],
    *,
    should_stop: Callable[[], bool] | None = None,
    should_stop_memory: Callable[[], bool] | None = None,
    charge_work: Callable[[str], None] | None = None,
    check_budget: Callable[[], None] | None = None,
    memory_cap_bytes: int | None = None,
    rss_reader: Callable[[], int] = _peak_rss_bytes,
) -> None:
    """Reconstruct bounded MITM evidence using public inputs only.

    A solver run with an exclusion cannot use this proof to claim public
    exhaustion.
    """

    if request.exclude_secret is not None:
        raise ValueError("an exclusion cannot support public MITM exhaustion")
    if type(certificate) is not dict:
        raise ValueError("MITM certificate must be a canonical JSON object")
    weight, values = _secret_parameters(instance)
    found_witness = False

    def visit(candidate: tuple[int, ...]) -> None:
        nonlocal found_witness
        if found_witness:
            return
        if streaming_residual_feasible(
            instance,
            candidate,
            charge_work=charge_work,
            check_budget=check_budget,
        ):
            if charge_work is not None:
                charge_work("mitm_public_validation")
            verdict = instance.validate_secret(candidate)
            if check_budget is not None:
                check_budget()
            found_witness = getattr(verdict, "ok", None) is True

    manifest = build_mitm_coverage_manifest(
        instance,
        request,
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
        charge_work=charge_work,
        check_budget=check_budget,
        visit_candidate=visit,
        memory_cap_bytes=memory_cap_bytes,
        rss_reader=rss_reader,
    )
    selected_rows = select_mitm_rows(instance, request)
    expected = complete_mitm_certificate(
        n=instance.n,
        weight=weight,
        alphabet_size=len(values),
        selected_rows=selected_rows,
        bucket_width=2 * instance.error_max_abs + 1,
        coverage_manifest=manifest,
        should_stop=should_stop,
        should_stop_memory=should_stop_memory,
        charge_work=charge_work,
    )
    if found_witness:
        raise ValueError("MITM exhaustion replay found a public valid witness")
    _require_exact_certificate_value(
        certificate,
        expected,
        certificate_kind="MITM",
    )


class SparseSecretMitM(ValidatedExactSolver):
    """Resumable exact MITM search with bounded public exhaustion replay."""

    solver_id = "sparse_secret_mitm"

    def _solve(self, instance, request: SolveRequest) -> SolveResult:
        started = monotonic()
        try:
            weight, values = _secret_parameters(instance)
            work_cap = _work_unit_cap(request)
            memory_cap = _memory_cap(request)
            selected_rows = select_mitm_rows(instance, request)
        except ValueError as exc:
            code = str(exc)
            if code not in {
                "not_exact_weight",
                "invalid_exact_weight",
                "invalid_secret_alphabet",
            }:
                code = "invalid_public_parameters"
            return inapplicable_result(code)

        bucket_width = 2 * instance.error_max_abs + 1
        partitions = mitm_partition_counts(instance.n, weight, len(values))
        left_domain_size = sum(partition[1] for partition in partitions)
        right_domain_size = sum(partition[2] for partition in partitions)
        traversal_size = left_domain_size + right_domain_size
        try:
            protocol = _SparseRunProtocol.create(
                instance=instance,
                request=request,
                solver_id=self.solver_id,
                solver_revision="task4-mitm-v3",
                search_descriptor={
                    "kind": "cyclic_bucket_mitm",
                    "n": instance.n,
                    "weight": weight,
                    "values": values,
                    "selected_rows": selected_rows,
                    "bucket_width": bucket_width,
                    "partitions": partitions,
                    "left_domain_size": left_domain_size,
                    "right_domain_size": right_domain_size,
                    "work_unit_cap": work_cap,
                    "memory_cap_bytes": memory_cap,
                    "checkpoint_interval": request.checkpoint_every_work_units,
                },
                domain_size=traversal_size,
                minimum_work=lambda ordinal: ordinal,
                phase_sizes=(
                    ("mitm_left", left_domain_size),
                    ("mitm_right", right_domain_size),
                ),
            )
            budget = _TraversalBudget(
                deadline=_cumulative_deadline(protocol),
                work_unit_cap=work_cap,
                work_units=protocol.work_units,
                memory_cap_bytes=memory_cap,
                rss_reader=_peak_rss_bytes,
            )
        except (SolverContractError, ValueError):
            return inapplicable_result("invalid_checkpoint")

        def finish_censored(reason: str) -> SolveResult:
            try:
                protocol.advance(
                    next_ordinal=protocol.next_ordinal,
                    work_units=budget.work_units,
                    phase="censored",
                )
                protocol.checkpoint(force=True, phase="censored")
            except SolverContractError:
                return inapplicable_result("checkpoint_failure")
            detail: dict[str, object] = {"reason": reason}
            if reason == "work_unit_cap":
                detail["public_parameters"] = {
                    "cap": work_cap,
                    "cap_unit": "work_units",
                    "work_unit_cap": work_cap,
                }
            return SolveResult.censored(
                elapsed_seconds=protocol.elapsed_seconds,
                work_units=budget.work_units,
                peak_rss_bytes=_peak_rss_bytes(),
                checkpoint_count=protocol.checkpoint_count,
                detail=detail,
            )

        retained = _RetainedMemoryBudget(
            memory_cap, rss_reader=_peak_rss_bytes
        )
        left_range, right_range = split_coordinate_ranges(instance.n)
        table: dict[
            tuple[int, tuple[int, ...]], list[tuple[int, ...]]
        ] = {}
        table_bytes = 64
        try:
            fixed_search_bytes = (
                512 + 72 * len(partitions) + 36 * len(selected_rows)
            )
            retained.retain(fixed_search_bytes)
            retained.retain(table_bytes)
            row_bytes = 64 + len(selected_rows) * (64 + instance.n * 36)
            retained.preflight(row_bytes)
            budget.check(allocation_bytes=row_bytes)
            rows = _materialize_selected_rows(
                instance,
                selected_rows,
                should_stop=lambda: monotonic() >= budget.deadline,
                should_stop_memory=lambda: (
                    memory_cap is not None and _peak_rss_bytes() > memory_cap
                ),
                memory_cap_bytes=None,
            )
            retained.retain(row_bytes)
            for _ in rows:
                budget.charge("mitm_materialized_row")
            selected_b_bytes = 64 + 36 * len(selected_rows)
            selected_b_allocation_bytes = 128 + 72 * len(selected_rows)
            retained.preflight(selected_b_allocation_bytes)
            budget.check(allocation_bytes=selected_b_allocation_bytes)
            selected_b_parts: list[int] = []
            for index in selected_rows:
                budget.charge("mitm_selected_rhs")
                selected_b_parts.append(instance.b[index])
            selected_b = tuple(selected_b_parts)
            del selected_b_parts
            retained.retain(selected_b_bytes)

            global_left_ordinal = 0
            for left_weight, _, _, _ in partitions:
                iterator = _iter_half_candidates(
                    instance.n, left_range, left_weight, values
                )
                while True:
                    candidate_bytes = 64 + 36 * instance.n
                    retained.preflight(candidate_bytes)
                    budget.check(allocation_bytes=candidate_bytes)
                    try:
                        left = next(iterator)
                    except StopIteration:
                        break
                    syndrome_bytes = 64 + 36 * len(rows)
                    retained.preflight(candidate_bytes + syndrome_bytes)
                    budget.check(allocation_bytes=syndrome_bytes)
                    syndrome = _syndrome(
                        rows, left, instance.q, charge_work=budget.charge
                    )
                    key_bytes = 64 + 36 * len(rows)
                    maximum_retained_entry = (
                        candidate_bytes + 72 + 128 + 36 * len(rows)
                    )
                    retained.preflight(
                        candidate_bytes
                        + syndrome_bytes
                        + key_bytes
                        + maximum_retained_entry
                    )
                    key = tuple(
                        cyclic_bucket_index(
                            component,
                            q=instance.q,
                            bucket_width=bucket_width,
                        )
                        for component in syndrome
                    )
                    bucket_key = (left_weight, key)
                    retained_entry = candidate_bytes + 72
                    if bucket_key not in table:
                        retained_entry += 128 + 36 * len(key)
                    retained.retain(retained_entry)
                    table_bytes += retained_entry
                    table.setdefault(bucket_key, []).append(left)
                    budget.charge("mitm_left_entry")
                    global_left_ordinal += 1
                    if global_left_ordinal > protocol.next_ordinal:
                        protocol.advance(
                            next_ordinal=global_left_ordinal,
                            work_units=budget.work_units,
                            phase="mitm_left",
                        )
                        protocol.checkpoint(phase="mitm_left")

            global_right_ordinal = 0
            resumed_right_ordinal = max(
                0, protocol.next_ordinal - left_domain_size
            )
            for left_weight, _, _, _ in partitions:
                right_weight = weight - left_weight
                iterator = _iter_half_candidates(
                    instance.n, right_range, right_weight, values
                )
                while True:
                    candidate_bytes = 64 + 36 * instance.n
                    retained.preflight(candidate_bytes)
                    budget.check(allocation_bytes=candidate_bytes)
                    try:
                        right = next(iterator)
                    except StopIteration:
                        break
                    if global_right_ordinal < resumed_right_ordinal:
                        budget.charge("mitm_resume_replay")
                        global_right_ordinal += 1
                        continue
                    syndrome_bytes = 64 + 36 * len(rows)
                    retained.preflight(candidate_bytes + syndrome_bytes)
                    budget.check(allocation_bytes=syndrome_bytes)
                    right_syndrome = _syndrome(
                        rows, right, instance.q, charge_work=budget.charge
                    )
                    targets_bytes = 64 + 36 * len(rows)
                    right_transient_bytes = (
                        candidate_bytes + syndrome_bytes + targets_bytes
                    )
                    retained.preflight(right_transient_bytes)
                    targets = tuple(
                        (observed - partial) % instance.q
                        for observed, partial in zip(
                            selected_b, right_syndrome, strict=True
                        )
                    )
                    budget.charge("mitm_right_entry")

                    def retain_neighborhood(additional_bytes: int) -> None:
                        retained.preflight(
                            right_transient_bytes + additional_bytes
                        )
                        retained.retain(additional_bytes)

                    neighborhoods = iter_cyclic_neighborhood_bucket_keys(
                        targets,
                        q=instance.q,
                        max_abs=instance.error_max_abs,
                        bucket_width=bucket_width,
                        max_l1=instance.error_max_l1,
                        max_l2_squared=instance.error_max_l2_squared,
                        max_nonzero=instance.error_max_nonzero,
                        should_stop=lambda: monotonic() >= budget.deadline,
                        should_stop_memory=lambda: (
                            memory_cap is not None
                            and _peak_rss_bytes() > memory_cap
                        ),
                        charge_work=budget.charge,
                        retain_memory=retain_neighborhood,
                        release_memory=retained.release,
                    )
                    for key in neighborhoods:
                        budget.charge("mitm_neighborhood")
                        for left in table.get((left_weight, key), ()):
                            retained.preflight(
                                right_transient_bytes + candidate_bytes
                            )
                            budget.check(allocation_bytes=candidate_bytes)
                            budget.charge("mitm_collision")
                            candidate = tuple(
                                left_value + right_value
                                for left_value, right_value in zip(
                                    left, right, strict=True
                                )
                            )
                            if request.exclude_secret == candidate:
                                continue
                            if not streaming_residual_feasible(
                                instance,
                                candidate,
                                charge_work=budget.charge,
                                check_budget=budget.check,
                            ):
                                continue
                            budget.charge("mitm_validation")
                            verdict = instance.validate_secret(candidate)
                            budget.check()
                            if getattr(verdict, "ok", None) is True:
                                # The current right ordinal may contain more
                                # collisions, including this witness.  Persist
                                # it as pending so an interrupted result handoff
                                # cannot skip the public witness on resume.
                                protocol.advance(
                                    next_ordinal=(
                                        left_domain_size + global_right_ordinal
                                    ),
                                    work_units=budget.work_units,
                                    phase="success_pending",
                                )
                                protocol.checkpoint(
                                    force=True, phase="success_pending"
                                )
                                budget.check()
                                return SolveResult.success(
                                    secret=candidate,
                                    elapsed_seconds=protocol.elapsed_seconds,
                                    work_units=budget.work_units,
                                    peak_rss_bytes=_peak_rss_bytes(),
                                    checkpoint_count=protocol.checkpoint_count,
                                    detail={
                                        "public_parameters": {
                                            "bucket_width": bucket_width,
                                            "range_start": selected_rows[0],
                                            "range_stop": selected_rows[-1] + 1,
                                            "row_count": len(selected_rows),
                                            "subset_size": len(selected_rows),
                                        }
                                    },
                                )
                    global_right_ordinal += 1
                    protocol.advance(
                        next_ordinal=left_domain_size + global_right_ordinal,
                        work_units=budget.work_units,
                        phase="mitm_right",
                    )
                    protocol.checkpoint(phase="mitm_right")
        except _WorkCensored:
            return finish_censored("work_unit_cap")
        except _MemoryCensored:
            return finish_censored("memory_cap")
        except _TraversalCensored:
            return finish_censored("time_cap")
        except SolverContractError:
            return inapplicable_result("checkpoint_failure")
        except (IndexError, TypeError, ValueError):
            return inapplicable_result("malformed_public_instance")

        if request.exclude_secret is not None:
            return finish_censored("exclusion_prevents_public_certificate")

        # Drop the search table before allocating replay state.  RSS checks stay
        # active, so an allocator that retains those pages still fails closed.
        table.clear()
        retained.release(table_bytes)
        del table
        retained.release(row_bytes + selected_b_bytes)
        del rows, selected_b
        try:
            manifest = build_mitm_coverage_manifest(
                instance,
                request,
                should_stop=lambda: monotonic() >= budget.deadline,
                should_stop_memory=lambda: (
                    memory_cap is not None and _peak_rss_bytes() > memory_cap
                ),
                charge_work=budget.charge,
                check_budget=budget.check,
                memory_cap_bytes=memory_cap,
            )
            certificate = complete_mitm_certificate(
                n=instance.n,
                weight=weight,
                alphabet_size=len(values),
                selected_rows=selected_rows,
                bucket_width=bucket_width,
                coverage_manifest=manifest,
                should_stop=lambda: monotonic() >= budget.deadline,
                should_stop_memory=lambda: (
                    memory_cap is not None and _peak_rss_bytes() > memory_cap
                ),
                charge_work=budget.charge,
            )
            verify_public_mitm_certificate(
                instance,
                request,
                certificate,
                should_stop=lambda: monotonic() >= budget.deadline,
                should_stop_memory=lambda: (
                    memory_cap is not None and _peak_rss_bytes() > memory_cap
                ),
                charge_work=budget.charge,
                check_budget=budget.check,
                memory_cap_bytes=memory_cap,
            )
        except _WorkCensored:
            return finish_censored("work_unit_cap")
        except _MemoryCensored:
            return finish_censored("memory_cap")
        except _TraversalCensored:
            return finish_censored("time_cap")
        except ValueError:
            return _coverage_error_result(
                started=started, work_units=budget.work_units
            )
        protocol.advance(
            next_ordinal=traversal_size,
            work_units=budget.work_units,
            phase="exhausted",
        )
        try:
            protocol.checkpoint(force=True, phase="exhausted")
            budget.check()
        except _WorkCensored:
            return finish_censored("work_unit_cap")
        except _MemoryCensored:
            return finish_censored("memory_cap")
        except _TraversalCensored:
            return finish_censored("time_cap")
        except SolverContractError:
            return inapplicable_result("checkpoint_failure")
        return SolveResult.exhausted(
            elapsed_seconds=protocol.elapsed_seconds,
            work_units=budget.work_units,
            peak_rss_bytes=_peak_rss_bytes(),
            checkpoint_count=protocol.checkpoint_count,
            detail=certificate,
        )
