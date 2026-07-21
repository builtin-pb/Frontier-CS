"""Random clean-subset recovery for public sparse-bounded error instances.

The module-level algebra helpers are dependency-free and recovery-free.  The
only randomized candidate loop lives behind :class:`ValidatedExactSolver`.
"""

from __future__ import annotations

import hashlib
import json
import random
import resource
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .api import (
    CheckpointStore,
    ExactProblem,
    ValidatedExactSolver,
    ProgressEvent,
    SolveRequest,
    SolveResult,
    SolverContractError,
    append_progress,
)


_PHASE2_MAX_Q = 2**32 - 1
_DEFAULT_MEMORY_CAP_BYTES = 512 * 1024 * 1024


class MemoryLimitExceeded(RuntimeError):
    """A checked allocation would cross the task-wide memory cap."""


class TimeLimitExceeded(RuntimeError):
    """A cooperative operation reached the request deadline."""


def _current_rss_bytes() -> int:
    try:
        import psutil

        return int(psutil.Process().memory_info().rss)
    except Exception:
        return _peak_rss_bytes()


def _peak_rss_bytes() -> int:
    try:
        observed = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    except (OSError, ValueError):
        return 0
    return observed if sys.platform == "darwin" else observed * 1024


def memory_cap_bytes(request: SolveRequest) -> int:
    value = request.parameters.get("memory_cap_bytes", _DEFAULT_MEMORY_CAP_BYTES)
    if type(value) is not int or value <= 0:
        raise ValueError("memory_cap_bytes must be a positive integer")
    return value


def _canonical_digest(value: Mapping[str, object]) -> str:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise SolverContractError("run-control binding is not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


@dataclass(slots=True)
class SolverRunControl:
    """Small typed budget/checkpoint/progress controller for Task 6 solvers."""

    request: SolveRequest
    solver_id: str
    instance_id: str
    search_digest: str
    memory_cap_bytes: int
    store: CheckpointStore
    started: float
    max_seconds_ceiling: float
    clock: Callable[[], float] = time.monotonic
    rss_reader: Callable[[], int] = _current_rss_bytes
    peak_rss_reader: Callable[[], int] = _peak_rss_bytes
    elapsed_base: float = 0.0
    cursor: int = 0
    work_units: int = 0
    checkpoint_count: int = 0
    last_checkpoint_work: int = 0
    checkpoint_path: Path | None = None
    solver_state: Mapping[str, object] = field(default_factory=dict)
    peak_rss_bytes: int = 0

    @classmethod
    def create(
        cls,
        *,
        instance: ExactProblem,
        request: SolveRequest,
        solver_id: str,
        solver_revision: str,
        search_descriptor: Mapping[str, object],
        memory_cap_bytes: int,
        clock: Callable[[], float] = time.monotonic,
        rss_reader: Callable[[], int] = _current_rss_bytes,
        peak_rss_reader: Callable[[], int] = _peak_rss_bytes,
    ) -> "SolverRunControl":
        if type(memory_cap_bytes) is not int or memory_cap_bytes <= 0:
            raise SolverContractError("memory cap must be a positive integer")
        binding = {
            "schema_version": 1,
            "solver_id": solver_id,
            "search": dict(search_descriptor),
            "parameters": dict(request.parameters),
            "exclude_secret": request.exclude_secret,
            "checkpoint_interval": request.checkpoint_every_work_units,
            "single_worker": request.single_worker,
        }
        store = CheckpointStore(
            work_dir=request.work_dir,
            solver_id=solver_id,
            solver_revision=solver_revision,
            instance_digest=instance.instance_digest,
            seed=request.seed,
        )
        control = cls(
            request=request,
            solver_id=solver_id,
            instance_id=instance.instance_id,
            search_digest=_canonical_digest(binding),
            memory_cap_bytes=memory_cap_bytes,
            store=store,
            started=clock(),
            max_seconds_ceiling=request.max_seconds,
            clock=clock,
            rss_reader=rss_reader,
            peak_rss_reader=peak_rss_reader,
            checkpoint_path=request.resume_checkpoint,
            peak_rss_bytes=peak_rss_reader(),
        )
        if request.resume_checkpoint is not None:
            loaded = store.load(request.resume_checkpoint)
            if loaded is None:
                raise SolverContractError("checkpoint does not exist")
            control._restore(loaded)
        return control

    def _restore(self, state: Mapping[str, object]) -> None:
        expected = {
            "schema_version",
            "search_digest",
            "cursor",
            "work_units",
            "elapsed_seconds",
            "checkpoint_count",
            "peak_rss_bytes",
            "max_seconds_ceiling",
            "solver_state",
        }
        if frozenset(state) != expected:
            raise SolverContractError("checkpoint run state is malformed")
        integer_fields = (
            "schema_version",
            "cursor",
            "work_units",
            "checkpoint_count",
            "peak_rss_bytes",
        )
        if any(type(state[name]) is not int for name in integer_fields):
            raise SolverContractError("checkpoint run state is malformed")
        if (
            state["schema_version"] != 1
            or type(state["search_digest"]) is not str
            or state["search_digest"] != self.search_digest
        ):
            raise SolverContractError("checkpoint search binding does not match")
        cursor = state["cursor"]
        work_units = state["work_units"]
        checkpoint_count = state["checkpoint_count"]
        peak_rss_bytes = state["peak_rss_bytes"]
        max_seconds_ceiling = state["max_seconds_ceiling"]
        elapsed = state["elapsed_seconds"]
        solver_state = state["solver_state"]
        assert type(cursor) is int
        assert type(work_units) is int
        assert type(checkpoint_count) is int
        assert type(peak_rss_bytes) is int
        if (
            cursor < 0
            or work_units < 0
            or checkpoint_count < 0
            or peak_rss_bytes < 0
            or type(max_seconds_ceiling) not in (int, float)
            or isinstance(max_seconds_ceiling, bool)
            or not 0.0 < float(max_seconds_ceiling) < float("inf")
            or self.request.max_seconds > float(max_seconds_ceiling)
            or type(elapsed) not in (int, float)
            or isinstance(elapsed, bool)
            or not 0.0 <= float(elapsed) < float("inf")
            or not isinstance(solver_state, Mapping)
        ):
            raise SolverContractError("checkpoint run state or budget binding is malformed")
        self.cursor = cursor
        self.work_units = work_units
        self.checkpoint_count = checkpoint_count
        self.last_checkpoint_work = work_units
        self.elapsed_base = float(elapsed)
        self.solver_state = solver_state
        self.peak_rss_bytes = max(self.peak_rss_bytes, peak_rss_bytes)
        self.max_seconds_ceiling = min(
            self.request.max_seconds,
            float(max_seconds_ceiling),
        )

    @property
    def elapsed_seconds(self) -> float:
        return self.elapsed_base + max(0.0, self.clock() - self.started)

    @property
    def deadline(self) -> float:
        return self.started + max(
            0.0,
            self.request.max_seconds - self.elapsed_base,
        )

    def observe_peak(self) -> int:
        self.peak_rss_bytes = max(self.peak_rss_bytes, self.peak_rss_reader())
        return self.peak_rss_bytes

    def preflight(self, additional_bytes: int) -> None:
        if type(additional_bytes) is not int or additional_bytes < 0:
            raise ValueError("allocation estimate must be a non-negative integer")
        if self.rss_reader() + additional_bytes > self.memory_cap_bytes:
            raise MemoryLimitExceeded

    def stop_reason(self) -> str | None:
        if self.rss_reader() > self.memory_cap_bytes:
            return "memory_cap"
        if self.elapsed_seconds >= self.request.max_seconds:
            return "time_cap"
        return None

    def advance(
        self,
        *,
        cursor: int,
        work_units: int,
        solver_state: Mapping[str, object],
    ) -> None:
        if (
            type(cursor) is not int
            or cursor < self.cursor
            or type(work_units) is not int
            or work_units < self.work_units
            or not isinstance(solver_state, Mapping)
        ):
            raise SolverContractError("run-control traversal regressed")
        self.cursor = cursor
        self.work_units = work_units
        self.solver_state = dict(solver_state)

    def checkpoint(
        self,
        *,
        force: bool = False,
        phase: str = "checkpoint",
    ) -> Path | None:
        if (
            not force
            and self.work_units - self.last_checkpoint_work
            < self.request.checkpoint_every_work_units
        ):
            return self.checkpoint_path
        elapsed = self.elapsed_seconds
        peak_rss_bytes = self.observe_peak()
        next_count = self.checkpoint_count + 1
        state = {
            "schema_version": 1,
            "search_digest": self.search_digest,
            "cursor": self.cursor,
            "work_units": self.work_units,
            "elapsed_seconds": elapsed,
            "checkpoint_count": next_count,
            "peak_rss_bytes": peak_rss_bytes,
            "max_seconds_ceiling": self.max_seconds_ceiling,
            "solver_state": dict(self.solver_state),
        }
        self.checkpoint_path = self.store.save(
            state,
            work_units=self.work_units,
            path=self.checkpoint_path,
        )
        self.checkpoint_count = next_count
        self.last_checkpoint_work = self.work_units
        append_progress(
            self.request.work_dir / f"{self.solver_id}.progress.jsonl",
            ProgressEvent(
                solver_id=self.solver_id,
                instance_id=self.instance_id,
                elapsed_seconds=elapsed,
                work_units=self.work_units,
                phase=phase,
                peak_rss_bytes=peak_rss_bytes,
                checkpoint_count=self.checkpoint_count,
            ),
        )
        return self.checkpoint_path


def is_prime(value: int) -> bool:
    """Return primality inside the Phase 2 uint32 modulus envelope.

    The fixed Miller--Rabin bases are deterministic for every unsigned 32-bit
    input, so malformed huge moduli cannot trigger an unbounded trial division
    before solver budgets become active.
    """

    if type(value) is not int or not 2 <= value <= _PHASE2_MAX_Q:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    if value in small_primes:
        return True
    if any(value % prime == 0 for prime in small_primes):
        return False
    odd_part = value - 1
    power_of_two = 0
    while odd_part % 2 == 0:
        power_of_two += 1
        odd_part //= 2
    for base in (2, 3, 5, 7):
        witness = pow(base, odd_part, value)
        if witness in (1, value - 1):
            continue
        for _ in range(power_of_two - 1):
            witness = witness * witness % value
            if witness == value - 1:
                break
        else:
            return False
    return True


def invert_matrix_mod_prime(
    matrix: Sequence[Sequence[int]],
    q: int,
    *,
    budget_check: Callable[[], None] | None = None,
) -> tuple[tuple[int, ...], ...] | None:
    """Return the exact inverse over ``GF(q)``, or ``None`` when singular."""

    if not is_prime(q):
        raise ValueError("q must be prime")
    rows = tuple(tuple(row) for row in matrix)
    n = len(rows)
    if n == 0 or any(len(row) != n for row in rows):
        raise ValueError("matrix must be nonempty and square")
    augmented = [
        [value % q for value in row]
        + [1 if row_index == column else 0 for column in range(n)]
        for row_index, row in enumerate(rows)
    ]
    for column in range(n):
        if budget_check is not None:
            budget_check()
        pivot = next(
            (row for row in range(column, n) if augmented[row][column] % q),
            None,
        )
        if pivot is None:
            return None
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        inverse = pow(augmented[column][column], -1, q)
        augmented[column] = [(value * inverse) % q for value in augmented[column]]
        for row in range(n):
            if budget_check is not None:
                budget_check()
            if row == column:
                continue
            factor = augmented[row][column] % q
            if factor:
                augmented[row] = [
                    (left - factor * right) % q
                    for left, right in zip(
                        augmented[row], augmented[column], strict=True
                    )
                ]
    return tuple(tuple(row[n:]) for row in augmented)


def multiply_matrix_vector_mod(
    matrix: Sequence[Sequence[int]],
    vector: Sequence[int],
    q: int,
    *,
    budget_check: Callable[[], None] | None = None,
) -> tuple[int, ...]:
    if not is_prime(q):
        raise ValueError("q must be prime")
    values = tuple(vector)
    if any(len(row) != len(values) for row in matrix):
        raise ValueError("matrix/vector dimensions disagree")
    result: list[int] = []
    for row in matrix:
        if budget_check is not None:
            budget_check()
        result.append(
            sum(
                coefficient * value
                for coefficient, value in zip(row, values, strict=True)
            )
            % q
        )
    return tuple(result)


def map_secret_representatives(
    residues: Sequence[int],
    *,
    q: int,
    predicate_kind: str,
    alphabet: Sequence[int],
) -> tuple[int, ...]:
    """Map residues to the unique representatives allowed by the public predicate."""

    if type(q) is not int or q < 2:
        raise ValueError("q must be at least two")
    values = tuple(residue % q for residue in residues)
    if predicate_kind == "mod_q":
        return values
    if predicate_kind != "alphabet":
        raise ValueError("unknown public secret predicate")
    declared = tuple(alphabet)
    if not declared:
        raise ValueError("alphabet predicate has no representative")
    by_residue: dict[int, int] = {}
    for representative in declared:
        residue = representative % q
        if residue in by_residue:
            raise ValueError("alphabet does not define unique representatives")
        by_residue[residue] = representative
    try:
        return tuple(by_residue[value] for value in values)
    except KeyError as exc:
        raise ValueError("residue has no public secret representative") from exc


@dataclass(frozen=True, slots=True)
class SubsetCandidate:
    kind: str
    secret: tuple[int, ...] | None


def sampled_subset_candidate(
    *,
    rows: Sequence[Sequence[int]],
    rhs: Sequence[int],
    row_indices: Sequence[int],
    q: int,
    predicate_kind: str,
    alphabet: Sequence[int],
    budget_check: Callable[[], None] | None = None,
) -> SubsetCandidate:
    """Solve one declared row subset without validating it on unseen rows."""

    materialized = tuple(tuple(row) for row in rows)
    targets = tuple(rhs)
    indices = tuple(row_indices)
    if len(materialized) != len(targets) or not materialized:
        raise ValueError("public matrix/vector dimensions disagree")
    n = len(materialized[0])
    if any(len(row) != n for row in materialized):
        raise ValueError("public matrix is ragged")
    if len(indices) != n or len(set(indices)) != n:
        raise ValueError("row subset must contain n distinct indices")
    if any(index < 0 or index >= len(materialized) for index in indices):
        raise ValueError("row subset index is out of range")
    minor = tuple(materialized[index] for index in indices)
    inverse = invert_matrix_mod_prime(minor, q, budget_check=budget_check)
    if inverse is None:
        return SubsetCandidate("singular", None)
    residues = multiply_matrix_vector_mod(
        inverse,
        tuple(targets[index] for index in indices),
        q,
        budget_check=budget_check,
    )
    try:
        secret = map_secret_representatives(
            residues,
            q=q,
            predicate_kind=predicate_kind,
            alphabet=alphabet,
        )
    except ValueError:
        return SubsetCandidate("unrepresentable", None)
    return SubsetCandidate("candidate", secret)


def applicability(instance: ExactProblem, request: SolveRequest | None = None) -> bool:
    del request
    return (
        type(instance.n) is int
        and type(instance.m) is int
        and instance.n > 0
        and instance.m >= instance.n
        and is_prime(instance.q)
        and instance.error_distribution_kind == "sparse_bounded"
        and type(instance.error_weight) is int
        and 0 <= instance.error_weight <= instance.m
        and instance.m - instance.error_weight >= instance.n
    )


def _positive_int_parameter(request: SolveRequest, name: str, default: int) -> int:
    value = request.parameters.get(name, default)
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _deterministic_subset(
    *, seed: int, ordinal: int, population: int, subset_size: int
) -> tuple[int, ...]:
    encoded = f"clean-subset-v1:{seed}:{ordinal}".encode("ascii")
    local_seed = int.from_bytes(hashlib.sha256(encoded).digest(), "big")
    return tuple(random.Random(local_seed).sample(range(population), subset_size))


def _selected_rows_under_budget(
    instance: ExactProblem,
    indices: Sequence[int],
    control: SolverRunControl,
) -> tuple[tuple[int, ...], ...]:
    selected = tuple(indices)
    # Rows, the n-by-2n elimination scratch, selected RHS values, and container
    # overhead are all retained together while a candidate is formed.
    estimate = 4096 + instance.n * instance.n * 144 + instance.n * 256
    control.preflight(estimate)
    rows: list[tuple[int, ...]] = []
    for index in selected:
        reason = control.stop_reason()
        if reason == "memory_cap":
            raise MemoryLimitExceeded
        if reason == "time_cap":
            raise TimeLimitExceeded
        block = instance.materialize_row_block(index, index + 1)
        if len(block) != 1 or len(block[0]) != instance.n:
            raise ValueError("public instance dimensions disagree")
        rows.append(tuple(block[0]))
        control.preflight(0)
    return tuple(rows)


class CleanSubsetRecovery(ValidatedExactSolver):
    solver_id = "bounded_error"
    solver_revision = "bounded-error-v2"

    def _solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult:
        started = time.monotonic()
        if not applicability(instance, request):
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                detail={"code": "inapplicable_clean_subset"},
            )
        try:
            if len(instance.b) != instance.m:
                raise ValueError("public instance dimensions disagree")
            cap = _positive_int_parameter(
                request,
                "clean_subset_cap",
                max(1_000, 20 * instance.m),
            )
            cap = min(
                cap,
                _positive_int_parameter(request, "work_unit_cap", cap),
            )
            memory_cap = memory_cap_bytes(request)
            control = SolverRunControl.create(
                instance=instance,
                request=request,
                solver_id=self.solver_id,
                solver_revision=self.solver_revision,
                search_descriptor={
                    "algorithm": "deterministic_clean_subset_v1",
                    "m": instance.m,
                    "n": instance.n,
                    "q": instance.q,
                    "error_weight": instance.error_weight,
                    "secret_predicate_kind": instance.secret_predicate_kind,
                    "secret_alphabet": tuple(instance.secret_alphabet),
                    "attempt_cap": cap,
                },
                memory_cap_bytes=memory_cap,
            )
            state = control.solver_state
            state_keys = frozenset(state)
            persisted_keys = frozenset(
                {"singular_count", "active_ordinal", "pending_candidate"}
            )
            if state_keys not in (frozenset(), persisted_keys):
                raise SolverContractError("checkpoint run state is malformed")
            singular_count = state.get("singular_count", 0)
            active_ordinal = state.get("active_ordinal")
            raw_pending_candidate = state.get("pending_candidate")
            if raw_pending_candidate is None:
                pending_candidate: tuple[int, ...] | None = None
            elif type(raw_pending_candidate) in (list, tuple):
                pending_candidate = tuple(raw_pending_candidate)
            else:
                raise SolverContractError("checkpoint run state is malformed")
            if (
                type(singular_count) is not int
                or singular_count < 0
                or singular_count > control.cursor
                or control.cursor > cap
                or (
                    active_ordinal is None
                    and (
                        pending_candidate is not None
                        or control.work_units != control.cursor
                    )
                )
                or (
                    active_ordinal is not None
                    and (
                        type(active_ordinal) is not int
                        or active_ordinal != control.cursor
                        or active_ordinal >= cap
                        or control.work_units != control.cursor + 1
                        or (
                            pending_candidate is not None
                            and (
                                len(pending_candidate) != instance.n
                                or any(
                                    type(value) is not int
                                    for value in pending_candidate
                                )
                            )
                        )
                    )
                )
            ):
                raise SolverContractError("checkpoint run state is malformed")
        except SolverContractError:
            return SolveResult.error(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                peak_rss_bytes=_peak_rss_bytes(),
                detail={"code": "checkpoint_invalid"},
            )
        except (AttributeError, TypeError, ValueError):
            return SolveResult.error(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                detail={"code": "invalid_public_parameters"},
            )

        def state_payload() -> dict[str, object]:
            return {
                "singular_count": singular_count,
                "active_ordinal": active_ordinal,
                "pending_candidate": pending_candidate,
            }

        def censored(reason: str, *, phase: str) -> SolveResult:
            control.advance(
                cursor=control.cursor,
                work_units=control.work_units,
                solver_state=state_payload(),
            )
            try:
                control.checkpoint(force=True, phase=phase)
            except SolverContractError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "checkpoint_failure"},
                )
            parameters: dict[str, object] = {
                "subset_size": instance.n,
                "tested_count": control.work_units,
            }
            if reason == "memory_cap":
                parameters.update(
                    {
                        "cap": memory_cap,
                        "cap_unit": "bytes",
                        "memory_cap_bytes": memory_cap,
                    }
                )
            elif reason == "work_unit_cap":
                parameters.update(
                    {
                        "cap": cap,
                        "cap_unit": "work_units",
                        "work_unit_cap": cap,
                        "candidate_count": control.work_units - singular_count,
                    }
                )
            return SolveResult.censored(
                elapsed_seconds=control.elapsed_seconds,
                work_units=control.work_units,
                peak_rss_bytes=control.observe_peak(),
                checkpoint_count=control.checkpoint_count,
                detail={"reason": reason, "public_parameters": parameters},
            )

        def check_budget() -> None:
            reason = control.stop_reason()
            if reason == "memory_cap":
                raise MemoryLimitExceeded
            if reason == "time_cap":
                raise TimeLimitExceeded

        while control.cursor < cap:
            reason = control.stop_reason()
            if reason is not None:
                return censored(reason, phase=f"clean_subset_{reason}")
            ordinal = control.cursor
            indices = _deterministic_subset(
                seed=request.seed,
                ordinal=ordinal,
                population=instance.m,
                subset_size=instance.n,
            )
            if active_ordinal is None:
                active_ordinal = ordinal
                control.advance(
                    cursor=ordinal,
                    work_units=control.work_units + 1,
                    solver_state=state_payload(),
                )
                try:
                    control.checkpoint(
                        force=True,
                        phase="clean_subset_attempt_start",
                    )
                except SolverContractError:
                    return SolveResult.error(
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=control.work_units,
                        peak_rss_bytes=control.observe_peak(),
                        checkpoint_count=control.checkpoint_count,
                        detail={"code": "checkpoint_failure"},
                    )

            candidate = pending_candidate
            if candidate is None:
                try:
                    selected_rows = _selected_rows_under_budget(
                        instance,
                        indices,
                        control,
                    )
                except MemoryLimitExceeded:
                    return censored("memory_cap", phase="clean_subset_memory_cap")
                except TimeLimitExceeded:
                    return censored("time_cap", phase="clean_subset_time_cap")
                except (AttributeError, TypeError, ValueError):
                    return SolveResult.error(
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=control.work_units,
                        peak_rss_bytes=control.observe_peak(),
                        checkpoint_count=control.checkpoint_count,
                        detail={"code": "invalid_public_parameters"},
                    )
                try:
                    outcome = sampled_subset_candidate(
                        rows=selected_rows,
                        rhs=tuple(instance.b[index] for index in indices),
                        row_indices=tuple(range(instance.n)),
                        q=instance.q,
                        predicate_kind=instance.secret_predicate_kind,
                        alphabet=instance.secret_alphabet,
                        budget_check=check_budget,
                    )
                except MemoryLimitExceeded:
                    return censored("memory_cap", phase="clean_subset_memory_cap")
                except TimeLimitExceeded:
                    return censored("time_cap", phase="clean_subset_time_cap")
                if outcome.kind == "singular":
                    singular_count += 1
                candidate = outcome.secret
                if candidate is not None:
                    candidate = tuple(candidate)
                    if len(candidate) != instance.n or any(
                        type(value) is not int for value in candidate
                    ):
                        return SolveResult.error(
                            elapsed_seconds=control.elapsed_seconds,
                            work_units=control.work_units,
                            peak_rss_bytes=control.observe_peak(),
                            checkpoint_count=control.checkpoint_count,
                            detail={"code": "candidate_contract"},
                        )
                    pending_candidate = candidate
                    control.advance(
                        cursor=ordinal,
                        work_units=control.work_units,
                        solver_state=state_payload(),
                    )
                    try:
                        control.checkpoint(
                            force=True,
                            phase="clean_subset_candidate_pending",
                        )
                    except SolverContractError:
                        return SolveResult.error(
                            elapsed_seconds=control.elapsed_seconds,
                            work_units=control.work_units,
                            peak_rss_bytes=control.observe_peak(),
                            checkpoint_count=control.checkpoint_count,
                            detail={"code": "checkpoint_failure"},
                        )

            if candidate is None or candidate == request.exclude_secret:
                active_ordinal = None
                pending_candidate = None
                control.advance(
                    cursor=ordinal + 1,
                    work_units=control.work_units,
                    solver_state=state_payload(),
                )
                try:
                    control.checkpoint(phase="clean_subset_checkpoint")
                except SolverContractError:
                    return SolveResult.error(
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=control.work_units,
                        peak_rss_bytes=control.observe_peak(),
                        checkpoint_count=control.checkpoint_count,
                        detail={"code": "checkpoint_failure"},
                    )
                continue
            reason = control.stop_reason()
            if reason is not None:
                return censored(
                    reason,
                    phase="clean_subset_budget_cap",
                )
            verdict = instance.validate_secret(candidate)
            reason = control.stop_reason()
            if reason is not None:
                return censored(reason, phase=f"clean_subset_{reason}")
            if getattr(verdict, "ok", None) is True:
                try:
                    control.checkpoint(force=True, phase="clean_subset_success")
                except SolverContractError:
                    return SolveResult.error(
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=control.work_units,
                        peak_rss_bytes=control.observe_peak(),
                        checkpoint_count=control.checkpoint_count,
                        detail={"code": "checkpoint_failure"},
                    )
                return SolveResult.success(
                    secret=candidate,
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={
                        "public_parameters": {
                            "subset_size": instance.n,
                            "tested_count": control.work_units,
                        }
                    },
                )
            active_ordinal = None
            pending_candidate = None
            control.advance(
                cursor=ordinal + 1,
                work_units=control.work_units,
                solver_state=state_payload(),
            )
            try:
                control.checkpoint(phase="clean_subset_checkpoint")
            except SolverContractError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "checkpoint_failure"},
                )
        return censored("work_unit_cap", phase="clean_subset_work_unit_cap")


__all__ = (
    "CleanSubsetRecovery",
    "MemoryLimitExceeded",
    "SolverRunControl",
    "SubsetCandidate",
    "TimeLimitExceeded",
    "applicability",
    "invert_matrix_mod_prime",
    "is_prime",
    "map_secret_representatives",
    "memory_cap_bytes",
    "multiply_matrix_vector_mod",
    "sampled_subset_candidate",
)
