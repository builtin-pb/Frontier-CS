"""Systematic Construction-A primal BDD fallback.

All matrix construction and candidate decoding helpers are dependency-free.
``fpylll`` is imported only inside the validated solver body.
"""

from __future__ import annotations

import math
import multiprocessing
import os
import resource
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Mapping, Sequence

from .api import (
    ExactProblem,
    ValidatedExactSolver,
    SolveRequest,
    SolveResult,
    SolverContractError,
)
from .bounded_error import (
    MemoryLimitExceeded,
    SolverRunControl,
    TimeLimitExceeded,
    _current_rss_bytes,
    _peak_rss_bytes,
    invert_matrix_mod_prime,
    is_prime,
    map_secret_representatives,
    memory_cap_bytes,
    multiply_matrix_vector_mod,
)


_THREAD_POLICY = {
    "MKL_NUM_THREADS": "1",
    "OMP_NUM_THREADS": "1",
    "OPENBLAS_NUM_THREADS": "1",
    "VECLIB_MAXIMUM_THREADS": "1",
}


@dataclass(frozen=True, slots=True)
class ConstructionA:
    q: int
    n: int
    m: int
    independent_rows: tuple[int, ...]
    remaining_rows: tuple[int, ...]
    permutation: tuple[int, ...]
    a0_inverse: tuple[tuple[int, ...], ...]
    c: tuple[tuple[int, ...], ...]
    basis: tuple[tuple[int, ...], ...]

    def vector_is_in_lattice(
        self,
        vector: Sequence[int],
        *,
        budget_check: Callable[[], None] | None = None,
    ) -> bool:
        values = tuple(vector)
        if len(values) != self.m:
            return False
        leading = values[: self.n]
        trailing = values[self.n :]
        for observed, row in zip(trailing, self.c, strict=True):
            if budget_check is not None:
                budget_check()
            inner_product = 0
            for coefficient, value in zip(row, leading, strict=True):
                inner_product += coefficient * value
            if (observed - inner_product) % self.q != 0:
                return False
        return True


@dataclass(frozen=True, slots=True)
class IndependentCVPCheck:
    complete: bool
    exact: bool
    tested_vectors: int
    reason: str
    next_ordinal: int = 0


@dataclass(frozen=True, slots=True)
class BackendOutcome:
    reason: str
    vector: tuple[int, ...] | None
    peak_rss_bytes: int = 0


def _set_worker_memory_limit(memory_cap: int) -> None:
    if type(memory_cap) is not int or memory_cap <= 0:
        raise ValueError("worker memory cap must be positive")
    if hasattr(resource, "RLIMIT_AS"):
        try:
            resource.setrlimit(resource.RLIMIT_AS, (memory_cap, memory_cap))
        except (OSError, ValueError):
            # macOS may refuse to lower RLIMIT_AS below the process's existing
            # virtual address reservation.  The parent still samples aggregate
            # RSS and terminates the worker as soon as the same cap is crossed.
            pass


def _native_backend_worker(
    connection,
    construction: ConstructionA,
    target: tuple[int, ...],
    mode: str,
    block_size: int,
    memory_cap: int,
) -> None:
    try:
        _set_worker_memory_limit(memory_cap)
        vector = _closest_lattice_vector(
            construction,
            target,
            mode=mode,
            block_size=block_size,
        )
        connection.send(("ok", vector, _peak_rss_bytes()))
    except MemoryError:
        connection.send(("memory_cap", None, _peak_rss_bytes()))
    except BaseException:
        # Native exception text and paths are deliberately not serialized.
        connection.send(("backend_error", None, _peak_rss_bytes()))
    finally:
        connection.close()


def _terminate_worker(process) -> None:
    if process.is_alive():
        process.terminate()
    process.join(timeout=1.0)
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
        process.join(timeout=1.0)


def run_deadline_bounded_backend(
    construction: ConstructionA,
    *,
    target: tuple[int, ...],
    mode: str,
    block_size: int,
    deadline: float,
    memory_cap_bytes: int,
    worker: Callable[..., None] = _native_backend_worker,
    context_name: str = "fork",
) -> BackendOutcome:
    """Run the non-interruptible native backend under one supervised worker.

    The supported platforms are POSIX-only. ``fork`` avoids serializing and
    duplicating the dense Construction-A basis before supervision begins; the
    parent imports no native solver library before forking.
    """

    if (
        type(deadline) not in (int, float)
        or isinstance(deadline, bool)
        or not math.isfinite(float(deadline))
        or type(memory_cap_bytes) is not int
        or memory_cap_bytes <= 0
    ):
        raise ValueError("native backend budget is invalid")
    aggregate_peak = _current_rss_bytes()

    def result(
        reason: str,
        vector: tuple[int, ...] | None = None,
    ) -> BackendOutcome:
        return BackendOutcome(reason, vector, aggregate_peak)

    if time.monotonic() >= deadline:
        return result("time_cap")
    try:
        context = multiprocessing.get_context(context_name)
    except ValueError as exc:
        raise RuntimeError("native backend process context is unavailable") from exc
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=worker,
        args=(sender, construction, target, mode, block_size, memory_cap_bytes),
        daemon=False,
    )
    process.start()
    sender.close()
    try:
        try:
            import psutil

            child = psutil.Process(process.pid)
        except Exception:
            _terminate_worker(process)
            return result("backend_error")
        while True:
            now = time.monotonic()
            if now >= deadline:
                _terminate_worker(process)
                return result("time_cap")
            try:
                aggregate_rss = _current_rss_bytes() + int(child.memory_info().rss)
            except Exception:
                if process.is_alive():
                    _terminate_worker(process)
                    return result("backend_error")
                aggregate_rss = _current_rss_bytes()
            aggregate_peak = max(aggregate_peak, aggregate_rss)
            if aggregate_rss > memory_cap_bytes:
                _terminate_worker(process)
                return result("memory_cap")
            if receiver.poll(min(0.01, max(0.0, deadline - now))):
                try:
                    payload = receiver.recv()
                except (EOFError, OSError):
                    payload = ("backend_error", None, 0)
                process.join(timeout=1.0)
                if process.is_alive():
                    _terminate_worker(process)
                    return result("backend_error")
                if (
                    type(payload) is not tuple
                    or len(payload) != 3
                    or payload[0]
                    not in {"ok", "memory_cap", "backend_error"}
                ):
                    return result("backend_error")
                reason, vector, worker_peak = payload
                if type(worker_peak) is not int or worker_peak < 0:
                    return result("backend_error")
                aggregate_peak = max(
                    aggregate_peak,
                    _current_rss_bytes() + worker_peak,
                )
                if aggregate_peak > memory_cap_bytes:
                    return result("memory_cap")
                if reason != "ok":
                    return result(reason)
                if (
                    type(vector) is not tuple
                    or len(vector) != construction.m
                    or any(type(value) is not int for value in vector)
                ):
                    return result("backend_error")
                return result("ok", vector)
            if not process.is_alive():
                process.join(timeout=1.0)
                return result("backend_error")
    finally:
        receiver.close()


def _rank_mod_prime(
    rows: Sequence[Sequence[int]],
    q: int,
    *,
    budget_check: Callable[[], None] | None = None,
) -> int:
    if not is_prime(q):
        raise ValueError("q must be prime")
    matrix: list[list[int]] = []
    for row in rows:
        if budget_check is not None:
            budget_check()
        matrix.append([value % q for value in row])
    if not matrix:
        return 0
    width = len(matrix[0])
    if any(len(row) != width for row in matrix):
        raise ValueError("matrix is ragged")
    pivot_row = 0
    for column in range(width):
        if budget_check is not None:
            budget_check()
        pivot = None
        for row in range(pivot_row, len(matrix)):
            if budget_check is not None:
                budget_check()
            if matrix[row][column]:
                pivot = row
                break
        if pivot is None:
            continue
        matrix[pivot_row], matrix[pivot] = matrix[pivot], matrix[pivot_row]
        inverse = pow(matrix[pivot_row][column], -1, q)
        matrix[pivot_row] = [(value * inverse) % q for value in matrix[pivot_row]]
        for row in range(len(matrix)):
            if budget_check is not None:
                budget_check()
            if row == pivot_row:
                continue
            factor = matrix[row][column]
            if factor:
                matrix[row] = [
                    (left - factor * right) % q
                    for left, right in zip(matrix[row], matrix[pivot_row], strict=True)
                ]
        pivot_row += 1
        if pivot_row == len(matrix):
            break
    return pivot_row


def build_construction_a(
    rows: Sequence[Sequence[int]],
    *,
    q: int,
    budget_check: Callable[[], None] | None = None,
) -> ConstructionA:
    materialized_rows: list[tuple[int, ...]] = []
    for row in rows:
        if budget_check is not None:
            budget_check()
        materialized_rows.append(tuple(row))
    materialized = tuple(materialized_rows)
    if not is_prime(q):
        raise ValueError("q must be prime")
    if not materialized or not materialized[0]:
        raise ValueError("matrix must be nonempty")
    n = len(materialized[0])
    m = len(materialized)
    if m < n or any(len(row) != n for row in materialized):
        raise ValueError("matrix dimensions do not admit a square minor")

    selected: list[int] = []
    current_rows: list[tuple[int, ...]] = []
    rank = 0
    for index, row in enumerate(materialized):
        if budget_check is not None:
            budget_check()
        candidate_rank = _rank_mod_prime(
            (*current_rows, row),
            q,
            budget_check=budget_check,
        )
        if candidate_rank > rank:
            selected.append(index)
            current_rows.append(row)
            rank = candidate_rank
            if rank == n:
                break
    if rank != n:
        raise ValueError("matrix is rank deficient modulo q")

    independent = tuple(selected)
    independent_set = frozenset(independent)
    remaining = tuple(index for index in range(m) if index not in independent_set)
    inverse = invert_matrix_mod_prime(
        tuple(materialized[index] for index in independent),
        q,
        budget_check=budget_check,
    )
    if inverse is None:  # Kept as a defensive invariant after rank selection.
        raise ValueError("selected minor is rank deficient modulo q")
    c_rows: list[tuple[int, ...]] = []
    for row_index in remaining:
        row = materialized[row_index]
        transformed: list[int] = []
        for output in range(n):
            if budget_check is not None:
                budget_check()
            transformed.append(
                sum(row[column] * inverse[column][output] for column in range(n))
                % q
            )
        c_rows.append(tuple(transformed))
    c = tuple(c_rows)
    dimension = m
    basis_rows: list[tuple[int, ...]] = []
    for index in range(n):
        if budget_check is not None:
            budget_check()
        basis_rows.append(
            tuple(
                (1 if column == index else 0)
                if column < n
                else c[column - n][index]
                for column in range(dimension)
            )
        )
    for trailing_index in range(m - n):
        if budget_check is not None:
            budget_check()
        basis_rows.append(
            tuple(
                q if column == n + trailing_index else 0
                for column in range(dimension)
            )
        )
    return ConstructionA(
        q=q,
        n=n,
        m=m,
        independent_rows=independent,
        remaining_rows=remaining,
        permutation=(*independent, *remaining),
        a0_inverse=inverse,
        c=c,
        basis=tuple(basis_rows),
    )


def candidate_from_codeword(
    construction: ConstructionA,
    codeword: Sequence[int],
    *,
    predicate_kind: str,
    alphabet: Sequence[int],
    budget_check: Callable[[], None] | None = None,
) -> tuple[int, ...]:
    values = tuple(codeword)
    if len(values) != construction.m:
        raise ValueError("codeword dimension disagrees with Construction-A basis")
    if not construction.vector_is_in_lattice(values, budget_check=budget_check):
        raise ValueError("candidate codeword is not in the Construction-A lattice")
    residues = multiply_matrix_vector_mod(
        construction.a0_inverse,
        values[: construction.n],
        construction.q,
        budget_check=budget_check,
    )
    return map_secret_representatives(
        residues,
        q=construction.q,
        predicate_kind=predicate_kind,
        alphabet=alphabet,
    )


def classify_unsuccessful_cvp(
    *, mode: str, elapsed_seconds: float, work_units: int
) -> SolveResult:
    if mode not in {"nearest_plane", "exact_cvp"}:
        raise ValueError("unsupported CVP mode")
    # A closest-vector miss does not enumerate the complete public witness
    # domain.  Therefore neither mode can claim EXHAUSTED here.
    return SolveResult.censored(
        elapsed_seconds=elapsed_seconds,
        work_units=work_units,
        detail={"code": f"{mode}_candidate_rejected"},
    )


def verify_independent_exact_cvp(
    construction: ConstructionA,
    *,
    target: Sequence[int],
    candidate: Sequence[int],
    work_unit_cap: int,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
    rss_reader: Callable[[], int] = _current_rss_bytes,
    start_ordinal: int = 0,
    progress_callback: Callable[[int, int], None] | None = None,
    max_dimension: int = 12,
    max_distance_squared: int = 64,
) -> IndependentCVPCheck:
    """Independently check exactness by bounded shorter-error enumeration.

    For the systematic Construction-A lattice, a vector ``v`` is a lattice
    point exactly when :meth:`ConstructionA.vector_is_in_lattice` accepts it.
    To prove a backend candidate closest, enumerate every integral error vector
    whose squared norm is strictly smaller than the candidate distance and
    reject if ``target - error`` is another lattice point.  Fixed dimension,
    distance, work, and time bounds keep this independent check fail-closed.
    """

    observed_target = tuple(target)
    observed_candidate = tuple(candidate)
    if (
        type(work_unit_cap) is not int
        or work_unit_cap < 0
        or type(start_ordinal) is not int
        or start_ordinal < 0
        or type(max_dimension) is not int
        or max_dimension <= 0
        or type(max_distance_squared) is not int
        or max_distance_squared < 0
        or (
            memory_cap_bytes is not None
            and (type(memory_cap_bytes) is not int or memory_cap_bytes <= 0)
        )
    ):
        raise ValueError("independent CVP verification bounds are invalid")
    if (
        len(observed_target) != construction.m
        or len(observed_candidate) != construction.m
        or any(type(value) is not int for value in (*observed_target, *observed_candidate))
    ):
        raise ValueError("independent CVP verification dimensions disagree")
    if not construction.vector_is_in_lattice(observed_candidate):
        raise ValueError("backend candidate is outside the Construction-A lattice")
    if construction.m > max_dimension:
        return IndependentCVPCheck(
            False,
            False,
            0,
            "dimension_limit",
            start_ordinal,
        )
    distance_squared = sum(
        (left - right) * (left - right)
        for left, right in zip(observed_target, observed_candidate, strict=True)
    )
    if distance_squared > max_distance_squared:
        return IndependentCVPCheck(
            False,
            False,
            0,
            "distance_limit",
            start_ordinal,
        )
    if distance_squared == 0:
        return IndependentCVPCheck(
            True,
            True,
            0,
            "verified_exact",
            start_ordinal,
        )

    shorter_bound = distance_squared - 1
    dimension = construction.m

    @lru_cache(maxsize=None)
    def completion_count(coordinate: int, remaining_squared: int) -> int:
        if coordinate == dimension:
            return 1
        radius = math.isqrt(remaining_squared)
        return sum(
            completion_count(
                coordinate + 1,
                remaining_squared - value * value,
            )
            for value in range(-radius, radius + 1)
        )

    total_vectors = completion_count(0, shorter_bound)
    if start_ordinal > total_vectors:
        raise ValueError("independent CVP resume ordinal is out of range")

    def vector_at_ordinal(ordinal: int) -> tuple[int, ...]:
        if not 0 <= ordinal < total_vectors:
            raise ValueError("independent CVP ordinal is out of range")
        values: list[int] = []
        remaining_squared = shorter_bound
        for coordinate in range(dimension):
            radius = math.isqrt(remaining_squared)
            for value in range(-radius, radius + 1):
                count = completion_count(
                    coordinate + 1,
                    remaining_squared - value * value,
                )
                if ordinal < count:
                    values.append(value)
                    remaining_squared -= value * value
                    break
                ordinal -= count
            else:  # Defensive invariant for the counted traversal.
                raise RuntimeError("independent CVP ordinal unranking failed")
        return tuple(values)

    tested = 0
    stopped: str | None = None
    found_shorter = False
    next_ordinal = start_ordinal
    for ordinal in range(start_ordinal, total_vectors):
        if memory_cap_bytes is not None and rss_reader() > memory_cap_bytes:
            stopped = "memory_cap"
            break
        if deadline is not None and time.monotonic() >= deadline:
            stopped = "timeout"
            break
        if tested >= work_unit_cap:
            stopped = "work_unit_cap"
            break
        error = vector_at_ordinal(ordinal)
        tested += 1
        lattice_point = tuple(
            value - delta
            for value, delta in zip(observed_target, error, strict=True)
        )
        if construction.vector_is_in_lattice(lattice_point):
            found_shorter = True
        if found_shorter:
            # A shorter vector is a terminal refutation, not traversed search
            # state.  Keep the resumable cursor on this ordinal so a caller
            # that resumes a censored result cannot skip the refutation.
            next_ordinal = ordinal
            break
        next_ordinal = ordinal + 1
        if progress_callback is not None:
            progress_callback(next_ordinal, tested)
    if found_shorter:
        return IndependentCVPCheck(
            True,
            False,
            tested,
            "shorter_lattice_vector",
            next_ordinal,
        )
    if stopped is not None:
        return IndependentCVPCheck(
            False,
            False,
            tested,
            stopped,
            next_ordinal,
        )
    return IndependentCVPCheck(
        True,
        True,
        tested,
        "verified_exact",
        next_ordinal,
    )


def _basic_applicability(instance: ExactProblem) -> bool:
    return not (
        type(instance.n) is not int
        or type(instance.m) is not int
        or instance.n <= 0
        or instance.m <= instance.n
        or not is_prime(instance.q)
    )


def _primal_retained_state_bytes(m: int, n: int) -> int:
    if type(m) is not int or type(n) is not int or m <= 0 or n <= 0:
        raise ValueError("primal dimensions must be positive integers")
    entries = m * n + n * n + (m - n) * n + m * m
    return 16_384 + entries * 128 + (m + n) * 512


def _materialize_primal_rows(
    instance: ExactProblem,
    *,
    preflight: Callable[[int], None],
) -> tuple[tuple[int, ...], ...]:
    preflight(_primal_retained_state_bytes(instance.m, instance.n))
    rows = instance.materialize_row_block(0, instance.m)
    if len(rows) != instance.m or any(len(row) != instance.n for row in rows):
        raise ValueError("public instance dimensions disagree")
    preflight(0)
    return tuple(tuple(row) for row in rows)


def applicability(instance: ExactProblem, request: SolveRequest | None = None) -> bool:
    if not _basic_applicability(instance):
        return False
    try:
        cap = (
            512 * 1024 * 1024
            if request is None
            else memory_cap_bytes(request)
        )
        def preflight(estimate: int) -> None:
            if _current_rss_bytes() + estimate > cap:
                raise MemoryLimitExceeded

        rows = _materialize_primal_rows(instance, preflight=preflight)
        construction = build_construction_a(rows, q=instance.q)
    except (AttributeError, MemoryLimitExceeded, TypeError, ValueError):
        return False
    return construction.n == instance.n and construction.m == instance.m


def single_thread_policy_satisfied(
    environment: Mapping[str, str] | None = None,
) -> bool:
    observed = os.environ if environment is None else environment
    return all(observed.get(name) == value for name, value in _THREAD_POLICY.items())


def _configure_single_thread_policy() -> None:
    """Configure lazy native dependencies before importing their runtimes."""

    for name, value in _THREAD_POLICY.items():
        os.environ[name] = value


def _cvp_mode(request: SolveRequest) -> str:
    value = request.parameters.get("primal_cvp_mode", "nearest_plane")
    if type(value) is not str or value not in {"nearest_plane", "exact_cvp"}:
        raise ValueError("primal_cvp_mode must be nearest_plane or exact_cvp")
    return value


def _bkz_block_size(request: SolveRequest, dimension: int) -> int:
    value = request.parameters.get("primal_bkz_block_size", min(20, dimension))
    if type(value) is not int or value < 2 or value > dimension:
        raise ValueError("primal_bkz_block_size is outside the lattice dimension")
    return value


def _exact_verification_cap(request: SolveRequest) -> int:
    value = request.parameters.get("primal_exact_verification_cap", 250_000)
    if type(value) is not int or value < 0 or value > 1_000_000:
        raise ValueError("primal_exact_verification_cap must be between zero and one million")
    return value


def _global_work_unit_cap(request: SolveRequest, default: int) -> int:
    value = request.parameters.get("work_unit_cap", default)
    if type(value) is not int or value <= 0:
        raise ValueError("work_unit_cap must be a positive integer")
    return value


def _lattice_vector_from_coefficients(
    basis, coefficients: Sequence[int]
) -> tuple[int, ...]:
    dimension = basis.ncols
    return tuple(
        sum(int(coefficients[row]) * int(basis[row, column]) for row in range(basis.nrows))
        for column in range(dimension)
    )


def _closest_lattice_vector(
    construction: ConstructionA,
    target: tuple[int, ...],
    *,
    mode: str,
    block_size: int,
) -> tuple[int, ...]:
    # Native dependencies stay lazy so the evaluator and non-lattice solvers
    # do not need fpylll.  Environment receipts are a packaging check, not a
    # precondition for using the public reference solver.
    from fpylll import BKZ, CVP, GSO, IntegerMatrix

    basis = IntegerMatrix.from_matrix([list(row) for row in construction.basis])
    BKZ.reduction(basis, BKZ.Param(block_size=block_size))
    if mode == "nearest_plane":
        gso = GSO.Mat(basis)
        gso.update_gso()
        coefficients = gso.babai(target)
        vector = _lattice_vector_from_coefficients(basis, coefficients)
    else:
        vector = tuple(int(value) for value in CVP.closest_vector(basis, target, method="proved"))
    # Structurally verify membership against the unreduced public
    # Construction-A congruences.  This does not establish closest-vector
    # exactness; exact mode performs a separate bounded independent check.
    if not construction.vector_is_in_lattice(vector):
        raise RuntimeError("CVP backend returned a vector outside the lattice")
    return vector


class PrimalBDD(ValidatedExactSolver):
    solver_id = "primal_bdd"
    solver_revision = "primal-bdd-v2"

    def _solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult:
        started = time.monotonic()
        if not _basic_applicability(instance):
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                detail={"code": "inapplicable_primal_bdd"},
            )
        _configure_single_thread_policy()
        if not single_thread_policy_satisfied():
            return SolveResult.error(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                detail={"code": "single_thread_policy_required"},
            )
        try:
            mode = _cvp_mode(request)
            block_size = _bkz_block_size(request, instance.m)
            exact_verification_cap = (
                _exact_verification_cap(request) if mode == "exact_cvp" else 0
            )
            global_work_cap = _global_work_unit_cap(
                request,
                1 + exact_verification_cap,
            )
            memory_cap = memory_cap_bytes(request)
            control = SolverRunControl.create(
                instance=instance,
                request=request,
                solver_id=self.solver_id,
                solver_revision=self.solver_revision,
                search_descriptor={
                    "algorithm": "construction_a_supervised_v2",
                    "m": instance.m,
                    "n": instance.n,
                    "q": instance.q,
                    "mode": mode,
                    "block_size": block_size,
                    "exact_verification_cap": exact_verification_cap,
                    "global_work_unit_cap": global_work_cap,
                },
                memory_cap_bytes=memory_cap,
            )
            if control.cursor not in (0, 1) or control.work_units > global_work_cap:
                raise SolverContractError("checkpoint run state is malformed")
            saved_state = control.solver_state
            if control.cursor == 0:
                if not saved_state and control.work_units == 0:
                    backend_attempted = False
                elif frozenset(saved_state) == {"backend_attempted"} and (
                    saved_state["backend_attempted"] is True
                    and control.work_units == 1
                ):
                    backend_attempted = True
                else:
                    raise SolverContractError("checkpoint run state is malformed")
                saved_codeword = None
                exact_verified = False
                exact_cursor = 0
            else:
                if frozenset(saved_state) != {
                    "codeword",
                    "exact_verified",
                    "exact_cursor",
                    "exact_refuted",
                }:
                    raise SolverContractError("checkpoint run state is malformed")
                raw_codeword = saved_state["codeword"]
                raw_exact_verified = saved_state["exact_verified"]
                raw_exact_cursor = saved_state["exact_cursor"]
                raw_exact_refuted = saved_state["exact_refuted"]
                if (
                    type(raw_codeword) not in (list, tuple)
                    or len(raw_codeword) != instance.m
                    or any(type(value) is not int for value in raw_codeword)
                    or type(raw_exact_verified) is not bool
                    or raw_exact_verified
                    or type(raw_exact_cursor) is not int
                    or not 0 <= raw_exact_cursor <= exact_verification_cap
                    or type(raw_exact_refuted) is not bool
                    or (
                        raw_exact_refuted
                        and mode != "exact_cvp"
                    )
                    or control.work_units
                    != 1 + raw_exact_cursor + (1 if raw_exact_refuted else 0)
                ):
                    raise SolverContractError("checkpoint run state is malformed")
                saved_codeword = tuple(raw_codeword)
                backend_attempted = True
                exact_verified = False
                exact_cursor = raw_exact_cursor
                exact_refuted = raw_exact_refuted
            if control.cursor == 0:
                exact_refuted = False
            reason = control.stop_reason()
            if reason is not None:
                return self._censored_budget(
                    control,
                    reason=reason,
                    memory_cap=memory_cap,
                    work_unit_cap=global_work_cap,
                    phase=f"primal_{reason}",
                )

            def check_budget() -> None:
                observed_reason = control.stop_reason()
                if observed_reason == "memory_cap":
                    raise MemoryLimitExceeded
                if observed_reason == "time_cap":
                    raise TimeLimitExceeded

            rows = _materialize_primal_rows(instance, preflight=control.preflight)
            construction = build_construction_a(
                rows,
                q=instance.q,
                budget_check=check_budget,
            )
            target_values: list[int] = []
            for index in construction.permutation:
                check_budget()
                target_values.append(instance.b[index])
            target = tuple(target_values)
            if len(target) != construction.m:
                raise ValueError("public target dimension disagrees with matrix")
            if saved_codeword is not None and not construction.vector_is_in_lattice(
                saved_codeword,
                budget_check=check_budget,
            ):
                raise SolverContractError("checkpoint backend candidate is malformed")
        except MemoryLimitExceeded:
            return self._censored_budget(
                control,
                reason="memory_cap",
                memory_cap=memory_cap,
                work_unit_cap=global_work_cap,
                phase="primal_memory_cap",
            )
        except TimeLimitExceeded:
            return self._censored_budget(
                control,
                reason="time_cap",
                memory_cap=memory_cap,
                work_unit_cap=global_work_cap,
                phase="primal_time_cap",
            )
        except SolverContractError:
            return SolveResult.error(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                peak_rss_bytes=_peak_rss_bytes(),
                detail={"code": "checkpoint_invalid"},
            )
        except (AttributeError, TypeError, ValueError):
            # Rank deficiency and malformed dimensions are non-applicable to
            # this fallback; no candidate-domain certificate is claimed.
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                peak_rss_bytes=_peak_rss_bytes(),
                detail={"code": "inapplicable_primal_bdd"},
            )

        codeword = saved_codeword
        if codeword is not None and exact_refuted:
            return SolveResult.censored(
                elapsed_seconds=control.elapsed_seconds,
                work_units=control.work_units,
                peak_rss_bytes=control.observe_peak(),
                checkpoint_count=control.checkpoint_count,
                detail={"code": "exact_cvp_backend_candidate_refuted"},
            )
        if codeword is None:
            if control.work_units >= global_work_cap:
                return self._censored_budget(
                    control,
                    reason="work_unit_cap",
                    memory_cap=memory_cap,
                    work_unit_cap=global_work_cap,
                    phase="primal_work_unit_cap",
                )
            if backend_attempted:
                return SolveResult.censored(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "primal_backend_attempt_incomplete"},
                )
            control.advance(
                cursor=0,
                work_units=control.work_units + 1,
                solver_state={"backend_attempted": True},
            )
            backend_attempted = True
            try:
                control.checkpoint(force=True, phase="primal_backend_start")
            except SolverContractError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "checkpoint_failure"},
                )
            outcome = run_deadline_bounded_backend(
                construction,
                target=target,
                mode=mode,
                block_size=block_size,
                deadline=control.deadline,
                memory_cap_bytes=memory_cap,
            )
            if (
                type(outcome.peak_rss_bytes) is not int
                or outcome.peak_rss_bytes < 0
            ):
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "cvp_backend_contract"},
                )
            control.peak_rss_bytes = max(
                control.peak_rss_bytes,
                outcome.peak_rss_bytes,
            )
            if outcome.peak_rss_bytes > memory_cap:
                return self._censored_budget(
                    control,
                    reason="memory_cap",
                    memory_cap=memory_cap,
                    work_unit_cap=global_work_cap,
                    phase="primal_memory_cap",
                )
            if outcome.reason in {"time_cap", "memory_cap"}:
                return self._censored_budget(
                    control,
                    reason=outcome.reason,
                    memory_cap=memory_cap,
                    work_unit_cap=global_work_cap,
                    phase=f"primal_{outcome.reason}",
                )
            if outcome.reason != "ok" or outcome.vector is None:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "cvp_backend_contract"},
                )
            codeword = outcome.vector
            try:
                codeword_in_lattice = construction.vector_is_in_lattice(
                    codeword,
                    budget_check=check_budget,
                )
            except MemoryLimitExceeded:
                return self._censored_budget(
                    control,
                    reason="memory_cap",
                    memory_cap=memory_cap,
                    work_unit_cap=global_work_cap,
                    phase="primal_memory_cap",
                )
            except TimeLimitExceeded:
                return self._censored_budget(
                    control,
                    reason="time_cap",
                    memory_cap=memory_cap,
                    work_unit_cap=global_work_cap,
                    phase="primal_time_cap",
                )
            if not codeword_in_lattice:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "cvp_backend_contract"},
                )
            control.advance(
                cursor=1,
                work_units=control.work_units,
                solver_state={
                    "codeword": codeword,
                    "exact_verified": False,
                    "exact_cursor": 0,
                    "exact_refuted": False,
                },
            )
            try:
                control.checkpoint(force=True, phase="primal_backend_complete")
            except SolverContractError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "checkpoint_failure"},
                )

        if mode == "exact_cvp" and not exact_verified:
            remaining_work = global_work_cap - control.work_units
            exact_remaining = max(0, exact_verification_cap - exact_cursor)
            exact_base_work = control.work_units

            def exact_progress(next_ordinal: int, tested: int) -> None:
                control.advance(
                    cursor=1,
                    work_units=exact_base_work + tested,
                    solver_state={
                        "codeword": codeword,
                        "exact_verified": False,
                        "exact_cursor": next_ordinal,
                        "exact_refuted": False,
                    },
                )
                control.checkpoint(phase="primal_exact_checkpoint")

            try:
                check = verify_independent_exact_cvp(
                    construction,
                    target=target,
                    candidate=codeword,
                    work_unit_cap=max(
                        0,
                        min(exact_remaining, remaining_work),
                    ),
                    deadline=control.deadline,
                    memory_cap_bytes=memory_cap,
                    start_ordinal=exact_cursor,
                    progress_callback=exact_progress,
                )
            except SolverContractError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "checkpoint_failure"},
                )
            except ValueError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "checkpoint_invalid"},
                )
            control.advance(
                cursor=control.cursor,
                work_units=exact_base_work + check.tested_vectors,
                solver_state={
                    "codeword": codeword,
                    "exact_verified": False,
                    "exact_cursor": check.next_ordinal,
                    "exact_refuted": check.reason == "shorter_lattice_vector",
                },
            )
            if not check.complete or not check.exact:
                global_work_exhausted = (
                    check.reason == "work_unit_cap"
                    and remaining_work < exact_remaining
                )
                if check.reason in {"timeout", "memory_cap"} or global_work_exhausted:
                    reason = "time_cap" if check.reason == "timeout" else check.reason
                    return self._censored_budget(
                        control,
                        reason=reason,
                        memory_cap=memory_cap,
                        work_unit_cap=global_work_cap,
                        phase=f"primal_{reason}",
                    )
                try:
                    control.checkpoint(force=True, phase="primal_exact_incomplete")
                except SolverContractError:
                    return SolveResult.error(
                        elapsed_seconds=control.elapsed_seconds,
                        work_units=control.work_units,
                        peak_rss_bytes=control.observe_peak(),
                        checkpoint_count=control.checkpoint_count,
                        detail={"code": "checkpoint_failure"},
                    )
                return SolveResult.censored(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={
                        "code": (
                            "exact_cvp_independent_proof_infeasible"
                            if not check.complete
                            else "exact_cvp_backend_candidate_refuted"
                        )
                    },
                )
            control.advance(
                cursor=1,
                work_units=control.work_units,
                solver_state={
                    "codeword": codeword,
                    "exact_verified": False,
                    "exact_cursor": check.next_ordinal,
                    "exact_refuted": False,
                },
            )
            try:
                control.checkpoint(force=True, phase="primal_exact_verified")
            except SolverContractError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "checkpoint_failure"},
                )

        try:
            candidate = candidate_from_codeword(
                construction,
                codeword,
                predicate_kind=instance.secret_predicate_kind,
                alphabet=instance.secret_alphabet,
                budget_check=check_budget,
            )
        except MemoryLimitExceeded:
            return self._censored_budget(
                control,
                reason="memory_cap",
                memory_cap=memory_cap,
                work_unit_cap=global_work_cap,
                phase="primal_memory_cap",
            )
        except TimeLimitExceeded:
            return self._censored_budget(
                control,
                reason="time_cap",
                memory_cap=memory_cap,
                work_unit_cap=global_work_cap,
                phase="primal_time_cap",
            )
        except ValueError:
            result = classify_unsuccessful_cvp(
                mode=mode,
                elapsed_seconds=control.elapsed_seconds,
                work_units=control.work_units,
            )
            try:
                control.checkpoint(force=True, phase="primal_candidate_rejected")
            except SolverContractError:
                return SolveResult.error(
                    elapsed_seconds=control.elapsed_seconds,
                    work_units=control.work_units,
                    peak_rss_bytes=control.observe_peak(),
                    checkpoint_count=control.checkpoint_count,
                    detail={"code": "checkpoint_failure"},
                )
            return SolveResult.censored(
                elapsed_seconds=result.elapsed_seconds,
                work_units=result.work_units,
                peak_rss_bytes=control.observe_peak(),
                checkpoint_count=control.checkpoint_count,
                detail=result.detail,
            )

        reason = control.stop_reason()
        if reason is not None:
            return self._censored_budget(
                control,
                reason=reason,
                memory_cap=memory_cap,
                work_unit_cap=global_work_cap,
                phase=f"primal_{reason}",
            )
        if candidate != request.exclude_secret:
            verdict = instance.validate_secret(candidate)
            reason = control.stop_reason()
            if reason is not None:
                return self._censored_budget(
                    control,
                    reason=reason,
                    memory_cap=memory_cap,
                    work_unit_cap=global_work_cap,
                    phase=f"primal_{reason}",
                )
            if getattr(verdict, "ok", None) is True:
                try:
                    control.checkpoint(force=True, phase="primal_success")
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
                            "m": instance.m,
                            "n": instance.n,
                            "q": instance.q,
                        }
                    },
                )
        result = classify_unsuccessful_cvp(
            mode=mode,
            elapsed_seconds=control.elapsed_seconds,
            work_units=control.work_units,
        )
        try:
            control.checkpoint(force=True, phase="primal_candidate_rejected")
        except SolverContractError:
            return SolveResult.error(
                elapsed_seconds=control.elapsed_seconds,
                work_units=control.work_units,
                peak_rss_bytes=control.observe_peak(),
                checkpoint_count=control.checkpoint_count,
                detail={"code": "checkpoint_failure"},
            )
        return SolveResult.censored(
            elapsed_seconds=result.elapsed_seconds,
            work_units=result.work_units,
            peak_rss_bytes=control.observe_peak(),
            checkpoint_count=control.checkpoint_count,
            detail=result.detail,
        )

    @staticmethod
    def _censored_budget(
        control: SolverRunControl,
        *,
        reason: str,
        memory_cap: int,
        work_unit_cap: int,
        phase: str,
    ) -> SolveResult:
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
        parameters: dict[str, object] = {}
        if reason == "memory_cap":
            parameters = {
                "cap": memory_cap,
                "cap_unit": "bytes",
                "memory_cap_bytes": memory_cap,
            }
        elif reason == "work_unit_cap":
            parameters = {
                "cap": work_unit_cap,
                "cap_unit": "work_units",
                "work_unit_cap": work_unit_cap,
            }
        detail: dict[str, object] = {"reason": reason}
        if parameters:
            detail["public_parameters"] = parameters
        return SolveResult.censored(
            elapsed_seconds=control.elapsed_seconds,
            work_units=control.work_units,
            peak_rss_bytes=control.observe_peak(),
            checkpoint_count=control.checkpoint_count,
            detail=detail,
        )


__all__ = (
    "ConstructionA",
    "IndependentCVPCheck",
    "PrimalBDD",
    "applicability",
    "build_construction_a",
    "candidate_from_codeword",
    "classify_unsuccessful_cvp",
    "map_secret_representatives",
    "single_thread_policy_satisfied",
    "verify_independent_exact_cvp",
)
