"""Exact sparse-matrix recovery methods over the public instance facade.

The public helpers in this module are deliberately recovery-free: they expose
small, deterministic pieces used to verify completeness, rank, branching, and
certificate boundaries without crossing the public validation boundary.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import random
import sys
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, fields, is_dataclass
from pathlib import Path
from types import MappingProxyType

from .api import (
    CheckpointStore,
    ExactProblem,
    ValidatedExactSolver,
    SolveRequest,
    SolveResult,
    SolveStatus,
    SolverContractError,
)


_SPARSE_MATRIX_KINDS = frozenset({"sparse_uniform", "sparse_small_alphabet"})
_EVENT_CHAIN_SEED = hashlib.sha256(
    b"FCS-LWE-TASK5-EXHAUSTION-EVENT-CHAIN-v2"
).hexdigest()


@dataclass(frozen=True, slots=True)
class RepeatedRowGroup:
    support: tuple[int, ...]
    coefficients: tuple[int, ...]
    row_indices: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class LocalAssignmentOutcome:
    assignments: tuple[Mapping[int, int], ...]
    tested: int
    expected: int
    complete: bool
    reason: str = "complete"


@dataclass(frozen=True, slots=True)
class ExactSearchOutcome:
    secret: tuple[int, ...] | None
    complete: bool
    work_units: int
    reason: str
    traversal_ranges: tuple[tuple[int, int], ...] = ()
    candidate_count: int = 0
    domain_digest: str = ""
    event_chain: str = ""
    checkpoint_count: int = 0


@dataclass(frozen=True, slots=True)
class DomainAxis:
    name: str
    domain_size: int
    ranges: tuple[tuple[int, int], ...]
    values: tuple[int, ...] = ()
    domain_digest: str = ""


@dataclass(frozen=True, slots=True)
class CompleteDomainCertificate:
    axes: tuple[DomainAxis, ...]
    censored: bool
    traversal_ranges: tuple[tuple[int, int], ...] = ()
    candidate_count: int = 0
    domain_digest: str = ""
    event_chain: str = ""


@dataclass(frozen=True, slots=True)
class LeafDecision:
    kind: str
    values: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class PeelState:
    kind: str
    assignments: tuple[tuple[int, int], ...]
    unresolved: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DenseMinor:
    coordinates: tuple[int, ...]
    row_indices: tuple[int, ...]


class TraversalCutoff(RuntimeError):
    """Internal signal for a time or memory cutoff, never a solver ERROR."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _estimated_size(
    value: object,
    *,
    cap: int | None = None,
    deadline: float | None = None,
) -> int:
    """Iteratively account solver-owned state and stop once a cap is crossed."""

    if cap is not None and cap < 0:
        raise ValueError("size cap must be non-negative")
    seen: set[int] = set()
    stack: list[object] = [value]
    size = 0
    while stack:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        current = stack.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        size += sys.getsizeof(current)
        if cap is not None and size > cap:
            return cap + 1
        if isinstance(current, Mapping):
            for key, item in current.items():
                if deadline is not None and time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                stack.append(key)
                stack.append(item)
        elif isinstance(current, (tuple, list, set, frozenset)):
            stack.extend(current)
        elif is_dataclass(current) and not isinstance(current, type):
            for field in fields(current):
                if deadline is not None and time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                stack.append(getattr(current, field.name))
    return size


def estimate_solver_state_bytes(value: object, *, cap: int | None = None) -> int:
    """Public static-test surface for the cap-aware iterative estimator."""

    return _estimated_size(value, cap=cap)


def _cutoff_reason(
    *, deadline: float | None, memory_used: int, memory_cap_bytes: int | None
) -> str | None:
    if deadline is not None and time.monotonic() >= deadline:
        return "timeout"
    if memory_cap_bytes is not None and memory_used > memory_cap_bytes:
        return "memory_cap"
    return None


def _materialize_rows_bounded(
    instance: ExactProblem, *, deadline: float, memory_cap_bytes: int
) -> tuple[tuple[int, ...], ...]:
    rows: list[tuple[int, ...]] = []
    for public_row in instance.iter_rows():
        if time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        row = tuple(public_row)
        memory_used = _estimated_size(
            (rows, row),
            cap=memory_cap_bytes,
            deadline=deadline,
        )
        reason = _cutoff_reason(
            deadline=deadline,
            memory_used=memory_used,
            memory_cap_bytes=memory_cap_bytes,
        )
        if reason is not None:
            raise TraversalCutoff(reason)
        rows.append(row)
    return tuple(rows)


def _centered(value: int, q: int) -> int:
    residue = value % q
    return residue - q if residue > q // 2 else residue


def _canonical_json_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_domains(
    domains: Sequence[Sequence[int]],
    *,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> tuple[tuple[int, ...], ...]:
    frozen: list[tuple[int, ...]] = []
    retained_memory = _estimated_size(
        domains,
        cap=memory_cap_bytes,
        deadline=deadline,
    )
    if memory_cap_bytes is not None and retained_memory > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    permanent_memory = retained_memory + sys.getsizeof(frozen)
    for domain in domains:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        values: list[int] = []
        observed: set[int] = set()
        working_memory = (
            permanent_memory
            + sys.getsizeof(values)
            + sys.getsizeof(observed)
        )
        for value in domain:
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            if type(value) is not int or value in observed:
                raise ValueError(
                    "canonical domains must contain unique integer values"
                )
            old_values_size = sys.getsizeof(values)
            old_observed_size = sys.getsizeof(observed)
            values.append(value)
            observed.add(value)
            working_memory += (
                sys.getsizeof(values)
                - old_values_size
                + sys.getsizeof(observed)
                - old_observed_size
            )
            if memory_cap_bytes is not None and working_memory > memory_cap_bytes:
                raise TraversalCutoff("memory_cap")
        if not values:
            raise ValueError("canonical domains must contain unique integer values")
        frozen_domain = tuple(values)
        old_frozen_size = sys.getsizeof(frozen)
        frozen.append(frozen_domain)
        permanent_memory += (
            sys.getsizeof(frozen)
            - old_frozen_size
            + sys.getsizeof(frozen_domain)
        )
        if (
            memory_cap_bytes is not None
            and max(
                permanent_memory,
                working_memory + sys.getsizeof(frozen_domain),
            )
            > memory_cap_bytes
        ):
            raise TraversalCutoff("memory_cap")
    result = tuple(frozen)
    if memory_cap_bytes is not None and _estimated_size(
        result,
        cap=memory_cap_bytes,
        deadline=deadline,
    ) > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    return result


def _domain_digest(
    domains: Sequence[Sequence[int]],
    *,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> str:
    frozen = _canonical_domains(
        domains,
        deadline=deadline,
        memory_cap_bytes=memory_cap_bytes,
    )
    return _frozen_domain_digest(frozen, deadline=deadline)


def _frozen_domain_digest(
    frozen_domains: Sequence[Sequence[int]],
    *,
    deadline: float | None = None,
) -> str:
    digest = hashlib.sha256()
    digest.update(b'{"domains":[')
    for domain_index, domain in enumerate(frozen_domains):
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if domain_index:
            digest.update(b",")
        digest.update(b"[")
        for value_index, value in enumerate(domain):
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            if value_index:
                digest.update(b",")
            digest.update(str(value).encode("ascii"))
        digest.update(b"]")
    digest.update(b"]}")
    return digest.hexdigest()


def _axis_digest(
    domain: Sequence[int], *, deadline: float | None = None
) -> str:
    digest = hashlib.sha256()
    digest.update(b'{"values":[')
    for index, value in enumerate(domain):
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if index:
            digest.update(b",")
        digest.update(str(value).encode("ascii"))
    digest.update(b"]}")
    return digest.hexdigest()


def _advance_event_chain(
    chain: str,
    *,
    ordinal: int,
    candidate: tuple[int, ...],
    outcome: str,
    retained_memory_bytes: int = 0,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> str:
    """Advance one fixed-schema canonical event without opaque generators."""

    if (
        type(chain) is not str
        or len(chain) != 64
        or any(character not in "0123456789abcdef" for character in chain)
        or type(ordinal) is not int
        or ordinal < 0
        or type(candidate) is not tuple
        or any(type(value) is not int for value in candidate)
        or outcome not in {"accepted", "not_returned"}
    ):
        raise ValueError("event-chain input is malformed")

    persistent_reserve_bytes = 0

    def require_capacity(
        *transient: object, reserve_bytes: int = 0
    ) -> None:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if memory_cap_bytes is None:
            return
        used = _estimated_size(
            (chain, candidate, transient),
            cap=memory_cap_bytes,
            deadline=deadline,
        )
        reason = _cutoff_reason(
            deadline=deadline,
            memory_used=(
                retained_memory_bytes
                + used
                + persistent_reserve_bytes
                + reserve_bytes
            ),
            memory_cap_bytes=memory_cap_bytes,
        )
        if reason is not None:
            raise TraversalCutoff(reason)

    require_capacity(reserve_bytes=512)
    digest = hashlib.sha256()
    persistent_reserve_bytes = 512
    require_capacity(digest)

    def update_integer(value: int) -> None:
        decimal_digits = max(1, (value.bit_length() * 30_103) // 100_000 + 1)
        require_capacity(
            digest,
            value,
            reserve_bytes=decimal_digits * 2 + 128,
        )
        text = str(value)
        require_capacity(digest, value, text, reserve_bytes=len(text) + 64)
        encoded = text.encode("ascii")
        require_capacity(digest, value, text, encoded)
        digest.update(encoded)

    digest.update(b'{"candidate":[')
    for index, value in enumerate(candidate):
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if index:
            digest.update(b",")
        update_integer(value)
    digest.update(b'],"ordinal":')
    update_integer(ordinal)
    digest.update(b',"outcome":"')
    require_capacity(
        digest,
        outcome,
        reserve_bytes=len(outcome) + 64,
    )
    outcome_bytes = outcome.encode("ascii")
    require_capacity(digest, outcome, outcome_bytes)
    digest.update(outcome_bytes)
    digest.update(b'","previous":"')
    require_capacity(
        digest,
        reserve_bytes=len(chain) + 64,
    )
    chain_bytes = chain.encode("ascii")
    require_capacity(digest, chain_bytes)
    digest.update(chain_bytes)
    digest.update(b'"}')
    require_capacity(
        digest,
        outcome_bytes,
        chain_bytes,
        reserve_bytes=sys.getsizeof(chain),
    )
    result = digest.hexdigest()
    require_capacity(
        digest,
        outcome_bytes,
        chain_bytes,
        result,
    )
    if deadline is not None and time.monotonic() >= deadline:
        raise TraversalCutoff("timeout")
    return result


def residuals_within_budget(
    residuals: Sequence[int],
    *,
    max_abs: int,
    max_l1: int | None,
    max_l2_squared: int | None,
    max_nonzero: int | None,
) -> bool:
    """Check every public residual predicate, with equality accepted."""

    if max_abs < 0:
        return False
    absolute = tuple(abs(value) for value in residuals)
    if any(value > max_abs for value in absolute):
        return False
    if max_l1 is not None and sum(absolute) > max_l1:
        return False
    if max_l2_squared is not None and sum(value * value for value in residuals) > max_l2_squared:
        return False
    if max_nonzero is not None and sum(value != 0 for value in residuals) > max_nonzero:
        return False
    return True


def _matrix_shape(
    rows: Sequence[Sequence[int]], *, deadline: float | None = None
) -> int:
    if not rows:
        return 0
    n = len(rows[0])
    for row in rows:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if len(row) != n:
            raise ValueError("matrix rows have inconsistent lengths")
    return n


def group_repeated_rows(
    rows: Sequence[Sequence[int]],
    *,
    q: int,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> tuple[RepeatedRowGroup, ...]:
    """Group only exactly repeated public support/coefficient patterns."""

    if type(q) is not int or q <= 1:
        raise ValueError("q must be an integer greater than one")
    retained_memory = _estimated_size(
        rows,
        cap=memory_cap_bytes,
        deadline=deadline,
    )
    if memory_cap_bytes is not None and retained_memory > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    _matrix_shape(rows, deadline=deadline)
    grouped: dict[tuple[tuple[int, ...], tuple[int, ...]], list[int]] = {}
    for row_index, row in enumerate(rows):
        reason = _cutoff_reason(
            deadline=deadline,
            memory_used=retained_memory + _estimated_size(grouped),
            memory_cap_bytes=memory_cap_bytes,
        )
        if reason is not None:
            raise TraversalCutoff(reason)
        support_list: list[int] = []
        coefficient_list: list[int] = []
        for index, value in enumerate(row):
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            if value % q:
                support_list.append(index)
                coefficient_list.append(value % q)
                if memory_cap_bytes is not None and _estimated_size(
                    (rows, grouped, support_list, coefficient_list),
                    cap=memory_cap_bytes,
                    deadline=deadline,
                ) > memory_cap_bytes:
                    raise TraversalCutoff("memory_cap")
        support = tuple(support_list)
        coefficients = tuple(coefficient_list)
        grouped.setdefault((support, coefficients), []).append(row_index)
    result: list[RepeatedRowGroup] = []
    for (support, coefficients), indices in sorted(grouped.items()):
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if len(indices) < 2:
            continue
        candidate = RepeatedRowGroup(support, coefficients, tuple(indices))
        if memory_cap_bytes is not None and _estimated_size(
            (rows, grouped, result, candidate),
            cap=memory_cap_bytes,
            deadline=deadline,
        ) > memory_cap_bytes:
            raise TraversalCutoff("memory_cap")
        result.append(candidate)
    return tuple(result)


def enumerate_local_assignments(
    group: RepeatedRowGroup,
    *,
    rows: Sequence[Sequence[int]],
    rhs: Sequence[int],
    domains: Sequence[Sequence[int]],
    q: int,
    max_abs: int,
    max_l1: int | None,
    max_l2_squared: int | None,
    max_nonzero: int | None,
    assignment_budget: int,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> LocalAssignmentOutcome:
    """Retain all compatible local assignments, including ambiguity."""

    if assignment_budget < 0 or len(rows) != len(rhs):
        raise ValueError("invalid local assignment input")
    n = _matrix_shape(rows, deadline=deadline)
    if len(domains) != n:
        raise ValueError("coordinate domains do not match the matrix")
    for domain in domains:
        if deadline is not None and time.monotonic() >= deadline:
            return LocalAssignmentOutcome((), 0, 0, False, "timeout")
        if not domain:
            raise ValueError("coordinate domains do not match the matrix")
    expected = math.prod(len(domains[index]) for index in group.support)
    kept: list[Mapping[int, int]] = []
    tested = 0
    try:
        retained_memory = _estimated_size(
            (group, rows, rhs, domains),
            cap=memory_cap_bytes,
            deadline=deadline,
        )
    except TraversalCutoff as exc:
        return LocalAssignmentOutcome((), 0, expected, False, exc.reason)
    if memory_cap_bytes is not None and retained_memory > memory_cap_bytes:
        return LocalAssignmentOutcome((), 0, expected, False, "memory_cap")
    memory_used = retained_memory + _estimated_size(kept)
    for values in itertools.product(*(domains[index] for index in group.support)):
        reason = _cutoff_reason(
            deadline=deadline,
            memory_used=memory_used,
            memory_cap_bytes=memory_cap_bytes,
        )
        if reason is not None:
            return LocalAssignmentOutcome(
                tuple(kept), tested, expected, False, reason
            )
        if tested >= assignment_budget:
            return LocalAssignmentOutcome(
                tuple(kept), tested, expected, False, "assignment_cap"
            )
        tested += 1
        assignment = dict(zip(group.support, values, strict=True))
        residual_list: list[int] = []
        for row_index in group.row_indices:
            reason = _cutoff_reason(
                deadline=deadline,
                    memory_used=(
                        memory_used
                        + _estimated_size(
                            residual_list,
                            cap=memory_cap_bytes,
                        )
                    ),
                memory_cap_bytes=memory_cap_bytes,
            )
            if reason is not None:
                return LocalAssignmentOutcome(
                    tuple(kept), tested, expected, False, reason
                )
            residual_list.append(
                _centered(
                    rhs[row_index]
                    - sum(
                        rows[row_index][index] * assignment[index]
                        for index in group.support
                    ),
                    q,
                )
            )
        residuals = tuple(residual_list)
        if residuals_within_budget(
            residuals,
            max_abs=max_abs,
            max_l1=max_l1,
            max_l2_squared=max_l2_squared,
            max_nonzero=max_nonzero,
        ):
            frozen = MappingProxyType(assignment)
            candidate_size = _estimated_size(
                frozen,
                cap=memory_cap_bytes,
            )
            if (
                memory_cap_bytes is not None
                and memory_used + candidate_size > memory_cap_bytes
            ):
                return LocalAssignmentOutcome(
                    tuple(kept), tested, expected, False, "memory_cap"
                )
            kept.append(frozen)
            memory_used += candidate_size
    return LocalAssignmentOutcome(
        tuple(kept), tested, expected, tested == expected, "complete"
    )


def _assignment_search_digest(
    *,
    n: int,
    assignment_groups: Sequence[Sequence[Mapping[int, int]]],
    uncovered_items: tuple[tuple[int, Sequence[int]], ...],
    excluded: tuple[int, ...] | None,
    deadline: float | None,
    memory_cap_bytes: int | None,
) -> str:
    digest = hashlib.sha256(b"FCS-LWE-TASK5-ASSIGNMENT-PRODUCT-v2")
    digest.update(str(n).encode("ascii"))
    digest.update(
        json.dumps(
            {"excluded": None if excluded is None else list(excluded)},
            separators=(",", ":"),
        ).encode("ascii")
    )
    for group_index, group in enumerate(assignment_groups):
        digest.update(f"g:{group_index}:{len(group)};".encode("ascii"))
        for candidate_index, candidate in enumerate(group):
            reason = _cutoff_reason(
                deadline=deadline,
                memory_used=_estimated_size(
                    candidate,
                    cap=memory_cap_bytes,
                    deadline=deadline,
                ),
                memory_cap_bytes=memory_cap_bytes,
            )
            if reason is not None:
                raise TraversalCutoff(reason)
            encoded = json.dumps(
                {
                    "candidate_index": candidate_index,
                    "items": sorted(candidate.items()),
                },
                separators=(",", ":"),
            ).encode("ascii")
            digest.update(encoded)
    for coordinate, domain in uncovered_items:
        domain_values: list[int] = []
        for value in domain:
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            domain_values.append(value)
        digest.update(
            json.dumps(
                {"coordinate": coordinate, "domain": domain_values},
                separators=(",", ":"),
            ).encode("ascii")
        )
    return digest.hexdigest()


def search_assignment_product(
    *,
    n: int,
    assignment_groups: Sequence[Sequence[Mapping[int, int]]],
    uncovered_domains: Mapping[int, Sequence[int]],
    validator: Callable[[tuple[int, ...]], bool],
    excluded: tuple[int, ...] | None,
    work_unit_cap: int,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
    checkpoint_store: CheckpointStore | None = None,
    resume_checkpoint: Path | None = None,
    checkpoint_every_work_units: int = 10_000,
) -> ExactSearchOutcome:
    """Backtrack deterministic products with bound, resumable branch accounting."""

    if (
        n < 0
        or work_unit_cap < 0
        or type(checkpoint_every_work_units) is not int
        or checkpoint_every_work_units <= 0
    ):
        raise ValueError("invalid search bound")
    if resume_checkpoint is not None and checkpoint_store is None:
        raise ValueError("resume checkpoint requires a checkpoint store")
    uncovered_items = tuple(sorted(uncovered_domains.items()))
    for index, domain in uncovered_items:
        if deadline is not None and time.monotonic() >= deadline:
            return ExactSearchOutcome(None, False, 0, "timeout")
        if index < 0 or index >= n or not domain:
            raise ValueError("invalid uncovered coordinate domain")
    try:
        base_memory = _estimated_size(
            (assignment_groups, uncovered_domains),
            cap=memory_cap_bytes,
            deadline=deadline,
        )
        if memory_cap_bytes is not None and base_memory > memory_cap_bytes:
            return ExactSearchOutcome(None, False, 0, "memory_cap")
        for group in assignment_groups:
            if deadline is not None and time.monotonic() >= deadline:
                return ExactSearchOutcome(None, False, 0, "timeout")
            if not group:
                return ExactSearchOutcome(None, True, 0, "complete", ())
        choice_pools: tuple[Sequence[object], ...] = tuple(
            assignment_groups
        ) + tuple(domain for _coordinate, domain in uncovered_items)
        combination_count = math.prod(len(pool) for pool in choice_pools)
        search_digest = ""
        if checkpoint_store is not None:
            search_digest = _assignment_search_digest(
                n=n,
                assignment_groups=assignment_groups,
                uncovered_items=uncovered_items,
                excluded=excluded,
                deadline=deadline,
                memory_cap_bytes=memory_cap_bytes,
            )
    except TraversalCutoff as exc:
        return ExactSearchOutcome(None, False, 0, exc.reason)

    next_ordinal = 0
    work_units = 0
    checkpoint_count = 0
    last_checkpoint_work = 0
    checkpoint_path = resume_checkpoint
    if resume_checkpoint is not None:
        assert checkpoint_store is not None
        loaded = checkpoint_store.load(resume_checkpoint)
        if loaded is None or frozenset(loaded) != {
            "search_revision",
            "search_digest",
            "combination_count",
            "next_ordinal",
            "covered_ranges",
            "work_units",
        }:
            raise SolverContractError("checkpoint search state is malformed")
        loaded_combination_count = loaded["combination_count"]
        if type(loaded_combination_count) is not int:
            raise SolverContractError("checkpoint search state is malformed")
        if (
            loaded["search_revision"] != "assignment-product-v3"
            or loaded["search_digest"] != search_digest
            or loaded_combination_count != combination_count
        ):
            raise SolverContractError("checkpoint search binding does not match")
        next_value = loaded["next_ordinal"]
        work_value = loaded["work_units"]
        ranges_value = loaded["covered_ranges"]
        if (
            type(next_value) is not int
            or next_value < 0
            or next_value > combination_count
            or type(work_value) is not int
            or work_value < 0
        ):
            raise SolverContractError("checkpoint search state is malformed")
        expected_ranges = () if next_value == 0 else ((0, next_value),)
        if type(ranges_value) is not tuple or any(
            type(interval) is not tuple
            or len(interval) != 2
            or type(interval[0]) is not int
            or type(interval[1]) is not int
            for interval in ranges_value
        ):
            raise SolverContractError("checkpoint covered ranges are malformed")
        if ranges_value != expected_ranges:
            raise SolverContractError("checkpoint covered ranges are not monotone")
        if work_value != next_value:
            raise SolverContractError(
                "checkpoint work units do not match ordinal coverage"
            )
        next_ordinal = next_value
        work_units = work_value
        last_checkpoint_work = work_units

    def ranges_for(stop: int) -> tuple[tuple[int, int], ...]:
        return () if stop == 0 else ((0, stop),)

    def save_checkpoint(*, force: bool = False) -> None:
        nonlocal checkpoint_count, last_checkpoint_work, checkpoint_path
        if checkpoint_store is None:
            return
        if (
            not force
            and work_units - last_checkpoint_work
            < checkpoint_every_work_units
        ):
            return
        state = {
            "search_revision": "assignment-product-v3",
            "search_digest": search_digest,
            "combination_count": combination_count,
            "next_ordinal": next_ordinal,
            "covered_ranges": ranges_for(next_ordinal),
            "work_units": work_units,
        }
        checkpoint_path = checkpoint_store.save(
            state,
            work_units=work_units,
            path=checkpoint_path,
        )
        checkpoint_count += 1
        last_checkpoint_work = work_units

    assignment: dict[int, int] = {}

    def cutoff(candidate: object | None = None) -> str | None:
        try:
            candidate_memory = 0
            if candidate is not None:
                candidate_memory = _estimated_size(
                    candidate,
                    cap=memory_cap_bytes,
                    deadline=deadline,
                )
            assignment_memory = _estimated_size(
                assignment,
                cap=memory_cap_bytes,
                deadline=deadline,
            )
        except TraversalCutoff as exc:
            return exc.reason
        return _cutoff_reason(
            deadline=deadline,
            memory_used=(
                base_memory
                + assignment_memory
                + candidate_memory
            ),
            memory_cap_bytes=memory_cap_bytes,
        )

    def choices_at_ordinal(ordinal: int) -> tuple[object, ...]:
        if ordinal < 0 or ordinal >= combination_count:
            raise ValueError("assignment product ordinal is out of range")
        choices: list[object] = [None] * len(choice_pools)
        residual = ordinal
        for index in range(len(choice_pools) - 1, -1, -1):
            if (reason := cutoff(choices)) is not None:
                raise TraversalCutoff(reason)
            pool = choice_pools[index]
            residual, digit = divmod(residual, len(pool))
            choices[index] = pool[digit]
        if residual:
            raise ValueError("assignment product ordinal invariant failed")
        return tuple(choices)

    for ordinal in range(next_ordinal, combination_count):
        if work_units >= work_unit_cap:
            save_checkpoint(force=True)
            if deadline is not None and time.monotonic() >= deadline:
                return ExactSearchOutcome(
                    None,
                    False,
                    work_units,
                    "timeout",
                    ranges_for(next_ordinal),
                    checkpoint_count=checkpoint_count,
                )
            return ExactSearchOutcome(
                None,
                False,
                work_units,
                "work_unit_cap",
                ranges_for(next_ordinal),
                checkpoint_count=checkpoint_count,
            )
        try:
            choices = choices_at_ordinal(ordinal)
        except TraversalCutoff as exc:
            save_checkpoint(force=True)
            return ExactSearchOutcome(
                None,
                False,
                work_units,
                exc.reason,
                ranges_for(next_ordinal),
                checkpoint_count=checkpoint_count,
            )
        assignment.clear()
        compatible = True
        accepted = False
        complete_candidate: tuple[int, ...] | None = None
        for candidate in choices[: len(assignment_groups)]:
            assert isinstance(candidate, Mapping)
            for coordinate, value in candidate.items():
                if (reason := cutoff(candidate)) is not None:
                    save_checkpoint(force=True)
                    return ExactSearchOutcome(
                        None,
                        False,
                        work_units,
                        reason,
                        ranges_for(next_ordinal),
                        checkpoint_count=checkpoint_count,
                    )
                if (
                    type(coordinate) is not int
                    or coordinate < 0
                    or coordinate >= n
                    or type(value) is not int
                ):
                    raise ValueError("malformed local assignment")
                if coordinate in assignment and assignment[coordinate] != value:
                    compatible = False
                    break
                assignment[coordinate] = value
            if not compatible:
                break
        if compatible:
            uncovered_choices = choices[len(assignment_groups) :]
            for (coordinate, _domain), value in zip(
                uncovered_items, uncovered_choices, strict=True
            ):
                if coordinate in assignment:
                    raise ValueError("uncovered coordinate was already assigned")
                if (reason := cutoff(value)) is not None:
                    save_checkpoint(force=True)
                    return ExactSearchOutcome(
                        None,
                        False,
                        work_units,
                        reason,
                        ranges_for(next_ordinal),
                        checkpoint_count=checkpoint_count,
                    )
                assignment[coordinate] = value
            if len(assignment) != n:
                raise ValueError("search domain does not cover every coordinate")
            if (reason := cutoff()) is not None:
                save_checkpoint(force=True)
                return ExactSearchOutcome(
                    None,
                    False,
                    work_units,
                    reason,
                    ranges_for(next_ordinal),
                    checkpoint_count=checkpoint_count,
                )
            complete_candidate = tuple(assignment[index] for index in range(n))
            if complete_candidate != excluded:
                accepted = validator(complete_candidate)
                if deadline is not None and time.monotonic() >= deadline:
                    save_checkpoint(force=True)
                    return ExactSearchOutcome(
                        None,
                        False,
                        work_units,
                        "timeout",
                        ranges_for(next_ordinal),
                        checkpoint_count=checkpoint_count,
                    )
                if accepted is not True and accepted is not False:
                    raise ValueError("validator must return an exact boolean")
        if compatible and accepted and complete_candidate is not None:
            if deadline is not None and time.monotonic() >= deadline:
                save_checkpoint(force=True)
                return ExactSearchOutcome(
                    None,
                    False,
                    work_units,
                    "timeout",
                    ranges_for(next_ordinal),
                    checkpoint_count=checkpoint_count,
                )
            # Keep the durable checkpoint at the last fully disposed ordinal.
            # A crash after this save but before the result reaches the caller
            # must replay and revalidate the accepted candidate on resume.
            save_checkpoint(force=True)
            if deadline is not None and time.monotonic() >= deadline:
                return ExactSearchOutcome(
                    None,
                    False,
                    work_units,
                    "timeout",
                    ranges_for(next_ordinal),
                    checkpoint_count=checkpoint_count,
                )
            completed_work = ordinal + 1
            return ExactSearchOutcome(
                complete_candidate,
                False,
                completed_work,
                "success",
                ranges_for(completed_work),
                checkpoint_count=checkpoint_count,
            )
        next_ordinal = ordinal + 1
        work_units = next_ordinal
        save_checkpoint()

    if next_ordinal != combination_count:
        raise ValueError("assignment product ordinal invariant failed")
    if deadline is not None and time.monotonic() >= deadline:
        save_checkpoint(force=True)
        return ExactSearchOutcome(
            None,
            False,
            work_units,
            "timeout",
            ranges_for(next_ordinal),
            checkpoint_count=checkpoint_count,
        )
    save_checkpoint(force=True)
    if deadline is not None and time.monotonic() >= deadline:
        return ExactSearchOutcome(
            None,
            False,
            work_units,
            "timeout",
            ranges_for(next_ordinal),
            checkpoint_count=checkpoint_count,
        )
    return ExactSearchOutcome(
        None,
        True,
        work_units,
        "complete",
        ranges_for(combination_count),
        checkpoint_count=checkpoint_count,
    )


def certifying_cartesian_search(
    *,
    domains: Sequence[Sequence[int]],
    validator: Callable[[tuple[int, ...]], bool],
    excluded: tuple[int, ...] | None,
    work_unit_cap: int,
    deadline: float | None,
    memory_cap_bytes: int,
) -> ExactSearchOutcome:
    """Traverse public domains in mixed-radix order and record exact coverage."""

    if work_unit_cap < 0 or memory_cap_bytes <= 0:
        raise ValueError("invalid certifying Cartesian domain")
    try:
        frozen_domains = _canonical_domains(
            domains,
            deadline=deadline,
            memory_cap_bytes=memory_cap_bytes,
        )
        domain_size = math.prod(len(domain) for domain in frozen_domains)
        canonical_digest = _frozen_domain_digest(
            frozen_domains,
            deadline=deadline,
        )
        base_memory = _estimated_size(
            frozen_domains,
            cap=memory_cap_bytes,
            deadline=deadline,
        )
    except TraversalCutoff as exc:
        return ExactSearchOutcome(None, False, 0, exc.reason)
    visited = 0
    event_chain = _EVENT_CHAIN_SEED
    for ordinal, candidate_values in enumerate(itertools.product(*frozen_domains)):
        candidate = tuple(candidate_values)
        try:
            current_memory = base_memory + _estimated_size(
                (event_chain, candidate),
                cap=memory_cap_bytes,
                deadline=deadline,
            )
        except TraversalCutoff as exc:
            ranges = ((0, visited),) if visited else ()
            return ExactSearchOutcome(
                None,
                False,
                visited,
                exc.reason,
                ranges,
                visited,
                canonical_digest,
                event_chain,
            )
        reason = _cutoff_reason(
            deadline=deadline,
            memory_used=current_memory,
            memory_cap_bytes=memory_cap_bytes,
        )
        if reason is not None:
            ranges = ((0, visited),) if visited else ()
            return ExactSearchOutcome(
                None,
                False,
                visited,
                reason,
                ranges,
                visited,
                canonical_digest,
                event_chain,
            )
        if visited >= work_unit_cap:
            ranges = ((0, visited),) if visited else ()
            return ExactSearchOutcome(
                None,
                False,
                visited,
                "work_unit_cap",
                ranges,
                visited,
                canonical_digest,
                event_chain,
            )
        verdict = validator(candidate)
        if deadline is not None and time.monotonic() >= deadline:
            ranges = ((0, visited),) if visited else ()
            return ExactSearchOutcome(
                None,
                False,
                visited + 1,
                "timeout",
                ranges,
                visited,
                canonical_digest,
                event_chain,
            )
        if verdict is not True and verdict is not False:
            raise ValueError("validator must return an exact boolean")
        if candidate == excluded and verdict is True:
            ranges = ((0, visited),) if visited else ()
            return ExactSearchOutcome(
                None,
                False,
                visited + 1,
                "excluded_witness_requires_private_proof",
                ranges,
                visited,
                canonical_digest,
                event_chain,
            )
        accepted = candidate != excluded and verdict is True
        event_outcome = "accepted" if accepted else "not_returned"
        try:
            event_chain = _advance_event_chain(
                event_chain,
                ordinal=ordinal,
                candidate=candidate,
                outcome=event_outcome,
                retained_memory_bytes=base_memory,
                deadline=deadline,
                memory_cap_bytes=memory_cap_bytes,
            )
        except TraversalCutoff as exc:
            ranges = ((0, visited),) if visited else ()
            return ExactSearchOutcome(
                None,
                False,
                visited + 1,
                exc.reason,
                ranges,
                visited,
                canonical_digest,
                event_chain,
            )
        visited += 1
        if accepted:
            if deadline is not None and time.monotonic() >= deadline:
                return ExactSearchOutcome(
                    None,
                    False,
                    visited,
                    "timeout",
                    ((0, visited),),
                    visited,
                    canonical_digest,
                    event_chain,
                )
            return ExactSearchOutcome(
                candidate,
                False,
                visited,
                "success",
                ((0, visited),),
                visited,
                canonical_digest,
                event_chain,
            )
    if visited != domain_size:
        raise ValueError("Cartesian traversal ordinal invariant failed")
    if deadline is not None and time.monotonic() >= deadline:
        return ExactSearchOutcome(
            None,
            False,
            visited,
            "timeout",
            ((0, visited),) if visited else (),
            visited,
            canonical_digest,
            event_chain,
        )
    return ExactSearchOutcome(
        None,
        True,
        visited,
        "complete",
        ((0, domain_size),),
        visited,
        canonical_digest,
        event_chain,
    )


def build_complete_domain_certificate(
    domains: Sequence[Sequence[int]],
    traversal: ExactSearchOutcome,
    *,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> CompleteDomainCertificate:
    """Bind a completed observed traversal to its canonical public domains."""

    frozen_domains = _canonical_domains(
        domains,
        deadline=deadline,
        memory_cap_bytes=memory_cap_bytes,
    )
    retained_memory = _estimated_size(
        (domains, traversal, frozen_domains),
        cap=memory_cap_bytes,
        deadline=deadline,
    )
    if memory_cap_bytes is not None and retained_memory > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    expected_count = 1
    for domain in frozen_domains:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        expected_count *= len(domain)
    expected_digest = _frozen_domain_digest(
        frozen_domains,
        deadline=deadline,
    )
    if (
        type(traversal.complete) is not bool
        or traversal.complete is not True
        or traversal.secret is not None
        or traversal.reason != "complete"
        or type(traversal.work_units) is not int
        or traversal.work_units != expected_count
        or type(traversal.candidate_count) is not int
        or traversal.candidate_count != expected_count
        or traversal.domain_digest != expected_digest
        or type(traversal.traversal_ranges) is not tuple
        or any(
            type(interval) is not tuple
            or len(interval) != 2
            or type(interval[0]) is not int
            or type(interval[1]) is not int
            for interval in traversal.traversal_ranges
        )
        or traversal.traversal_ranges != ((0, expected_count),)
        or type(traversal.event_chain) is not str
        or not traversal.event_chain
    ):
        raise ValueError("traversal is not a complete bound domain observation")
    axes_list: list[DomainAxis] = []
    for index, domain in enumerate(frozen_domains):
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        axis = DomainAxis(
            name=f"coordinate-{index}",
            domain_size=len(domain),
            ranges=((0, len(domain)),),
            values=domain,
            domain_digest=_axis_digest(domain, deadline=deadline),
        )
        axes_list.append(axis)
        retained_memory = _estimated_size(
            (domains, traversal, frozen_domains, axes_list),
            cap=memory_cap_bytes,
            deadline=deadline,
        )
        if memory_cap_bytes is not None and retained_memory > memory_cap_bytes:
            raise TraversalCutoff("memory_cap")
    certificate = CompleteDomainCertificate(
        axes=tuple(axes_list),
        censored=False,
        traversal_ranges=traversal.traversal_ranges,
        candidate_count=traversal.candidate_count,
        domain_digest=traversal.domain_digest,
        event_chain=traversal.event_chain,
    )
    if memory_cap_bytes is not None and _estimated_size(
        (domains, traversal, frozen_domains, axes_list, certificate),
        cap=memory_cap_bytes,
        deadline=deadline,
    ) > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    if deadline is not None and time.monotonic() >= deadline:
        raise TraversalCutoff("timeout")
    return certificate


def verify_complete_domain_certificate(
    certificate: CompleteDomainCertificate,
    *,
    domains: Sequence[Sequence[int]] | None = None,
    validator: Callable[[tuple[int, ...]], bool] | None = None,
    excluded: tuple[int, ...] | None = None,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
    work_unit_cap: int | None = None,
) -> bool:
    """Replay public domains and verify structural coverage plus event chain."""

    del excluded

    if work_unit_cap is not None and (
        type(work_unit_cap) is not int or work_unit_cap < 0
    ):
        return False
    if (
        not isinstance(certificate, CompleteDomainCertificate)
        or type(certificate.censored) is not bool
        or certificate.censored is not False
        or type(certificate.axes) is not tuple
        or type(certificate.traversal_ranges) is not tuple
        or type(certificate.candidate_count) is not int
        or type(certificate.domain_digest) is not str
        or type(certificate.event_chain) is not str
        or domains is None
        or validator is None
    ):
        return False
    try:
        frozen_domains = _canonical_domains(
            domains,
            deadline=deadline,
            memory_cap_bytes=memory_cap_bytes,
        )
    except ValueError:
        return False
    base_memory = _estimated_size(
        (certificate, domains, frozen_domains),
        cap=memory_cap_bytes,
        deadline=deadline,
    )
    if memory_cap_bytes is not None and base_memory > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    if len(certificate.axes) != len(frozen_domains):
        return False
    names: set[str] = set()
    cartesian_size = 1
    for index, (axis, domain) in enumerate(
        zip(certificate.axes, frozen_domains, strict=True)
    ):
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if (
            not isinstance(axis, DomainAxis)
            or axis.name != f"coordinate-{index}"
            or axis.name in names
            or type(axis.domain_size) is not int
            or axis.domain_size != len(domain)
            or type(axis.ranges) is not tuple
            or type(axis.values) is not tuple
            or axis.values != domain
            or type(axis.domain_digest) is not str
            or axis.domain_digest != _axis_digest(domain, deadline=deadline)
        ):
            return False
        names.add(axis.name)
        cartesian_size *= axis.domain_size
        cursor = 0
        for interval in axis.ranges:
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            if (
                type(interval) is not tuple
                or len(interval) != 2
                or type(interval[0]) is not int
                or type(interval[1]) is not int
                or interval[0] != cursor
                or interval[1] <= interval[0]
                or interval[1] > axis.domain_size
            ):
                return False
            cursor = interval[1]
        if cursor != axis.domain_size:
            return False
    if (
        certificate.candidate_count != cartesian_size
        or certificate.domain_digest
        != _frozen_domain_digest(frozen_domains, deadline=deadline)
    ):
        return False
    cursor = 0
    for interval in certificate.traversal_ranges:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if (
            type(interval) is not tuple
            or len(interval) != 2
            or type(interval[0]) is not int
            or type(interval[1]) is not int
            or interval[0] != cursor
            or interval[1] <= interval[0]
            or interval[1] > cartesian_size
        ):
            return False
        cursor = interval[1]
    if cursor != cartesian_size:
        return False

    chain = _EVENT_CHAIN_SEED
    observed = 0
    for ordinal, candidate_values in enumerate(itertools.product(*frozen_domains)):
        if work_unit_cap is not None and observed >= work_unit_cap:
            raise TraversalCutoff("work_unit_cap")
        candidate = tuple(candidate_values)
        current_memory = base_memory + _estimated_size(
            (chain, candidate),
            cap=memory_cap_bytes,
            deadline=deadline,
        )
        reason = _cutoff_reason(
            deadline=deadline,
            memory_used=current_memory,
            memory_cap_bytes=memory_cap_bytes,
        )
        if reason is not None:
            raise TraversalCutoff(reason)
        verdict = validator(candidate)
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if verdict is not True and verdict is not False:
            return False
        if verdict is True:
            return False
        event_outcome = "not_returned"
        chain = _advance_event_chain(
            chain,
            ordinal=ordinal,
            candidate=candidate,
            outcome=event_outcome,
            retained_memory_bytes=base_memory,
            deadline=deadline,
            memory_cap_bytes=memory_cap_bytes,
        )
        observed += 1
    if deadline is not None and time.monotonic() >= deadline:
        raise TraversalCutoff("timeout")
    return (
        observed == certificate.candidate_count
        and chain == certificate.event_chain
    )


def _certificate_digest(
    certificate: CompleteDomainCertificate,
    *,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> str:
    retained_memory = _estimated_size(
        certificate,
        cap=memory_cap_bytes,
        deadline=deadline,
    )
    if memory_cap_bytes is not None and retained_memory > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    axes_payload: list[dict[str, object]] = []
    for axis in certificate.axes:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        ranges_payload: list[list[int]] = []
        for interval in axis.ranges:
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            ranges_payload.append(list(interval))
            if memory_cap_bytes is not None and _estimated_size(
                (certificate, axes_payload, ranges_payload),
                cap=memory_cap_bytes,
                deadline=deadline,
            ) > memory_cap_bytes:
                raise TraversalCutoff("memory_cap")
        values_payload: list[int] = []
        for value in axis.values:
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            values_payload.append(value)
            if memory_cap_bytes is not None and _estimated_size(
                (certificate, axes_payload, ranges_payload, values_payload),
                cap=memory_cap_bytes,
                deadline=deadline,
            ) > memory_cap_bytes:
                raise TraversalCutoff("memory_cap")
        axes_payload.append(
            {
                "domain_size": axis.domain_size,
                "name": axis.name,
                "ranges": ranges_payload,
                "values": values_payload,
                "domain_digest": axis.domain_digest,
            }
        )
        if memory_cap_bytes is not None and _estimated_size(
            (certificate, axes_payload),
            cap=memory_cap_bytes,
            deadline=deadline,
        ) > memory_cap_bytes:
            raise TraversalCutoff("memory_cap")
    traversal_ranges: list[list[int]] = []
    for interval in certificate.traversal_ranges:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        traversal_ranges.append(list(interval))
        if memory_cap_bytes is not None and _estimated_size(
            (certificate, axes_payload, traversal_ranges),
            cap=memory_cap_bytes,
            deadline=deadline,
        ) > memory_cap_bytes:
            raise TraversalCutoff("memory_cap")
    payload = {
        "axes": axes_payload,
        "censored": certificate.censored,
        "candidate_count": certificate.candidate_count,
        "domain_digest": certificate.domain_digest,
        "event_chain": certificate.event_chain,
        "traversal_ranges": traversal_ranges,
    }
    if memory_cap_bytes is not None and _estimated_size(
        (certificate, payload),
        cap=memory_cap_bytes,
        deadline=deadline,
    ) > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    digest = hashlib.sha256()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"))
    for chunk in encoder.iterencode(payload):
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        encoded_chunk = chunk.encode("utf-8")
        if memory_cap_bytes is not None and _estimated_size(
            (certificate, payload, chunk, encoded_chunk),
            cap=memory_cap_bytes,
            deadline=deadline,
        ) > memory_cap_bytes:
            raise TraversalCutoff("memory_cap")
        digest.update(encoded_chunk)
    if deadline is not None and time.monotonic() >= deadline:
        raise TraversalCutoff("timeout")
    return digest.hexdigest()


def classify_no_solution(
    *,
    complete_domain: bool,
    invariant_ok: bool,
    certificate: CompleteDomainCertificate | None = None,
    domains: Sequence[Sequence[int]] | None = None,
    validator: Callable[[tuple[int, ...]], bool] | None = None,
    excluded: tuple[int, ...] | None = None,
) -> SolveStatus:
    if not invariant_ok:
        return SolveStatus.ERROR
    if not complete_domain:
        return SolveStatus.CENSORED
    if certificate is None or not verify_complete_domain_certificate(
        certificate,
        domains=domains,
        validator=validator,
        excluded=excluded,
    ):
        return SolveStatus.ERROR
    return SolveStatus.EXHAUSTED


def leaf_candidates(
    *,
    coefficient: int,
    adjusted_rhs: int,
    q: int,
    domain: Sequence[int],
    max_abs: int,
    max_l1: int | None,
    max_l2_squared: int | None,
    max_nonzero: int | None,
) -> tuple[int, ...]:
    """Enumerate every value permitted by one current degree-one row."""

    if q <= 1 or not domain or coefficient % q == 0:
        raise ValueError("invalid leaf equation")
    return tuple(
        value
        for value in domain
        if residuals_within_budget(
            (_centered(adjusted_rhs - coefficient * value, q),),
            max_abs=max_abs,
            max_l1=max_l1,
            max_l2_squared=max_l2_squared,
            max_nonzero=max_nonzero,
        )
    )


def classify_leaf_intersection(
    candidate_sets: Sequence[Iterable[int]], *, votes: Mapping[int, int] | None = None
) -> LeafDecision:
    """Ignore votes for commitment; only an exact singleton may be forced."""

    del votes
    sets = tuple(set(values) for values in candidate_sets)
    if not sets:
        return LeafDecision("ambiguous", ())
    values = tuple(sorted(set.intersection(*sets)))
    if not values:
        return LeafDecision("contradiction", ())
    if len(values) == 1:
        return LeafDecision("singleton", values)
    return LeafDecision("ambiguous", values)


def peel_public_graph(
    *,
    rows: Sequence[Sequence[int]],
    rhs: Sequence[int],
    q: int,
    domains: Sequence[Sequence[int]],
    max_abs: int,
    max_l1: int | None,
    max_l2_squared: int | None,
    max_nonzero: int | None,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> PeelState:
    """Peel only exact singleton leaf intersections; never vote or guess."""

    n = _matrix_shape(rows, deadline=deadline)
    if len(rows) != len(rhs) or len(domains) != n:
        raise ValueError("graph dimensions do not agree")
    retained_memory = _estimated_size(
        (rows, rhs, domains),
        cap=memory_cap_bytes,
        deadline=deadline,
    )
    if memory_cap_bytes is not None and retained_memory > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    assignments: dict[int, int] = {}
    while True:
        reason = _cutoff_reason(
            deadline=deadline,
            memory_used=retained_memory + _estimated_size(assignments),
            memory_cap_bytes=memory_cap_bytes,
        )
        if reason is not None:
            raise TraversalCutoff(reason)
        by_coordinate: dict[int, list[tuple[int, ...]]] = {}
        for row, target in zip(rows, rhs, strict=True):
            reason = _cutoff_reason(
                deadline=deadline,
                memory_used=(
                    retained_memory
                    + _estimated_size(assignments)
                    + _estimated_size(by_coordinate)
                ),
                memory_cap_bytes=memory_cap_bytes,
            )
            if reason is not None:
                raise TraversalCutoff(reason)
            unresolved_list: list[int] = []
            for index, coefficient in enumerate(row):
                if deadline is not None and time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                if coefficient % q and index not in assignments:
                    unresolved_list.append(index)
            unresolved = tuple(unresolved_list)
            adjusted = target
            for index, value in assignments.items():
                if deadline is not None and time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                adjusted -= row[index] * value
            if not unresolved:
                residual = _centered(adjusted, q)
                if not residuals_within_budget(
                    (residual,),
                    max_abs=max_abs,
                    max_l1=max_l1,
                    max_l2_squared=max_l2_squared,
                    max_nonzero=max_nonzero,
                ):
                    return PeelState(
                        "contradiction", tuple(sorted(assignments.items())),
                        tuple(index for index in range(n) if index not in assignments),
                    )
            elif len(unresolved) == 1:
                coordinate = unresolved[0]
                by_coordinate.setdefault(coordinate, []).append(
                    leaf_candidates(
                        coefficient=row[coordinate],
                        adjusted_rhs=adjusted,
                        q=q,
                        domain=domains[coordinate],
                        max_abs=max_abs,
                        max_l1=max_l1,
                        max_l2_squared=max_l2_squared,
                        max_nonzero=max_nonzero,
                    )
                )
        commits: dict[int, int] = {}
        for coordinate, candidate_sets in by_coordinate.items():
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            decision = classify_leaf_intersection(candidate_sets)
            if decision.kind == "contradiction":
                return PeelState(
                    "contradiction", tuple(sorted(assignments.items())),
                    tuple(index for index in range(n) if index not in assignments),
                )
            if decision.kind == "singleton":
                commits[coordinate] = decision.values[0]
        if not commits:
            unresolved = tuple(index for index in range(n) if index not in assignments)
            kind = "complete" if not unresolved else "stalled"
            return PeelState(kind, tuple(sorted(assignments.items())), unresolved)
        assignments.update(commits)


def _is_prime(q: int, *, deadline: float | None = None) -> bool:
    if type(q) is not int or q < 2:
        return False
    if q % 2 == 0:
        return q == 2
    factor = 3
    while factor * factor <= q:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if q % factor == 0:
            return False
        factor += 2
    return True


def rank_mod_prime(
    matrix: Sequence[Sequence[int]],
    q: int,
    *,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> int:
    if not _is_prime(q, deadline=deadline):
        raise ValueError("rank requires a prime field modulus")
    if not matrix:
        return 0
    width = len(matrix[0])
    for row in matrix:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if len(row) != width:
            raise ValueError("rank matrix is ragged")
    def require_state(*state: object, reserve_bytes: int = 0) -> int:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if memory_cap_bytes is None:
            return 0
        retained_memory = _estimated_size(
            state,
            cap=memory_cap_bytes,
            deadline=deadline,
        )
        if retained_memory + reserve_bytes > memory_cap_bytes:
            raise TraversalCutoff("memory_cap")
        return retained_memory

    require_state(matrix, reserve_bytes=128)
    work: list[list[int]] = []
    require_state(matrix, work)
    for matrix_row in matrix:
        require_state(matrix, work, matrix_row, reserve_bytes=128)
        reduced_row: list[int] = []
        require_state(matrix, work, matrix_row, reduced_row)
        for value in matrix_row:
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            require_state(
                matrix,
                work,
                matrix_row,
                reduced_row,
                value,
                q,
                reserve_bytes=sys.getsizeof(reduced_row) + sys.getsizeof(q),
            )
            reduced_value = value % q
            require_state(
                matrix,
                work,
                matrix_row,
                reduced_row,
                reduced_value,
                reserve_bytes=sys.getsizeof(reduced_row),
            )
            reduced_row.append(reduced_value)
            require_state(matrix, work, matrix_row, reduced_row)
        require_state(
            matrix,
            work,
            matrix_row,
            reduced_row,
            reserve_bytes=sys.getsizeof(work),
        )
        work.append(reduced_row)
        require_state(matrix, work)
    rank = 0
    for column in range(width):
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        pivot = None
        for row in range(rank, len(work)):
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            if work[row][column]:
                pivot = row
                break
        if pivot is None:
            continue
        work[rank], work[pivot] = work[pivot], work[rank]
        inverse = pow(work[rank][column], -1, q)
        require_state(matrix, work, inverse, reserve_bytes=128)
        normalized: list[int] = []
        require_state(matrix, work, inverse, normalized)
        for value in work[rank]:
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            require_state(
                matrix,
                work,
                inverse,
                normalized,
                value,
                q,
                reserve_bytes=sys.getsizeof(normalized) + sys.getsizeof(q),
            )
            normalized_value = (value * inverse) % q
            require_state(
                matrix,
                work,
                inverse,
                normalized,
                normalized_value,
                reserve_bytes=sys.getsizeof(normalized),
            )
            normalized.append(normalized_value)
            require_state(matrix, work, inverse, normalized)
        require_state(matrix, work, inverse, normalized)
        work[rank] = normalized
        require_state(matrix, work, inverse)
        for row in range(len(work)):
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            if row == rank or work[row][column] == 0:
                continue
            multiple = work[row][column]
            require_state(matrix, work, inverse, multiple, reserve_bytes=128)
            reduced: list[int] = []
            require_state(matrix, work, inverse, multiple, reduced)
            for index in range(width):
                if deadline is not None and time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                value = work[row][index]
                pivot_value = work[rank][index]
                require_state(
                    matrix,
                    work,
                    inverse,
                    multiple,
                    reduced,
                    value,
                    pivot_value,
                    q,
                    reserve_bytes=sys.getsizeof(reduced) + sys.getsizeof(q),
                )
                reduced_value = (value - multiple * pivot_value) % q
                require_state(
                    matrix,
                    work,
                    inverse,
                    multiple,
                    reduced,
                    reduced_value,
                    reserve_bytes=sys.getsizeof(reduced),
                )
                reduced.append(reduced_value)
                require_state(matrix, work, inverse, multiple, reduced)
            require_state(matrix, work, inverse, multiple, reduced)
            work[row] = reduced
            require_state(matrix, work, inverse, multiple)
        rank += 1
        if rank == len(work) or rank == width:
            break
    require_state(matrix, work)
    return rank


def _minor_for_coordinates(
    rows: Sequence[Sequence[int]],
    q: int,
    coordinates: tuple[int, ...],
    *,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> DenseMinor | None:
    selected = frozenset(coordinates)

    def require_state(*state: object, reserve_bytes: int = 0) -> int:
        retained_memory = _estimated_size(
            state,
            cap=memory_cap_bytes,
            deadline=deadline,
        )
        reason = _cutoff_reason(
            deadline=deadline,
            memory_used=retained_memory + reserve_bytes,
            memory_cap_bytes=memory_cap_bytes,
        )
        if reason is not None:
            raise TraversalCutoff(reason)
        return retained_memory

    require_state(rows, coordinates, selected)
    contained_list: list[int] = []
    for row_index, row in enumerate(rows):
        require_state(rows, coordinates, selected, contained_list, row_index)
        is_contained = True
        for index, value in enumerate(row):
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            if value % q and index not in selected:
                is_contained = False
                break
        if is_contained:
            require_state(
                rows,
                coordinates,
                selected,
                contained_list,
                row_index,
                reserve_bytes=sys.getsizeof(contained_list),
            )
            contained_list.append(row_index)
            require_state(rows, coordinates, selected, contained_list)
    require_state(
        rows,
        coordinates,
        selected,
        contained_list,
        reserve_bytes=sys.getsizeof(contained_list),
    )
    contained = tuple(contained_list)
    require_state(rows, coordinates, selected, contained_list, contained)
    r = len(coordinates)
    if len(contained) < r + 1:
        return None
    induced_list: list[tuple[int, ...]] = []
    for row_index in contained:
        require_state(
            rows,
            coordinates,
            selected,
            contained_list,
            contained,
            induced_list,
            row_index,
            reserve_bytes=sys.getsizeof(induced_list),
        )
        induced_row: list[int] = []
        for column in coordinates:
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            value = rows[row_index][column]
            require_state(
                rows,
                coordinates,
                selected,
                contained_list,
                contained,
                induced_list,
                induced_row,
                value,
                reserve_bytes=sys.getsizeof(induced_row),
            )
            induced_row.append(value)
            require_state(
                rows,
                coordinates,
                selected,
                contained_list,
                contained,
                induced_list,
                induced_row,
            )
        require_state(
            rows,
            coordinates,
            selected,
            contained_list,
            contained,
            induced_list,
            induced_row,
            reserve_bytes=sys.getsizeof(induced_row),
        )
        frozen_induced_row = tuple(induced_row)
        require_state(
            rows,
            coordinates,
            selected,
            contained_list,
            contained,
            induced_list,
            induced_row,
            frozen_induced_row,
            reserve_bytes=sys.getsizeof(induced_list),
        )
        induced_list.append(frozen_induced_row)
        require_state(
            rows,
            coordinates,
            selected,
            contained_list,
            contained,
            induced_list,
            induced_row,
            frozen_induced_row,
        )
        del induced_row, frozen_induced_row
    require_state(
        rows,
        coordinates,
        selected,
        contained_list,
        contained,
        induced_list,
        reserve_bytes=sys.getsizeof(induced_list),
    )
    induced = tuple(induced_list)
    require_state(
        rows,
        coordinates,
        selected,
        contained_list,
        contained,
        induced_list,
        induced,
    )
    outside_rank_memory = require_state(
        rows,
        coordinates,
        selected,
        contained_list,
        contained,
        induced_list,
    )
    rank_memory_cap = (
        None
        if memory_cap_bytes is None
        else memory_cap_bytes - outside_rank_memory
    )
    if rank_memory_cap is not None and rank_memory_cap <= 0:
        raise TraversalCutoff("memory_cap")
    if rank_mod_prime(
        induced,
        q,
        deadline=deadline,
        memory_cap_bytes=rank_memory_cap,
    ) != r:
        return None
    require_state(
        rows,
        coordinates,
        selected,
        contained_list,
        contained,
        induced_list,
        induced,
        reserve_bytes=sys.getsizeof(coordinates) + sys.getsizeof(contained),
    )
    minor = DenseMinor(coordinates, contained)
    require_state(
        rows,
        coordinates,
        selected,
        contained_list,
        contained,
        induced_list,
        induced,
        minor,
    )
    return minor


def find_dense_minor(
    rows: Sequence[Sequence[int]],
    *,
    q: int,
    r: int,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> DenseMinor | None:
    n = _matrix_shape(rows, deadline=deadline)
    if not _is_prime(q, deadline=deadline) or type(r) is not int or r <= 0 or r > n:
        return None
    retained_memory = _estimated_size(
        rows,
        cap=memory_cap_bytes,
        deadline=deadline,
    )
    if memory_cap_bytes is not None and retained_memory > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    for coordinates in itertools.combinations(range(n), r):
        reason = _cutoff_reason(
            deadline=deadline,
            memory_used=retained_memory + _estimated_size(coordinates),
            memory_cap_bytes=memory_cap_bytes,
        )
        if reason is not None:
            raise TraversalCutoff(reason)
        minor = _minor_for_coordinates(
            rows,
            q,
            coordinates,
            deadline=deadline,
            memory_cap_bytes=memory_cap_bytes,
        )
        if minor is not None:
            return minor
    return None


def _unrank_combination(*, n: int, r: int, ordinal: int) -> tuple[int, ...]:
    """Return one lexicographically ranked r-subset without enumerating peers."""

    total = math.comb(n, r)
    if not 0 <= ordinal < total:
        raise ValueError("combination ordinal is outside the public domain")
    selected: list[int] = []
    lower = 0
    remaining = r
    while remaining:
        for candidate in range(lower, n):
            suffix_count = math.comb(n - candidate - 1, remaining - 1)
            if ordinal < suffix_count:
                selected.append(candidate)
                lower = candidate + 1
                remaining -= 1
                break
            ordinal -= suffix_count
        else:  # pragma: no cover - guarded by the ordinal bound above
            raise ValueError("combination ordinal cannot be decoded")
    return tuple(selected)


def _sample_unique_ordinals(
    *,
    total: int,
    count: int,
    seed: int,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> tuple[int, ...]:
    """Deterministically sample distinct ordinals without a sized range."""

    if (
        type(total) is not int
        or type(count) is not int
        or type(seed) is not int
        or total < 0
        or count < 0
        or count > total
    ):
        raise ValueError("invalid ordinal sample domain")
    if memory_cap_bytes is not None:
        if type(memory_cap_bytes) is not int or memory_cap_bytes <= 0:
            raise ValueError("memory_cap_bytes must be a positive integer")
        # Floyd sampling retains one integer plus references in a set, a list,
        # and the returned tuple.  This deliberately conservative bound is
        # checked before either container grows, so an adversarially large
        # public subset cap is censored instead of allocating toward an OOM.
        empty_container_bytes = sys.getsizeof(set()) + sys.getsizeof([])
        retained_bytes_per_ordinal = sys.getsizeof(0) + 3 * sys.getsizeof(None) + 128
        if (
            empty_container_bytes + count * retained_bytes_per_ordinal
            > memory_cap_bytes
        ):
            raise TraversalCutoff("memory_cap")
    generator = random.Random(seed)
    selected_set: set[int] = set()
    selected: list[int] = []
    # Floyd's algorithm needs exactly ``count`` arbitrary-precision draws and
    # never asks Python to represent ``total`` as a platform-sized length.
    for upper in range(total - count, total):
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        candidate = generator.randrange(upper + 1)
        ordinal = upper if candidate in selected_set else candidate
        selected_set.add(ordinal)
        selected.append(ordinal)
    return tuple(selected)


def iter_local_candidates(
    *,
    rows: Sequence[Sequence[int]],
    rhs: Sequence[int],
    coordinates: Sequence[int],
    domains: Sequence[Sequence[int]],
    q: int,
    max_abs: int,
    max_l1: int | None,
    max_l2_squared: int | None,
    max_nonzero: int | None,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
    retained_state: object | None = None,
) -> Iterable[Mapping[int, int]]:
    """Yield every locally compatible witness, not merely the first one."""

    n = _matrix_shape(rows, deadline=deadline)
    if len(rows) != len(rhs) or len(domains) != n:
        raise ValueError("local problem dimensions do not agree")
    chosen = tuple(coordinates)
    chosen_set: set[int] = set()
    for index in chosen:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if index < 0 or index >= n or index in chosen_set:
            raise ValueError("invalid local coordinates")
        chosen_set.add(index)
    if len(chosen) != len(chosen_set):
        raise ValueError("invalid local coordinates")
    retained_memory = _estimated_size(
        (rows, rhs, chosen, domains, retained_state),
        cap=memory_cap_bytes,
        deadline=deadline,
    )
    if memory_cap_bytes is not None and retained_memory > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    for values in itertools.product(*(domains[index] for index in chosen)):
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        assignment = dict(zip(chosen, values, strict=True))
        if memory_cap_bytes is not None and _estimated_size(
            (rows, rhs, chosen, domains, retained_state, assignment),
            cap=memory_cap_bytes,
            deadline=deadline,
        ) > memory_cap_bytes:
            raise TraversalCutoff("memory_cap")
        residual_list: list[int] = []
        for row, target in zip(rows, rhs, strict=True):
            if deadline is not None and time.monotonic() >= deadline:
                raise TraversalCutoff("timeout")
            residual = target
            for index in chosen:
                if deadline is not None and time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                residual -= row[index] * assignment[index]
            residual_list.append(
                _centered(residual, q)
            )
            if memory_cap_bytes is not None and _estimated_size(
                (
                    rows,
                    rhs,
                    chosen,
                    domains,
                    retained_state,
                    assignment,
                    residual_list,
                ),
                cap=memory_cap_bytes,
                deadline=deadline,
            ) > memory_cap_bytes:
                raise TraversalCutoff("memory_cap")
        residuals = tuple(residual_list)
        if residuals_within_budget(
            residuals,
            max_abs=max_abs,
            max_l1=max_l1,
            max_l2_squared=max_l2_squared,
            max_nonzero=max_nonzero,
        ):
            yield MappingProxyType(assignment)


def search_local_completions(
    *,
    n: int,
    coordinates: Sequence[int],
    local_candidates: Sequence[Mapping[int, int]],
    remaining_domains: Mapping[int, Sequence[int]],
    validator: Callable[[tuple[int, ...]], bool],
    excluded: tuple[int, ...] | None,
    work_unit_cap: int,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> ExactSearchOutcome:
    expected = frozenset(coordinates)
    if any(frozenset(candidate) != expected for candidate in local_candidates):
        raise ValueError("local candidate has the wrong coordinate set")
    return search_assignment_product(
        n=n,
        assignment_groups=(local_candidates,),
        uncovered_domains=remaining_domains,
        validator=validator,
        excluded=excluded,
        work_unit_cap=work_unit_cap,
        deadline=deadline,
        memory_cap_bytes=memory_cap_bytes,
    )


def _parameter_int(request: SolveRequest, name: str, default: int) -> int:
    value = request.parameters.get(name, default)
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _memory_cap(request: SolveRequest) -> int:
    return _parameter_int(request, "memory_cap_bytes", 256 * 1024 * 1024)


def _secret_domains(
    instance: ExactProblem,
    *,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> tuple[tuple[int, ...], ...]:
    source: Iterable[int]
    if instance.secret_predicate_kind == "mod_q":
        source = range(instance.q)
    else:
        source = instance.secret_alphabet
    values: list[int] = []
    observed: set[int] = set()
    memory_used = sys.getsizeof(values) + sys.getsizeof(observed)
    for value in source:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if type(value) is not int or value in observed:
            raise ValueError("secret predicate has an invalid coordinate domain")
        old_values_size = sys.getsizeof(values)
        old_observed_size = sys.getsizeof(observed)
        values.append(value)
        observed.add(value)
        memory_used += (
            sys.getsizeof(values)
            - old_values_size
            + sys.getsizeof(observed)
            - old_observed_size
            + sys.getsizeof(value)
        )
        if memory_cap_bytes is not None and memory_used > memory_cap_bytes:
            raise TraversalCutoff("memory_cap")
    if not values:
        raise ValueError("secret predicate has an invalid coordinate domain")
    domain = tuple(values)
    domains = (domain,) * instance.n
    if memory_cap_bytes is not None and _estimated_size(
        (values, observed, domains),
        cap=memory_cap_bytes,
        deadline=deadline,
    ) > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")
    return domains


def _valid_candidate(
    instance: ExactProblem,
    secret: tuple[int, ...],
    *,
    deadline: float | None = None,
) -> bool:
    verdict = instance.validate_secret(secret)
    if deadline is not None and time.monotonic() >= deadline:
        raise TraversalCutoff("timeout")
    return getattr(verdict, "ok", None) is True


def _result_detail(
    code: str,
    *,
    certificate: CompleteDomainCertificate | None = None,
    tested_count: int | None = None,
    subset_size: int | None = None,
    rank: int | None = None,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> dict[str, object]:
    detail: dict[str, object] = {"code": code}
    public_parameters: dict[str, object] = {}
    if tested_count is not None:
        public_parameters["tested_count"] = tested_count
    if subset_size is not None:
        public_parameters["subset_size"] = subset_size
    if rank is not None:
        public_parameters["rank"] = rank
    if public_parameters:
        detail["public_parameters"] = public_parameters
    if certificate is not None:
        detail["certificate_id"] = "complete_domain_v1"
        detail["certificate_digest"] = _certificate_digest(
            certificate,
            deadline=deadline,
            memory_cap_bytes=memory_cap_bytes,
        )
    return detail


def make_public_result_detail(
    code: str,
    *,
    certificate: CompleteDomainCertificate | None = None,
    tested_count: int | None = None,
    subset_size: int | None = None,
    rank: int | None = None,
) -> dict[str, object]:
    """Build the closed, witness-free detail shape used by every task-5 result."""

    return _result_detail(
        code,
        certificate=certificate,
        tested_count=tested_count,
        subset_size=subset_size,
        rank=rank,
    )


def repeated_support_applicability(
    instance: ExactProblem, request: SolveRequest | None = None
) -> bool:
    del request
    if instance.matrix_kind not in _SPARSE_MATRIX_KINDS:
        return False
    try:
        return bool(group_repeated_rows(instance.materialize_rows(), q=instance.q))
    except (TypeError, ValueError):
        return False


def graph_peeling_applicability(
    instance: ExactProblem, request: SolveRequest | None = None
) -> bool:
    del request
    return (
        instance.matrix_kind == "sparse_small_alphabet"
        and type(instance.matrix_row_weight) is int
        and instance.matrix_row_weight > 0
    )


def dense_minor_applicability(
    instance: ExactProblem, request: SolveRequest | None = None
) -> bool:
    try:
        deadline = (
            None
            if request is None
            else time.monotonic() + request.max_seconds
        )
        if (
            instance.matrix_kind not in _SPARSE_MATRIX_KINDS
            or not _is_prime(instance.q, deadline=deadline)
        ):
            return False
        n = instance.n
        m = instance.m
        r = instance.matrix_row_weight
        if request is not None:
            r = request.parameters.get("minor_size", r)
        return (
            type(n) is int
            and n > 0
            and type(m) is int
            and type(r) is int
            and 0 < r <= n
            and m >= r + 1
        )
    except (AttributeError, TraversalCutoff, TypeError, ValueError):
        return False


class RepeatedSupportRecovery(ValidatedExactSolver):
    solver_id = "repeated_support"

    def _solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult:
        started = time.monotonic()
        deadline = started + request.max_seconds
        work_units = 0
        checkpoint_count = 0
        try:
            memory_cap = _memory_cap(request)
            rows = _materialize_rows_bounded(
                instance, deadline=deadline, memory_cap_bytes=memory_cap
            )
            if (
                len(rows) != instance.m
                or len(instance.b) != instance.m
                or _matrix_shape(rows) != instance.n
            ):
                raise ValueError("public instance dimensions disagree")
            groups = group_repeated_rows(
                rows,
                q=instance.q,
                deadline=deadline,
                memory_cap_bytes=memory_cap,
            )
            if not groups:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=0,
                    detail=_result_detail("inapplicable_no_repeated_support"),
                )
            retained_before_domains = _estimated_size(
                (rows, groups),
                cap=memory_cap,
                deadline=deadline,
            )
            if retained_before_domains > memory_cap:
                raise TraversalCutoff("memory_cap")
            domains = _secret_domains(
                instance,
                deadline=deadline,
                memory_cap_bytes=memory_cap - retained_before_domains,
            )
            global_work_cap = _parameter_int(
                request, "work_unit_cap", 2_000_000
            )
            local_budget = _parameter_int(request, "local_assignment_budget", 1_000_000)
            group_candidates: list[tuple[Mapping[int, int], ...]] = []
            for group in groups:
                if time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                remaining_work = global_work_cap - work_units
                if remaining_work <= 0:
                    return SolveResult.censored(
                        elapsed_seconds=time.monotonic() - started,
                        work_units=work_units,
                        detail=_result_detail(
                            "work_unit_cap", tested_count=work_units
                        ),
                    )
                outer_memory = _estimated_size(
                    (groups, group_candidates),
                    cap=memory_cap,
                    deadline=deadline,
                )
                if outer_memory > memory_cap:
                    raise TraversalCutoff("memory_cap")
                outcome = enumerate_local_assignments(
                    group,
                    rows=rows,
                    rhs=instance.b,
                    domains=domains,
                    q=instance.q,
                    max_abs=instance.error_max_abs,
                    max_l1=instance.error_max_l1,
                    max_l2_squared=instance.error_max_l2_squared,
                    max_nonzero=instance.error_max_nonzero,
                    assignment_budget=min(local_budget, remaining_work),
                    deadline=deadline,
                    memory_cap_bytes=memory_cap - outer_memory,
                )
                work_units += outcome.tested
                if not outcome.complete or time.monotonic() >= deadline:
                    if time.monotonic() >= deadline:
                        reason = "timeout"
                    elif work_units >= global_work_cap:
                        reason = "work_unit_cap"
                    else:
                        reason = outcome.reason
                    return SolveResult.censored(
                        elapsed_seconds=time.monotonic() - started,
                        work_units=work_units,
                        detail=_result_detail(reason, tested_count=work_units),
                    )
                if _estimated_size(
                    (rows, groups, domains, group_candidates, outcome.assignments),
                    cap=memory_cap,
                    deadline=deadline,
                ) > memory_cap:
                    raise TraversalCutoff("memory_cap")
                group_candidates.append(outcome.assignments)
            covered_values: set[int] = set()
            for group in groups:
                if time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                for index in group.support:
                    if time.monotonic() >= deadline:
                        raise TraversalCutoff("timeout")
                    covered_values.add(index)
            covered = frozenset(covered_values)
            uncovered: dict[int, Sequence[int]] = {}
            for index in range(instance.n):
                if time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                if index not in covered:
                    uncovered[index] = domains[index]
            remaining_cap = max(global_work_cap - work_units, 0)
            checkpoint_store = CheckpointStore(
                work_dir=request.work_dir,
                solver_id=self.solver_id,
                solver_revision="task5-repeated-v1",
                instance_digest=instance.instance_digest,
                seed=request.seed,
            )
            outside_search_memory = _estimated_size(
                (rows, groups, group_candidates, covered),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_search_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            outcome = search_assignment_product(
                n=instance.n,
                assignment_groups=tuple(group_candidates),
                uncovered_domains=uncovered,
                validator=lambda secret: _valid_candidate(
                    instance, secret, deadline=deadline
                ),
                excluded=request.exclude_secret,
                work_unit_cap=remaining_cap,
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_search_memory,
                checkpoint_store=checkpoint_store,
                resume_checkpoint=request.resume_checkpoint,
                checkpoint_every_work_units=(
                    request.checkpoint_every_work_units
                ),
            )
            checkpoint_count = outcome.checkpoint_count
            work_units += outcome.work_units
            if outcome.secret is not None:
                return SolveResult.success(
                    secret=outcome.secret,
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    checkpoint_count=checkpoint_count,
                    detail=_result_detail("accepted_witness", tested_count=work_units),
                )
            if not outcome.complete:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    checkpoint_count=checkpoint_count,
                    detail=_result_detail(outcome.reason, tested_count=work_units),
                )
            outside_certificate_memory = _estimated_size(
                (
                    rows,
                    groups,
                    group_candidates,
                    covered,
                    uncovered,
                    outcome,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_certificate_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            remaining_cap = max(global_work_cap - work_units, 0)
            certified = certifying_cartesian_search(
                domains=domains,
                validator=lambda secret: _valid_candidate(
                    instance, secret, deadline=deadline
                ),
                excluded=request.exclude_secret,
                work_unit_cap=remaining_cap,
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_certificate_memory,
            )
            work_units += certified.work_units
            if certified.secret is not None:
                return SolveResult.success(
                    secret=certified.secret,
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    checkpoint_count=checkpoint_count,
                    detail=_result_detail(
                        "accepted_witness", tested_count=work_units
                    ),
                )
            if not certified.complete:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    checkpoint_count=checkpoint_count,
                    detail=_result_detail(
                        certified.reason, tested_count=work_units
                    ),
                )
            outside_builder_memory = _estimated_size(
                (
                    rows,
                    groups,
                    group_candidates,
                    covered,
                    uncovered,
                    outcome,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_builder_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            certificate = build_complete_domain_certificate(
                domains,
                certified,
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_builder_memory,
            )
            outside_verifier_memory = _estimated_size(
                (
                    rows,
                    groups,
                    group_candidates,
                    covered,
                    uncovered,
                    outcome,
                    certified,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_verifier_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            verifier_work = certificate.candidate_count
            if verifier_work > global_work_cap - work_units:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    checkpoint_count=checkpoint_count,
                    detail=_result_detail(
                        "work_unit_cap", tested_count=work_units
                    ),
                )
            work_units += verifier_work
            if not verify_complete_domain_certificate(
                certificate,
                domains=domains,
                validator=lambda secret: _valid_candidate(
                    instance, secret, deadline=deadline
                ),
                excluded=request.exclude_secret,
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_verifier_memory,
                work_unit_cap=verifier_work,
            ):
                return SolveResult.error(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    checkpoint_count=checkpoint_count,
                    detail=_result_detail("certificate_invariant"),
                )
            outside_digest_memory = _estimated_size(
                (
                    rows,
                    groups,
                    domains,
                    group_candidates,
                    covered,
                    uncovered,
                    outcome,
                    certified,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_digest_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            return SolveResult.exhausted(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                checkpoint_count=checkpoint_count,
                detail=_result_detail(
                    "complete_domain",
                    certificate=certificate,
                    tested_count=work_units,
                    deadline=deadline,
                    memory_cap_bytes=memory_cap - outside_digest_memory,
                ),
            )
        except TraversalCutoff as exc:
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                checkpoint_count=checkpoint_count,
                detail=_result_detail(exc.reason, tested_count=work_units),
            )
        except (IndexError, SolverContractError, TypeError, ValueError):
            return SolveResult.error(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                checkpoint_count=checkpoint_count,
                detail=_result_detail("malformed_invariant"),
            )


class GraphPeelingRecovery(ValidatedExactSolver):
    solver_id = "graph_peeling"

    def _solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult:
        started = time.monotonic()
        deadline = started + request.max_seconds
        work_units = 0
        try:
            memory_cap = _memory_cap(request)
            global_work_cap = _parameter_int(
                request, "work_unit_cap", 2_000_000
            )
            if not graph_peeling_applicability(instance, request):
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=0,
                    detail=_result_detail("inapplicable_graph"),
                )
            rows = _materialize_rows_bounded(
                instance,
                deadline=deadline,
                memory_cap_bytes=memory_cap,
            )
            rows_memory = _estimated_size(
                rows,
                cap=memory_cap,
                deadline=deadline,
            )
            if rows_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            domains = _secret_domains(
                instance,
                deadline=deadline,
                memory_cap_bytes=memory_cap - rows_memory,
            )
            state = peel_public_graph(
                rows=rows,
                rhs=instance.b,
                q=instance.q,
                domains=domains,
                max_abs=instance.error_max_abs,
                max_l1=instance.error_max_l1,
                max_l2_squared=instance.error_max_l2_squared,
                max_nonzero=instance.error_max_nonzero,
                deadline=deadline,
                memory_cap_bytes=memory_cap,
            )
            assigned = dict(state.assignments)
            work_units = len(state.assignments)
            if work_units > global_work_cap:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail(
                        "work_unit_cap", tested_count=work_units
                    ),
                )
            if state.kind == "complete":
                candidate = tuple(assigned[index] for index in range(instance.n))
                if candidate != request.exclude_secret and _valid_candidate(
                    instance, candidate, deadline=deadline
                ):
                    return SolveResult.success(
                        secret=candidate,
                        elapsed_seconds=time.monotonic() - started,
                        work_units=len(state.assignments),
                        detail=_result_detail("accepted_witness", tested_count=1),
                    )
            # Revisit even proved singleton values after the fast peel when a
            # witness was not already accepted.  This conservative fallback
            # makes a later EXHAUSTED certificate cover the literal full
            # public domain without asking its verifier to trust a peel proof.
            ordered_domains: dict[int, Sequence[int]] = {}
            for index in range(instance.n):
                if time.monotonic() >= started + request.max_seconds:
                    raise TraversalCutoff("timeout")
                if index in assigned:
                    reordered = [assigned[index]]
                    for value in domains[index]:
                        if time.monotonic() >= started + request.max_seconds:
                            raise TraversalCutoff("timeout")
                        if value != assigned[index]:
                            reordered.append(value)
                    ordered_domains[index] = tuple(reordered)
                else:
                    ordered_domains[index] = domains[index]
                if _estimated_size(
                    (rows, domains, assigned, ordered_domains),
                    cap=memory_cap,
                    deadline=deadline,
                ) > memory_cap:
                    raise TraversalCutoff("memory_cap")
            component_domain_size = 1
            for domain in ordered_domains.values():
                if time.monotonic() >= started + request.max_seconds:
                    raise TraversalCutoff("timeout")
                component_domain_size *= len(domain)
            component_cap = _parameter_int(request, "residual_component_budget", 1_000_000)
            if component_domain_size > component_cap:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=len(state.assignments),
                    detail=_result_detail("residual_component_cap"),
                )
            # The peel values remain first in branch order, but no heuristic or
            # unverified proof narrows the certified traversal.
            search_domains = tuple(
                tuple(ordered_domains[index]) for index in range(instance.n)
            )
            outside_certificate_memory = _estimated_size(
                (rows, domains, state, assigned, ordered_domains, search_domains),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_certificate_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            outcome = certifying_cartesian_search(
                domains=search_domains,
                validator=lambda secret: _valid_candidate(
                    instance, secret, deadline=deadline
                ),
                excluded=request.exclude_secret,
                work_unit_cap=min(
                    component_cap, max(global_work_cap - work_units, 0)
                ),
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_certificate_memory,
            )
            work_units += outcome.work_units
            if outcome.secret is not None:
                return SolveResult.success(
                    secret=outcome.secret,
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail("accepted_witness", tested_count=outcome.work_units),
                )
            if not outcome.complete:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail(outcome.reason, tested_count=outcome.work_units),
                )
            outside_builder_memory = _estimated_size(
                (rows, domains, state, assigned, ordered_domains, search_domains),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_builder_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            certificate = build_complete_domain_certificate(
                search_domains,
                outcome,
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_builder_memory,
            )
            outside_verifier_memory = _estimated_size(
                (
                    rows,
                    domains,
                    state,
                    assigned,
                    ordered_domains,
                    search_domains,
                    outcome,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_verifier_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            verifier_work = certificate.candidate_count
            if verifier_work > global_work_cap - work_units:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail(
                        "work_unit_cap", tested_count=work_units
                    ),
                )
            work_units += verifier_work
            if not verify_complete_domain_certificate(
                certificate,
                domains=search_domains,
                validator=lambda secret: _valid_candidate(
                    instance, secret, deadline=deadline
                ),
                excluded=request.exclude_secret,
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_verifier_memory,
                work_unit_cap=verifier_work,
            ):
                return SolveResult.error(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail("certificate_invariant"),
                )
            outside_digest_memory = _estimated_size(
                (
                    rows,
                    domains,
                    state,
                    assigned,
                    ordered_domains,
                    search_domains,
                    outcome,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_digest_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            return SolveResult.exhausted(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                detail=_result_detail(
                    "complete_domain",
                    certificate=certificate,
                    tested_count=outcome.work_units,
                    deadline=deadline,
                    memory_cap_bytes=memory_cap - outside_digest_memory,
                ),
            )
        except TraversalCutoff as exc:
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                detail=_result_detail(exc.reason, tested_count=work_units),
            )
        except (IndexError, TypeError, ValueError):
            return SolveResult.error(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                detail=_result_detail("malformed_invariant"),
            )


class DenseMinorRecovery(ValidatedExactSolver):
    solver_id = "dense_minor"

    def _solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult:
        started = time.monotonic()
        deadline = started + request.max_seconds
        work_units = 0
        try:
            memory_cap = _memory_cap(request)
            global_work_cap = _parameter_int(
                request, "work_unit_cap", 2_000_000
            )
            if instance.matrix_kind not in _SPARSE_MATRIX_KINDS or not _is_prime(instance.q):
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=0,
                    detail=_result_detail("inapplicable_modulus_or_matrix"),
                )
            r = request.parameters.get("minor_size", instance.matrix_row_weight)
            if type(r) is not int or r <= 0 or r > instance.n:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=0,
                    detail=_result_detail("inapplicable_minor_size"),
                )
            rows = _materialize_rows_bounded(
                instance,
                deadline=started + request.max_seconds,
                memory_cap_bytes=memory_cap,
            )
            rows_memory = _estimated_size(
                rows,
                cap=memory_cap,
                deadline=deadline,
            )
            if rows_memory >= memory_cap:
                raise TraversalCutoff("memory_cap")
            total_coordinate_subsets = math.comb(instance.n, r)
            subset_cap = min(
                total_coordinate_subsets,
                _parameter_int(
                    request,
                    "subset_cap",
                    min(total_coordinate_subsets, 10_000),
                ),
            )
            coordinate_ordinals = _sample_unique_ordinals(
                total=total_coordinate_subsets,
                count=subset_cap,
                seed=request.seed,
                deadline=deadline,
                memory_cap_bytes=memory_cap - rows_memory,
            )
            coordinates: list[tuple[int, ...]] = []
            coordinate_memory = _estimated_size(
                (rows, coordinate_ordinals, coordinates),
                cap=memory_cap,
                deadline=started + request.max_seconds,
            )
            if coordinate_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            for ordinal in coordinate_ordinals:
                coordinate_subset = _unrank_combination(
                    n=instance.n,
                    r=r,
                    ordinal=ordinal,
                )
                coordinate_memory = _estimated_size(
                    (rows, coordinate_ordinals, coordinates, coordinate_subset),
                    cap=memory_cap,
                    deadline=started + request.max_seconds,
                )
                reason = _cutoff_reason(
                    deadline=started + request.max_seconds,
                    memory_used=coordinate_memory,
                    memory_cap_bytes=memory_cap,
                )
                if reason is not None:
                    raise TraversalCutoff(reason)
                coordinates.append(coordinate_subset)
            if time.monotonic() >= started + request.max_seconds:
                raise TraversalCutoff("timeout")
            coordinate_only_memory = _estimated_size(
                coordinates,
                cap=memory_cap,
                deadline=started + request.max_seconds,
            )
            if coordinate_only_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            selected: DenseMinor | None = None
            for coordinate_subset in coordinates:
                reason = _cutoff_reason(
                    deadline=started + request.max_seconds,
                    memory_used=coordinate_memory,
                    memory_cap_bytes=memory_cap,
                )
                if reason is not None:
                    raise TraversalCutoff(reason)
                selected = _minor_for_coordinates(
                    rows,
                    instance.q,
                    coordinate_subset,
                    deadline=started + request.max_seconds,
                    memory_cap_bytes=memory_cap - coordinate_only_memory,
                )
                if selected is not None:
                    break
            if selected is None:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=0,
                    detail=_result_detail("subset_cap_or_inapplicable", subset_size=r),
                )
            rows_memory = _estimated_size(
                (rows, coordinates, selected),
                cap=memory_cap,
                deadline=started + request.max_seconds,
            )
            if rows_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            domains = _secret_domains(
                instance,
                deadline=started + request.max_seconds,
                memory_cap_bytes=memory_cap - rows_memory,
            )
            local_domain_size = math.prod(len(domains[index]) for index in selected.coordinates)
            local_cap = _parameter_int(request, "local_assignment_budget", 1_000_000)
            if local_domain_size > local_cap:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=0,
                    detail=_result_detail("local_assignment_cap", subset_size=r, rank=r),
                )
            if local_domain_size > global_work_cap:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=0,
                    detail=_result_detail(
                        "work_unit_cap", subset_size=r, rank=r
                    ),
                )
            induced_rows = tuple(rows[index] for index in selected.row_indices)
            induced_rhs = tuple(instance.b[index] for index in selected.row_indices)
            local_candidates_list: list[Mapping[int, int]] = []
            local_memory = _estimated_size(
                (
                    rows,
                    coordinates,
                    domains,
                    selected,
                    induced_rows,
                    induced_rhs,
                    local_candidates_list,
                ),
                cap=memory_cap,
                deadline=started + request.max_seconds,
            )
            if local_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            for candidate in iter_local_candidates(
                rows=induced_rows,
                rhs=induced_rhs,
                coordinates=selected.coordinates,
                domains=domains,
                q=instance.q,
                max_abs=instance.error_max_abs,
                max_l1=instance.error_max_l1,
                max_l2_squared=instance.error_max_l2_squared,
                max_nonzero=instance.error_max_nonzero,
                deadline=started + request.max_seconds,
                memory_cap_bytes=memory_cap,
                retained_state=(
                    rows,
                    coordinates,
                    selected,
                    local_candidates_list,
                ),
            ):
                local_memory = _estimated_size(
                    (
                        rows,
                        coordinates,
                        domains,
                        selected,
                        induced_rows,
                        induced_rhs,
                        local_candidates_list,
                        candidate,
                    ),
                    cap=memory_cap,
                    deadline=started + request.max_seconds,
                )
                if local_memory > memory_cap:
                    raise TraversalCutoff("memory_cap")
                local_candidates_list.append(candidate)
            local_candidates = tuple(local_candidates_list)
            work_units += local_domain_size
            selected_coordinates = frozenset(selected.coordinates)
            remaining: dict[int, Sequence[int]] = {}
            for index in range(instance.n):
                if time.monotonic() >= started + request.max_seconds:
                    raise TraversalCutoff("timeout")
                if index not in selected_coordinates:
                    remaining[index] = domains[index]
            outside_search_memory = _estimated_size(
                (
                    rows,
                    coordinates,
                    selected,
                    induced_rows,
                    induced_rhs,
                    local_candidates_list,
                    selected_coordinates,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_search_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            outcome = search_local_completions(
                n=instance.n,
                coordinates=selected.coordinates,
                local_candidates=local_candidates,
                remaining_domains=remaining,
                validator=lambda secret: _valid_candidate(
                    instance, secret, deadline=deadline
                ),
                excluded=request.exclude_secret,
                work_unit_cap=max(global_work_cap - work_units, 0),
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_search_memory,
            )
            work_units += outcome.work_units
            if outcome.secret is not None:
                return SolveResult.success(
                    secret=outcome.secret,
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail(
                        "accepted_witness",
                        tested_count=work_units,
                        subset_size=r,
                        rank=r,
                    ),
                )
            if not outcome.complete:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail(
                        outcome.reason,
                        tested_count=work_units,
                        subset_size=r,
                        rank=r,
                    ),
                )
            outside_certificate_memory = _estimated_size(
                (
                    rows,
                    coordinates,
                    selected,
                    induced_rows,
                    induced_rhs,
                    local_candidates_list,
                    local_candidates,
                    selected_coordinates,
                    remaining,
                    outcome,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_certificate_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            certified = certifying_cartesian_search(
                domains=domains,
                validator=lambda secret: _valid_candidate(
                    instance, secret, deadline=deadline
                ),
                excluded=request.exclude_secret,
                work_unit_cap=min(
                    _parameter_int(
                        request, "certificate_work_unit_cap", 2_000_000
                    ),
                    max(global_work_cap - work_units, 0),
                ),
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_certificate_memory,
            )
            work_units += certified.work_units
            if certified.secret is not None:
                return SolveResult.success(
                    secret=certified.secret,
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail(
                        "accepted_witness",
                        tested_count=work_units,
                        subset_size=r,
                        rank=r,
                    ),
                )
            if not certified.complete:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail(
                        certified.reason,
                        tested_count=work_units,
                        subset_size=r,
                        rank=r,
                    ),
                )
            outside_builder_memory = _estimated_size(
                (
                    rows,
                    coordinates,
                    selected,
                    induced_rows,
                    induced_rhs,
                    local_candidates_list,
                    local_candidates,
                    selected_coordinates,
                    remaining,
                    outcome,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_builder_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            certificate = build_complete_domain_certificate(
                domains,
                certified,
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_builder_memory,
            )
            outside_verifier_memory = _estimated_size(
                (
                    rows,
                    coordinates,
                    selected,
                    induced_rows,
                    induced_rhs,
                    local_candidates_list,
                    local_candidates,
                    selected_coordinates,
                    remaining,
                    outcome,
                    certified,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_verifier_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            verifier_work = certificate.candidate_count
            if verifier_work > global_work_cap - work_units:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail(
                        "work_unit_cap",
                        tested_count=work_units,
                        subset_size=r,
                        rank=r,
                    ),
                )
            work_units += verifier_work
            if not verify_complete_domain_certificate(
                certificate,
                domains=domains,
                validator=lambda secret: _valid_candidate(
                    instance, secret, deadline=deadline
                ),
                excluded=request.exclude_secret,
                deadline=deadline,
                memory_cap_bytes=memory_cap - outside_verifier_memory,
                work_unit_cap=verifier_work,
            ):
                return SolveResult.error(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail("certificate_invariant"),
                )
            outside_digest_memory = _estimated_size(
                (
                    rows,
                    coordinates,
                    domains,
                    selected,
                    induced_rows,
                    induced_rhs,
                    local_candidates_list,
                    local_candidates,
                    selected_coordinates,
                    remaining,
                    outcome,
                    certified,
                ),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_digest_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            return SolveResult.exhausted(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                detail=_result_detail(
                    "complete_domain",
                    certificate=certificate,
                    tested_count=work_units,
                    subset_size=r,
                    rank=r,
                    deadline=deadline,
                    memory_cap_bytes=memory_cap - outside_digest_memory,
                ),
            )
        except TraversalCutoff as exc:
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                detail=_result_detail(exc.reason, tested_count=work_units),
            )
        except (IndexError, TypeError, ValueError):
            return SolveResult.error(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                detail=_result_detail("malformed_invariant"),
            )


__all__ = (
    "CompleteDomainCertificate",
    "DenseMinorRecovery",
    "DomainAxis",
    "GraphPeelingRecovery",
    "RepeatedSupportRecovery",
    "build_complete_domain_certificate",
    "certifying_cartesian_search",
    "classify_leaf_intersection",
    "classify_no_solution",
    "dense_minor_applicability",
    "enumerate_local_assignments",
    "estimate_solver_state_bytes",
    "find_dense_minor",
    "graph_peeling_applicability",
    "group_repeated_rows",
    "iter_local_candidates",
    "leaf_candidates",
    "make_public_result_detail",
    "peel_public_graph",
    "rank_mod_prime",
    "repeated_support_applicability",
    "residuals_within_budget",
    "search_assignment_product",
    "search_local_completions",
    "verify_complete_domain_certificate",
)
