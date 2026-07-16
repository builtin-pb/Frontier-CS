"""Exact mixed sparse-row/small-secret filtering and backtracking."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from .api import ExactProblem, ValidatedExactSolver, SolveRequest, SolveResult
from .sparse_matrix import (
    ExactSearchOutcome,
    TraversalCutoff,
    _centered,
    _certificate_digest,
    _cutoff_reason,
    _estimated_size,
    _materialize_rows_bounded,
    _memory_cap,
    _result_detail,
    build_complete_domain_certificate,
    certifying_cartesian_search,
    leaf_candidates,
    verify_complete_domain_certificate,
)


@dataclass(frozen=True, slots=True)
class ValueScore:
    value: int
    accepted_count: int
    delta: int


@dataclass(frozen=True, slots=True)
class BranchPlan:
    values: tuple[int, ...]
    forced: bool
    contradiction: bool


@dataclass(slots=True)
class _BranchFrame:
    coordinate: int
    values: tuple[int, ...]
    next_index: int = 0


def score_coordinate_values(
    *,
    rows: Sequence[Sequence[int]],
    rhs: Sequence[int],
    q: int,
    assignment: Mapping[int, int],
    coordinate: int,
    domain: Sequence[int],
    max_abs: int,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> tuple[ValueScore, ...]:
    """Score all values; the score is never itself an exact commitment."""

    if len(rows) != len(rhs) or not rows or not domain:
        raise ValueError("invalid mixed scoring problem")
    n = len(rows[0])
    if coordinate < 0 or coordinate >= n or coordinate in assignment:
        raise ValueError("invalid scoring coordinate")
    for row in rows:
        if deadline is not None and time.monotonic() >= deadline:
            raise TraversalCutoff("timeout")
        if len(row) != n:
            raise ValueError("mixed scoring matrix is ragged")
    retained_memory = _estimated_size(
        (rows, rhs, assignment, domain),
        cap=memory_cap_bytes,
        deadline=deadline,
    )
    if memory_cap_bytes is not None and retained_memory > memory_cap_bytes:
        raise TraversalCutoff("memory_cap")

    def accepted(value: int | None) -> int:
        count = 0
        for row, target in zip(rows, rhs, strict=True):
            reason = _cutoff_reason(
                deadline=deadline,
                memory_used=retained_memory,
                memory_cap_bytes=memory_cap_bytes,
            )
            if reason is not None:
                raise TraversalCutoff(reason)
            residual = target
            for index, chosen in assignment.items():
                if deadline is not None and time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                residual -= row[index] * chosen
            if value is not None:
                residual -= row[coordinate] * value
            if abs(_centered(residual, q)) <= max_abs:
                count += 1
        return count

    baseline = accepted(None)
    return tuple(
        ValueScore(value, observed := accepted(value), observed - baseline)
        for value in domain
    )


def mixed_branch_plan(
    *,
    domain: Sequence[int],
    exact_candidate_sets: Sequence[Sequence[int]],
    scores: Sequence[ValueScore],
) -> BranchPlan:
    """Use greedy scores only to order the exact feasible set."""

    if not domain or len(domain) != len(set(domain)):
        raise ValueError("branch domain must be non-empty and unique")
    domain_set = set(domain)
    score_map = {score.value: score.accepted_count for score in scores}
    if frozenset(score_map) != frozenset(domain_set):
        raise ValueError("scores must cover the complete branch domain")
    if exact_candidate_sets:
        feasible = domain_set.intersection(
            *(set(candidate_set) for candidate_set in exact_candidate_sets)
        )
    else:
        feasible = domain_set
    ordered = tuple(sorted(feasible, key=lambda value: (-score_map[value], value)))
    if not ordered:
        return BranchPlan((), False, True)
    return BranchPlan(ordered, len(ordered) == 1, False)


def exact_ordered_backtrack(
    *,
    domains: Sequence[Sequence[int]],
    branch_planner: Callable[[int, Mapping[int, int], Sequence[int]], BranchPlan],
    coordinate_orderer: Callable[[tuple[int, ...], Mapping[int, int]], Sequence[int]],
    validator: Callable[[tuple[int, ...]], bool],
    excluded: tuple[int, ...] | None,
    min_nonzero: int,
    max_nonzero: int,
    work_unit_cap: int,
    deadline: float | None = None,
    memory_cap_bytes: int | None = None,
) -> ExactSearchOutcome:
    """Fully backtrack all exact-feasible branches in heuristic order."""

    n = len(domains)
    if (
        min_nonzero < 0
        or max_nonzero < min_nonzero
        or max_nonzero > n
        or work_unit_cap < 0
    ):
        raise ValueError("invalid mixed exact-search domain")
    for domain in domains:
        if deadline is not None and time.monotonic() >= deadline:
            return ExactSearchOutcome(None, False, 0, "timeout")
        if not domain:
            raise ValueError("invalid mixed exact-search domain")
    assignment: dict[int, int] = {}
    frames: list[_BranchFrame] = []
    work_units = 0
    try:
        base_memory = _estimated_size(
            domains,
            cap=memory_cap_bytes,
            deadline=deadline,
        )
    except TraversalCutoff as exc:
        return ExactSearchOutcome(None, False, work_units, exc.reason)
    if memory_cap_bytes is not None and base_memory > memory_cap_bytes:
        return ExactSearchOutcome(None, False, work_units, "memory_cap")

    def current_cutoff(*extra: object) -> str | None:
        try:
            search_memory = _estimated_size(
                (assignment, frames, extra),
                cap=memory_cap_bytes,
                deadline=deadline,
            )
        except TraversalCutoff as exc:
            return exc.reason
        return _cutoff_reason(
            deadline=deadline,
            memory_used=base_memory + search_memory,
            memory_cap_bytes=memory_cap_bytes,
        )

    def advance_branch() -> bool:
        while frames:
            if (reason := current_cutoff()) is not None:
                raise TraversalCutoff(reason)
            frame = frames[-1]
            assignment.pop(frame.coordinate)
            frame.next_index += 1
            if frame.next_index < len(frame.values):
                assignment[frame.coordinate] = frame.values[frame.next_index]
                return True
            frames.pop()
        return False

    while True:
        if (reason := current_cutoff()) is not None:
            return ExactSearchOutcome(None, False, work_units, reason)
        nonzero = 0
        for value in assignment.values():
            if deadline is not None and time.monotonic() >= deadline:
                return ExactSearchOutcome(None, False, work_units, "timeout")
            nonzero += value != 0
        remaining = n - len(assignment)
        pruned = nonzero > max_nonzero or nonzero + remaining < min_nonzero
        if not pruned and len(assignment) == n:
            if work_units >= work_unit_cap:
                return ExactSearchOutcome(None, False, work_units, "work_unit_cap")
            work_units += 1
            candidate = tuple(assignment[index] for index in range(n))
            if candidate != excluded:
                verdict = validator(candidate)
                if deadline is not None and time.monotonic() >= deadline:
                    return ExactSearchOutcome(
                        None, False, work_units, "timeout"
                    )
                if verdict is not True and verdict is not False:
                    raise ValueError("validator must return an exact boolean")
                if verdict is True:
                    if deadline is not None and time.monotonic() >= deadline:
                        return ExactSearchOutcome(
                            None, False, work_units, "timeout"
                        )
                    return ExactSearchOutcome(
                        candidate, False, work_units, "success"
                    )
        elif not pruned:
            unresolved_list: list[int] = []
            for index in range(n):
                if deadline is not None and time.monotonic() >= deadline:
                    return ExactSearchOutcome(None, False, work_units, "timeout")
                if index not in assignment:
                    unresolved_list.append(index)
            unresolved = tuple(unresolved_list)
            ordered_coordinates = tuple(coordinate_orderer(unresolved, assignment))
            if (reason := current_cutoff(unresolved, ordered_coordinates)) is not None:
                return ExactSearchOutcome(None, False, work_units, reason)
            if (
                frozenset(ordered_coordinates) != frozenset(unresolved)
                or len(ordered_coordinates) != len(unresolved)
            ):
                raise ValueError(
                    "coordinate orderer must retain every unresolved coordinate"
                )
            coordinate = ordered_coordinates[0]
            plan = branch_planner(coordinate, assignment, domains[coordinate])
            if (
                not isinstance(plan, BranchPlan)
                or type(plan.forced) is not bool
                or type(plan.contradiction) is not bool
            ):
                raise ValueError("branch planner flags must be exact booleans")
            if not plan.contradiction:
                if len(plan.values) != len(set(plan.values)):
                    raise ValueError("branch planner returned a duplicate branch")
                if plan.forced and len(plan.values) != 1:
                    raise ValueError(
                        "only a singleton exact feasible set may be forced"
                    )
                invalid_plan = not plan.values
                for value in plan.values:
                    if deadline is not None and time.monotonic() >= deadline:
                        return ExactSearchOutcome(
                            None, False, work_units, "timeout"
                        )
                    if value not in domains[coordinate]:
                        invalid_plan = True
                        break
                if invalid_plan:
                    raise ValueError(
                        "branch planner returned an invalid exact feasible set"
                    )
                frame = _BranchFrame(coordinate, tuple(plan.values))
                frames.append(frame)
                assignment[coordinate] = frame.values[0]
                continue
        try:
            if not advance_branch():
                break
        except TraversalCutoff as exc:
            return ExactSearchOutcome(None, False, work_units, exc.reason)

    if deadline is not None and time.monotonic() >= deadline:
        return ExactSearchOutcome(None, False, work_units, "timeout")
    return ExactSearchOutcome(None, True, work_units, "complete")


def _secret_domain(instance: ExactProblem) -> tuple[int, ...]:
    if instance.secret_predicate_kind == "mod_q":
        return tuple(range(instance.q))
    domain = tuple(instance.secret_alphabet)
    if not domain or len(domain) != len(set(domain)):
        raise ValueError("mixed secret domain is malformed")
    return domain


def _parameter_int(request: SolveRequest, name: str, default: int) -> int:
    value = request.parameters.get(name, default)
    if type(value) is not int or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def applicability(instance: ExactProblem, request: SolveRequest | None = None) -> bool:
    del request
    if (
        instance.family not in {"MIX_Q_SPARSE", "MIX_SMALL_SPARSE"}
        or instance.matrix_kind not in {"sparse_uniform", "sparse_small_alphabet"}
        or instance.secret_predicate_kind != "alphabet"
    ):
        return False
    alphabet = frozenset(instance.secret_alphabet)
    return bool(alphabet) and alphabet.issubset({-1, 0, 1}) and 0 in alphabet


class MixedFilterGreedy(ValidatedExactSolver):
    solver_id = "mixed_filter_greedy"

    def _solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult:
        started = time.monotonic()
        deadline = started + request.max_seconds
        work_units = 0
        try:
            memory_cap = _memory_cap(request)
            global_work_cap = _parameter_int(
                request, "work_unit_cap", 2_000_000
            )
            if not applicability(instance, request):
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=0,
                    detail=_result_detail("inapplicable_mixed_hypothesis"),
                )
            rows = _materialize_rows_bounded(
                instance,
                deadline=deadline,
                memory_cap_bytes=memory_cap,
            )
            if len(rows) != instance.m or len(instance.b) != instance.m:
                raise ValueError("public instance dimensions disagree")
            for row in rows:
                if time.monotonic() >= started + request.max_seconds:
                    raise TraversalCutoff("timeout")
                if len(row) != instance.n:
                    raise ValueError("public instance dimensions disagree")
            retained_row_memory = _estimated_size(
                (rows, instance.b),
                cap=memory_cap,
                deadline=started + request.max_seconds,
            )
            if retained_row_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            search_memory_cap = memory_cap - retained_row_memory
            domain = _secret_domain(instance)
            domains = (domain,) * instance.n

            def validate_candidate(secret: tuple[int, ...]) -> bool:
                verdict = getattr(instance.validate_secret(secret), "ok", None)
                if time.monotonic() >= deadline:
                    raise TraversalCutoff("timeout")
                return verdict is True

            def exact_leaf_sets(
                coordinate: int, assignment: Mapping[int, int]
            ) -> tuple[tuple[int, ...], ...]:
                sets: list[tuple[int, ...]] = []
                for row, target in zip(rows, instance.b, strict=True):
                    reason = _cutoff_reason(
                        deadline=started + request.max_seconds,
                        memory_used=(
                            retained_row_memory
                            + _estimated_size(assignment)
                            + _estimated_size(sets)
                        ),
                        memory_cap_bytes=memory_cap,
                    )
                    if reason is not None:
                        raise TraversalCutoff(reason)
                    if row[coordinate] % instance.q == 0:
                        continue
                    other_unresolved_list: list[int] = []
                    for index, coefficient in enumerate(row):
                        if time.monotonic() >= started + request.max_seconds:
                            raise TraversalCutoff("timeout")
                        if (
                            coefficient % instance.q
                            and index != coordinate
                            and index not in assignment
                        ):
                            other_unresolved_list.append(index)
                    other_unresolved = tuple(other_unresolved_list)
                    if other_unresolved:
                        continue
                    adjusted = target
                    for index, value in assignment.items():
                        if time.monotonic() >= started + request.max_seconds:
                            raise TraversalCutoff("timeout")
                        adjusted -= row[index] * value
                    sets.append(
                        leaf_candidates(
                            coefficient=row[coordinate],
                            adjusted_rhs=adjusted,
                            q=instance.q,
                            domain=domain,
                            max_abs=instance.error_max_abs,
                            max_l1=instance.error_max_l1,
                            max_l2_squared=instance.error_max_l2_squared,
                            max_nonzero=instance.error_max_nonzero,
                        )
                    )
                return tuple(sets)

            def scores_for(
                coordinate: int, assignment: Mapping[int, int]
            ) -> tuple[ValueScore, ...]:
                # This rematerializes every public residual after every branch.
                return score_coordinate_values(
                    rows=rows,
                    rhs=instance.b,
                    q=instance.q,
                    assignment=assignment,
                    coordinate=coordinate,
                    domain=domain,
                    max_abs=instance.error_max_abs,
                    deadline=started + request.max_seconds,
                    memory_cap_bytes=memory_cap,
                )

            def branch_planner(
                coordinate: int,
                assignment: Mapping[int, int],
                coordinate_domain: Sequence[int],
            ) -> BranchPlan:
                return mixed_branch_plan(
                    domain=coordinate_domain,
                    exact_candidate_sets=exact_leaf_sets(coordinate, assignment),
                    scores=scores_for(coordinate, assignment),
                )

            def coordinate_orderer(
                unresolved: tuple[int, ...], assignment: Mapping[int, int]
            ) -> tuple[int, ...]:
                margins: list[tuple[int, int]] = []
                for coordinate in unresolved:
                    if time.monotonic() >= started + request.max_seconds:
                        raise TraversalCutoff("timeout")
                    ordered = sorted(
                        (score.accepted_count for score in scores_for(coordinate, assignment)),
                        reverse=True,
                    )
                    margin = ordered[0] - ordered[1] if len(ordered) > 1 else ordered[0]
                    margins.append((coordinate, margin))
                return tuple(
                    coordinate
                    for coordinate, _margin in sorted(
                        margins, key=lambda item: (-item[1], item[0])
                    )
                )

            outcome = exact_ordered_backtrack(
                domains=domains,
                branch_planner=branch_planner,
                coordinate_orderer=coordinate_orderer,
                validator=validate_candidate,
                excluded=request.exclude_secret,
                min_nonzero=instance.secret_min_nonzero,
                max_nonzero=instance.secret_max_nonzero,
                work_unit_cap=global_work_cap,
                deadline=deadline,
                memory_cap_bytes=search_memory_cap,
            )
            if outcome.secret is not None:
                return SolveResult.success(
                    secret=outcome.secret,
                    elapsed_seconds=time.monotonic() - started,
                    work_units=outcome.work_units,
                    detail=_result_detail("accepted_witness", tested_count=outcome.work_units),
                )
            if not outcome.complete:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=outcome.work_units,
                    detail=_result_detail(outcome.reason, tested_count=outcome.work_units),
                )
            work_units = outcome.work_units
            outside_certificate_memory = _estimated_size(
                outcome,
                cap=search_memory_cap,
                deadline=deadline,
            )
            if outside_certificate_memory > search_memory_cap:
                raise TraversalCutoff("memory_cap")
            certified = certifying_cartesian_search(
                domains=domains,
                validator=validate_candidate,
                excluded=request.exclude_secret,
                work_unit_cap=min(
                    _parameter_int(
                        request, "certificate_work_unit_cap", 2_000_000
                    ),
                    max(global_work_cap - work_units, 0),
                ),
                deadline=deadline,
                memory_cap_bytes=(
                    search_memory_cap - outside_certificate_memory
                ),
            )
            total_work_units = outcome.work_units + certified.work_units
            work_units = total_work_units
            if certified.secret is not None:
                return SolveResult.success(
                    secret=certified.secret,
                    elapsed_seconds=time.monotonic() - started,
                    work_units=total_work_units,
                    detail=_result_detail(
                        "accepted_witness", tested_count=total_work_units
                    ),
                )
            if not certified.complete:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=total_work_units,
                    detail=_result_detail(
                        certified.reason, tested_count=total_work_units
                    ),
                )
            outside_builder_memory = _estimated_size(
                outcome,
                cap=search_memory_cap,
                deadline=deadline,
            )
            if outside_builder_memory > search_memory_cap:
                raise TraversalCutoff("memory_cap")
            certificate = build_complete_domain_certificate(
                domains,
                certified,
                deadline=deadline,
                memory_cap_bytes=search_memory_cap - outside_builder_memory,
            )
            outside_verifier_memory = _estimated_size(
                (outcome, certified),
                cap=search_memory_cap,
                deadline=deadline,
            )
            if outside_verifier_memory > search_memory_cap:
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
                domains=domains,
                validator=validate_candidate,
                excluded=request.exclude_secret,
                deadline=deadline,
                memory_cap_bytes=search_memory_cap - outside_verifier_memory,
                work_unit_cap=verifier_work,
            ):
                return SolveResult.error(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail=_result_detail("certificate_invariant"),
                )
            outside_digest_memory = _estimated_size(
                (rows, domains, outcome, certified),
                cap=memory_cap,
                deadline=deadline,
            )
            if outside_digest_memory > memory_cap:
                raise TraversalCutoff("memory_cap")
            return SolveResult.exhausted(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                detail={
                    **_result_detail(
                        "complete_domain", tested_count=work_units
                    ),
                    "certificate_id": "complete_domain_v1",
                    "certificate_digest": _certificate_digest(
                        certificate,
                        deadline=deadline,
                        memory_cap_bytes=memory_cap - outside_digest_memory,
                    ),
                },
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
    "BranchPlan",
    "MixedFilterGreedy",
    "ValueScore",
    "applicability",
    "exact_ordered_backtrack",
    "mixed_branch_plan",
    "score_coordinate_values",
)
