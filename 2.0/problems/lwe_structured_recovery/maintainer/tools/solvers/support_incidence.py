"""Support-incidence recovery for weight-two sparse-secret instances.

The solver uses only a public necessary condition.  If a row has
``|center(b_i)|`` above the accepted error bound, then a valid weight-two
secret cannot be zero on that row's public support.  For weight two, every
valid support is therefore a size-two hitting set for the active row supports.
"""

from __future__ import annotations

import itertools
import time
from collections.abc import Iterable

from .api import ExactProblem, SolveRequest, SolveResult, ValidatedExactSolver


_SUPPORTED_FAMILIES = frozenset({"MIX_Q_SPARSE"})


def _centered(value: int, q: int) -> int:
    residue = value % q
    return residue - q if residue > q // 2 else residue


def _nonzero_secret_values(instance: ExactProblem) -> tuple[int, ...]:
    if instance.secret_predicate_kind != "alphabet":
        return ()
    values = tuple(value for value in instance.secret_alphabet if value != 0)
    if not values or len(values) != len(set(values)):
        return ()
    return values


def applicability(instance: ExactProblem, request: SolveRequest | None = None) -> bool:
    del request
    if (
        instance.family not in _SUPPORTED_FAMILIES
        or instance.matrix_kind != "sparse_uniform"
        or type(instance.matrix_row_weight) is not int
        or instance.matrix_row_weight <= 0
        or instance.secret_predicate_kind != "alphabet"
        or instance.secret_min_nonzero != 2
        or instance.secret_max_nonzero != 2
        or type(instance.error_max_abs) is not int
        or instance.error_max_abs < 0
    ):
        return False
    alphabet = frozenset(instance.secret_alphabet)
    return 0 in alphabet and bool(_nonzero_secret_values(instance))


def _public_detail(
    code: str,
    *,
    instance: ExactProblem,
    active_rows: int,
    support_count: int,
    candidate_count: int,
    tested_count: int,
) -> dict[str, object]:
    return {
        "code": code,
        "public_parameters": {
            "candidate_count": candidate_count,
            "error_bound": instance.error_max_abs,
            "m": instance.m,
            "n": instance.n,
            "q": instance.q,
            "row_count": active_rows,
            "row_weight": instance.matrix_row_weight or 0,
            "support_count": support_count,
            "tested_count": tested_count,
            "weight": 2,
        },
    }


def _active_supports(
    instance: ExactProblem,
    *,
    deadline: float,
) -> tuple[frozenset[int], ...]:
    supports: list[frozenset[int]] = []
    if len(instance.b) != instance.m:
        raise ValueError("public instance dimensions disagree")
    observed_rows = 0
    for row_index, row in enumerate(instance.iter_rows()):
        observed_rows = row_index + 1
        if time.monotonic() >= deadline:
            raise TimeoutError
        if row_index >= instance.m or len(row) != instance.n:
            raise ValueError("public instance dimensions disagree")
        if abs(_centered(instance.b[row_index], instance.q)) <= instance.error_max_abs:
            continue
        support = frozenset(
            index for index, coefficient in enumerate(row) if coefficient % instance.q
        )
        if not support:
            raise ValueError("active public row has empty support")
        supports.append(support)
    if observed_rows != instance.m:
        raise ValueError("public instance dimensions disagree")
    return tuple(supports)


def _hitting_pairs(
    active_supports: tuple[frozenset[int], ...],
    *,
    n: int,
) -> Iterable[tuple[int, int]]:
    if not active_supports:
        return
    anchor = min(active_supports, key=len)
    emitted: set[tuple[int, int]] = set()
    for first in sorted(anchor):
        remaining = tuple(support for support in active_supports if first not in support)
        if remaining:
            partners = min(remaining, key=len)
        else:
            partners = frozenset(range(n)) - {first}
        for second in sorted(partners):
            if second == first:
                continue
            if any(first not in support and second not in support for support in remaining):
                continue
            pair = (first, second) if first < second else (second, first)
            if pair in emitted:
                continue
            emitted.add(pair)
            yield pair


class SupportIncidenceRecovery(ValidatedExactSolver):
    solver_id = "support_incidence"

    def _solve(self, instance: ExactProblem, request: SolveRequest) -> SolveResult:
        started = time.monotonic()
        deadline = started + request.max_seconds
        if not applicability(instance, request):
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                detail={"code": "inapplicable_support_incidence"},
            )
        try:
            raw_cap = request.parameters.get("work_unit_cap", 100_000)
            if type(raw_cap) is not int or raw_cap <= 0:
                raise ValueError("work_unit_cap must be a positive integer")
            active = _active_supports(instance, deadline=deadline)
            values = _nonzero_secret_values(instance)
        except TimeoutError:
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                detail={
                    "reason": "time_cap",
                    "public_parameters": {
                        "cap": request.max_seconds,
                        "cap_unit": "seconds",
                        "max_seconds": request.max_seconds,
                    },
                },
            )
        except (AttributeError, TypeError, ValueError):
            return SolveResult.error(
                elapsed_seconds=time.monotonic() - started,
                work_units=0,
                detail={"code": "invalid_public_parameters"},
            )
        if not active:
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=instance.m,
                detail=_public_detail(
                    "insufficient_active_rows",
                    instance=instance,
                    active_rows=0,
                    support_count=0,
                    candidate_count=0,
                    tested_count=0,
                ),
            )

        support_count = 0
        candidate_count = 0
        tested_count = 0
        excluded_seen = False
        work_units = instance.m * (instance.matrix_row_weight or instance.n)
        for left, right in _hitting_pairs(active, n=instance.n):
            support_count += 1
            if support_count > raw_cap:
                return SolveResult.censored(
                    elapsed_seconds=time.monotonic() - started,
                    work_units=work_units,
                    detail={
                        "reason": "work_unit_cap",
                        "public_parameters": {
                            "cap": raw_cap,
                            "cap_unit": "work_units",
                            "work_unit_cap": raw_cap,
                        },
                    },
                )
            for first_value, second_value in itertools.product(values, repeat=2):
                if time.monotonic() >= deadline:
                    return SolveResult.censored(
                        elapsed_seconds=time.monotonic() - started,
                        work_units=work_units,
                        detail={
                            "reason": "time_cap",
                            "public_parameters": {
                                "cap": request.max_seconds,
                                "cap_unit": "seconds",
                                "max_seconds": request.max_seconds,
                            },
                        },
                    )
                candidate = [0] * instance.n
                candidate[left] = first_value
                candidate[right] = second_value
                secret = tuple(candidate)
                candidate_count += 1
                work_units += 1
                if request.exclude_secret is not None and secret == request.exclude_secret:
                    excluded_seen = True
                    continue
                tested_count += 1
                verdict = instance.validate_secret(secret)
                if getattr(verdict, "ok", None) is True:
                    return SolveResult.success(
                        secret=secret,
                        elapsed_seconds=time.monotonic() - started,
                        work_units=work_units,
                        detail=_public_detail(
                            "support_incidence_hitting_pair",
                            instance=instance,
                            active_rows=len(active),
                            support_count=support_count,
                            candidate_count=candidate_count,
                            tested_count=tested_count,
                        ),
                    )

        if excluded_seen:
            return SolveResult.censored(
                elapsed_seconds=time.monotonic() - started,
                work_units=work_units,
                detail={"code": "excluded_witness_requires_private_proof"},
            )
        return SolveResult.exhausted(
            elapsed_seconds=time.monotonic() - started,
            work_units=work_units,
            detail=_public_detail(
                "support_incidence_complete",
                instance=instance,
                active_rows=len(active),
                support_count=support_count,
                candidate_count=candidate_count,
                tested_count=tested_count,
            ),
        )
