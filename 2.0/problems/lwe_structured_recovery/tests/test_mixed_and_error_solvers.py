from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.solvers.api import ValidatedExactSolver, SolveRequest, SolveStatus
from tools.solvers.mixed_recovery import (
    BranchPlan,
    MixedFilterGreedy,
    applicability,
    exact_ordered_backtrack,
    mixed_branch_plan,
    score_coordinate_values,
)


def request() -> SolveRequest:
    return SolveRequest(
        seed=11,
        max_seconds=20.0,
        work_dir=Path("build/lwe-test"),
    )


def test_mixed_solver_uses_only_the_validated_solve_wrapper() -> None:
    assert issubclass(MixedFilterGreedy, ValidatedExactSolver)
    assert "solve" not in MixedFilterGreedy.__dict__
    assert callable(MixedFilterGreedy.__dict__.get("_solve"))
    assert callable(applicability)


def test_mixed_scores_all_values_but_greedy_margin_only_orders_them() -> None:
    scores = score_coordinate_values(
        rows=((1, 0), (1, 1), (1, -1)),
        rhs=(1, 1, 1),
        q=7,
        assignment={},
        coordinate=0,
        domain=(-1, 0, 1),
        max_abs=0,
    )
    assert {score.value for score in scores} == {-1, 0, 1}
    assert max(scores, key=lambda score: score.accepted_count).value == 1

    plan = mixed_branch_plan(
        domain=(-1, 0, 1), exact_candidate_sets=(), scores=scores
    )
    assert plan.values[0] == 1
    assert set(plan.values) == {-1, 0, 1}
    assert not plan.forced
    assert not plan.contradiction


def test_mixed_commits_only_an_exact_singleton_and_retains_ambiguity() -> None:
    scores = score_coordinate_values(
        rows=((1,),),
        rhs=(1,),
        q=7,
        assignment={},
        coordinate=0,
        domain=(-1, 0, 1),
        max_abs=1,
    )
    singleton = mixed_branch_plan(
        domain=(-1, 0, 1), exact_candidate_sets=((-1, 1), (1,)), scores=scores
    )
    assert singleton == BranchPlan(values=(1,), forced=True, contradiction=False)

    ambiguous = mixed_branch_plan(
        domain=(-1, 0, 1), exact_candidate_sets=((-1, 1), (-1, 1)), scores=scores
    )
    assert set(ambiguous.values) == {-1, 1}
    assert not ambiguous.forced

    contradiction = mixed_branch_plan(
        domain=(-1, 0, 1), exact_candidate_sets=((-1,), (1,)), scores=scores
    )
    assert contradiction.contradiction
    assert contradiction.values == ()


def test_mixed_exact_search_backtracks_after_greedy_first_candidate() -> None:
    seen: list[tuple[int, ...]] = []

    def branch_planner(
        _coordinate: int, _assignment, domain
    ) -> BranchPlan:
        return BranchPlan(tuple(reversed(domain)), forced=False, contradiction=False)

    def validator(secret: tuple[int, ...]) -> bool:
        seen.append(secret)
        return secret == (0, 0)

    outcome = exact_ordered_backtrack(
        domains=((0, 1), (0, 1)),
        branch_planner=branch_planner,
        coordinate_orderer=lambda unresolved, _assignment: unresolved,
        validator=validator,
        excluded=None,
        min_nonzero=0,
        max_nonzero=2,
        work_unit_cap=4,
    )
    assert outcome.secret == (0, 0)
    assert seen[0] == (1, 1)
    assert len(seen) == 4


def test_mixed_exact_search_rejects_success_after_validator_crosses_deadline(
    monkeypatch,
) -> None:
    crossed = False

    def validator(_candidate: tuple[int, ...]) -> bool:
        nonlocal crossed
        crossed = True
        return True

    monkeypatch.setattr(
        "tools.solvers.mixed_recovery.time.monotonic",
        lambda: 2.0 if crossed else 0.0,
    )
    outcome = exact_ordered_backtrack(
        domains=((0,),),
        branch_planner=lambda _coordinate, _assignment, domain: BranchPlan(
            tuple(domain), forced=True, contradiction=False
        ),
        coordinate_orderer=lambda unresolved, _assignment: unresolved,
        validator=validator,
        excluded=None,
        min_nonzero=0,
        max_nonzero=0,
        work_unit_cap=1,
        deadline=1.0,
    )

    assert outcome.secret is None
    assert not outcome.complete
    assert outcome.reason == "timeout"


def test_mixed_terminal_acceptance_rechecks_deadline(monkeypatch) -> None:
    after_validator = False
    post_checks = 0

    def validator(_candidate: tuple[int, ...]) -> bool:
        nonlocal after_validator
        after_validator = True
        return True

    def clock() -> float:
        nonlocal post_checks
        if not after_validator:
            return 0.0
        post_checks += 1
        return 0.0 if post_checks == 1 else 2.0

    monkeypatch.setattr("tools.solvers.mixed_recovery.time.monotonic", clock)
    outcome = exact_ordered_backtrack(
        domains=((0,),),
        branch_planner=lambda _coordinate, _assignment, domain: BranchPlan(
            tuple(domain), forced=True, contradiction=False
        ),
        coordinate_orderer=lambda unresolved, _assignment: unresolved,
        validator=validator,
        excluded=None,
        min_nonzero=0,
        max_nonzero=0,
        work_unit_cap=1,
        deadline=1.0,
    )
    assert outcome.secret is None
    assert outcome.reason == "timeout"


def test_mixed_exact_search_cap_is_censored_and_complete_domain_is_distinct() -> None:
    planner = lambda _coordinate, _assignment, domain: BranchPlan(
        tuple(domain), forced=False, contradiction=False
    )
    capped = exact_ordered_backtrack(
        domains=((0, 1), (0, 1)),
        branch_planner=planner,
        coordinate_orderer=lambda unresolved, _assignment: unresolved,
        validator=lambda _secret: False,
        excluded=None,
        min_nonzero=0,
        max_nonzero=2,
        work_unit_cap=3,
    )
    assert not capped.complete
    assert capped.reason == "work_unit_cap"

    exhaustive = exact_ordered_backtrack(
        domains=((0, 1), (0, 1)),
        branch_planner=planner,
        coordinate_orderer=lambda unresolved, _assignment: unresolved,
        validator=lambda _secret: False,
        excluded=None,
        min_nonzero=0,
        max_nonzero=2,
        work_unit_cap=4,
    )
    assert exhaustive.complete
    assert exhaustive.reason == "complete"

    memory_censored = exact_ordered_backtrack(
        domains=((0, 1),),
        branch_planner=planner,
        coordinate_orderer=lambda unresolved, _assignment: unresolved,
        validator=lambda _secret: False,
        excluded=None,
        min_nonzero=0,
        max_nonzero=1,
        work_unit_cap=2,
        memory_cap_bytes=1,
    )
    assert not memory_censored.complete
    assert memory_censored.reason == "memory_cap"


def test_mixed_exact_search_rejects_overlapping_branch_certificate_ranges() -> None:
    with pytest.raises(ValueError, match="duplicate branch"):
        exact_ordered_backtrack(
            domains=((0, 1),),
            branch_planner=lambda _coordinate, _assignment, _domain: BranchPlan(
                (0, 0, 1), forced=False, contradiction=False
            ),
            coordinate_orderer=lambda unresolved, _assignment: unresolved,
            validator=lambda _secret: False,
            excluded=None,
            min_nonzero=0,
            max_nonzero=1,
            work_unit_cap=3,
        )


@pytest.mark.parametrize(
    "plan",
    (
        BranchPlan((0,), forced=1, contradiction=False),
        BranchPlan((0,), forced=False, contradiction=1),
    ),
)
def test_mixed_exact_search_rejects_non_boolean_branch_flags(
    plan: BranchPlan,
) -> None:
    with pytest.raises(ValueError, match="exact booleans"):
        exact_ordered_backtrack(
            domains=((0,),),
            branch_planner=lambda _coordinate, _assignment, _domain: plan,
            coordinate_orderer=lambda unresolved, _assignment: unresolved,
            validator=lambda _secret: False,
            excluded=None,
            min_nonzero=0,
            max_nonzero=0,
            work_unit_cap=1,
        )


def test_mixed_exact_search_is_iterative_beyond_python_recursion_limit() -> None:
    n = sys.getrecursionlimit() + 25
    domains = ((0,),) * n

    outcome = exact_ordered_backtrack(
        domains=domains,
        branch_planner=lambda _coordinate, _assignment, domain: BranchPlan(
            tuple(domain), forced=True, contradiction=False
        ),
        coordinate_orderer=lambda unresolved, _assignment: unresolved,
        validator=lambda secret: secret == (0,) * n,
        excluded=None,
        min_nonzero=0,
        max_nonzero=0,
        work_unit_cap=1,
        memory_cap_bytes=16 * 1024 * 1024,
    )

    assert outcome.secret == (0,) * n
    assert outcome.work_units == 1
    assert outcome.reason == "success"


def test_mixed_applicability_requires_sparse_rows_and_small_ternary_domain() -> None:
    base = dict(
        family="MIX_SMALL_SPARSE",
        matrix_kind="sparse_small_alphabet",
        secret_predicate_kind="alphabet",
        secret_alphabet=(-1, 0, 1),
    )
    assert applicability(SimpleNamespace(**base))
    assert not applicability(SimpleNamespace(**{**base, "family": "MIX_DENSE_SMALL"}))
    assert not applicability(SimpleNamespace(**{**base, "matrix_kind": "uniform"}))
    assert not applicability(SimpleNamespace(**{**base, "secret_alphabet": (-2, 0, 2)}))


@pytest.mark.recovery
def test_mixed_filter_recovers(mixed_fixture) -> None:
    result = MixedFilterGreedy().solve(mixed_fixture, request())
    assert result.status is SolveStatus.SUCCESS
    assert mixed_fixture.validate_secret(result.secret).ok
