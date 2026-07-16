from __future__ import annotations

import hashlib
import inspect
import json
import math
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import tools.solvers.sparse_matrix as sparse_matrix_module
from tools.solvers.api import (
    CheckpointStore,
    ValidatedExactSolver,
    SolveRequest,
    SolveResult,
    SolveStatus,
    SolverContractError,
    scrub_result,
    validate_solve_result,
)
from tools.solvers.sparse_matrix import (
    DenseMinorRecovery,
    DomainAxis,
    GraphPeelingRecovery,
    RepeatedSupportRecovery,
    TraversalCutoff,
    build_complete_domain_certificate,
    certifying_cartesian_search,
    classify_leaf_intersection,
    classify_no_solution,
    dense_minor_applicability,
    enumerate_local_assignments,
    estimate_solver_state_bytes,
    find_dense_minor,
    group_repeated_rows,
    graph_peeling_applicability,
    iter_local_candidates,
    leaf_candidates,
    make_public_result_detail,
    peel_public_graph,
    rank_mod_prime,
    repeated_support_applicability,
    residuals_within_budget,
    search_assignment_product,
    search_local_completions,
    verify_complete_domain_certificate,
)


def request() -> SolveRequest:
    return SolveRequest(
        seed=11,
        max_seconds=20.0,
        work_dir=Path("build/lwe-test"),
    )


def test_sparse_matrix_solvers_use_only_the_validated_solve_wrapper() -> None:
    for solver_type in (
        RepeatedSupportRecovery,
        GraphPeelingRecovery,
        DenseMinorRecovery,
    ):
        assert issubclass(solver_type, ValidatedExactSolver)
        assert "solve" not in solver_type.__dict__
        assert callable(solver_type.__dict__.get("_solve"))
    assert callable(repeated_support_applicability)
    assert callable(graph_peeling_applicability)
    assert callable(dense_minor_applicability)


def test_ordinal_sampling_rejects_an_impossible_memory_budget_before_allocating() -> None:
    with pytest.raises(TraversalCutoff, match="memory_cap"):
        sparse_matrix_module._sample_unique_ordinals(
            total=10**30,
            count=10**12,
            seed=11,
            memory_cap_bytes=1_024,
        )


def test_repeated_support_fixture_realizes_repeated_public_groups(
    repeated_support_fixture,
) -> None:
    rows = repeated_support_fixture.materialize_rows()
    groups = group_repeated_rows(rows, q=repeated_support_fixture.q)

    assert groups
    assert all(len(group.row_indices) >= 2 for group in groups)
    assert repeated_support_applicability(repeated_support_fixture)


def test_graph_peeling_prioritizes_the_public_peel_assignment() -> None:
    class Problem:
        n = 3
        m = 2
        q = 5
        b = (1, 2)
        matrix_kind = "sparse_small_alphabet"
        matrix_row_weight = 2
        secret_predicate_kind = "alphabet"
        secret_alphabet = (0, 1)
        error_max_abs = 0
        error_max_l1 = 0
        error_max_l2_squared = 0
        error_max_nonzero = 0
        rows = ((1, 0, 0), (0, 1, 1))

        def iter_rows(self):
            return iter(self.rows)

        def validate_secret(self, candidate):
            return SimpleNamespace(ok=tuple(candidate) == (1, 1, 1))

    result = GraphPeelingRecovery()._solve(Problem(), request())

    assert result.status is SolveStatus.SUCCESS
    assert result.secret == (1, 1, 1)
    assert result.work_units == 5


def test_graph_peeling_certifies_no_witness_in_peel_prioritized_domains() -> None:
    class Problem:
        n = 1
        m = 1
        q = 5
        b = (1,)
        matrix_kind = "sparse_small_alphabet"
        matrix_row_weight = 1
        secret_predicate_kind = "alphabet"
        secret_alphabet = (0, 1)
        error_max_abs = 0
        error_max_l1 = 0
        error_max_l2_squared = 0
        error_max_nonzero = 0
        rows = ((1,),)

        def iter_rows(self):
            return iter(self.rows)

        def validate_secret(self, _candidate):
            return SimpleNamespace(ok=False)

    result = GraphPeelingRecovery()._solve(Problem(), request())

    assert result.status is SolveStatus.EXHAUSTED
    assert result.detail["code"] == "complete_domain"


def test_graph_peeling_censors_when_prioritized_witness_is_excluded() -> None:
    class Problem:
        n = 1
        m = 1
        q = 5
        b = (1,)
        matrix_kind = "sparse_small_alphabet"
        matrix_row_weight = 1
        secret_predicate_kind = "alphabet"
        secret_alphabet = (0, 1)
        error_max_abs = 0
        error_max_l1 = 0
        error_max_l2_squared = 0
        error_max_nonzero = 0
        rows = ((1,),)

        def iter_rows(self):
            return iter(self.rows)

        def validate_secret(self, candidate):
            return SimpleNamespace(ok=tuple(candidate) == (1,))

    result = GraphPeelingRecovery()._solve(
        Problem(),
        SolveRequest(
            seed=11,
            max_seconds=20.0,
            work_dir=Path("build/lwe-test"),
            exclude_secret=(1,),
        ),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.detail["code"] == "excluded_witness_requires_private_proof"


def test_repeated_support_retains_every_locally_compatible_assignment() -> None:
    rows = ((1, 1, 0), (1, 1, 0), (0, 0, 1))
    groups = group_repeated_rows(rows, q=5)
    assert len(groups) == 1
    outcome = enumerate_local_assignments(
        groups[0],
        rows=rows,
        rhs=(0, 1, 4),
        domains=((0, 1, 2, 3, 4),) * 3,
        q=5,
        max_abs=1,
        max_l1=2,
        max_l2_squared=2,
        max_nonzero=2,
        assignment_budget=25,
    )
    assert outcome.complete
    assert outcome.tested == 25
    assert len(outcome.assignments) > 1
    assert {tuple(sorted(candidate.items())) for candidate in outcome.assignments} == {
        ((0, 0), (1, 0)),
        ((0, 0), (1, 1)),
        ((0, 1), (1, 0)),
        ((0, 1), (1, 4)),
        ((0, 2), (1, 3)),
        ((0, 2), (1, 4)),
        ((0, 3), (1, 2)),
        ((0, 3), (1, 3)),
        ((0, 4), (1, 1)),
        ((0, 4), (1, 2)),
    }

    capped = enumerate_local_assignments(
        groups[0],
        rows=rows,
        rhs=(0, 1, 4),
        domains=((0, 1, 2, 3, 4),) * 3,
        q=5,
        max_abs=1,
        max_l1=2,
        max_l2_squared=2,
        max_nonzero=2,
        assignment_budget=24,
    )
    assert capped.tested == 24
    assert not capped.complete


def test_repeated_row_grouping_accounts_for_retained_public_rows() -> None:
    rows = (tuple([0] * 10_000), tuple([0] * 10_000))
    memory_cap = 5_000
    assert estimate_solver_state_bytes(rows) > memory_cap

    with pytest.raises(TraversalCutoff, match="memory_cap"):
        group_repeated_rows(rows, q=17, memory_cap_bytes=memory_cap)


def test_repeated_row_grouping_checks_deadline_inside_each_row(monkeypatch) -> None:
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(
        "tools.solvers.sparse_matrix.time.monotonic",
        lambda: next(ticks, 2.0),
    )

    with pytest.raises(TraversalCutoff, match="timeout"):
        group_repeated_rows(
            (tuple([0] * 10_000),),
            q=17,
            deadline=1.0,
        )


def test_repeated_support_global_merge_backtracks_and_covers_uncovered_coordinates() -> None:
    seen: list[tuple[int, ...]] = []

    def validator(secret: tuple[int, ...]) -> bool:
        seen.append(secret)
        return secret == (1, 1, 2)

    outcome = search_assignment_product(
        n=3,
        assignment_groups=(
            ({0: 0}, {0: 1}),
            ({1: 0}, {1: 1}),
        ),
        uncovered_domains={2: (0, 1, 2)},
        validator=validator,
        excluded=None,
        work_unit_cap=100,
    )
    assert outcome.secret == (1, 1, 2)
    assert outcome.complete is False
    assert seen[-1] == (1, 1, 2)
    assert len(seen) > 1

    conflict = search_assignment_product(
        n=1,
        assignment_groups=(({0: 0},), ({0: 1},)),
        uncovered_domains={},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=3,
    )
    assert conflict.secret is None
    assert conflict.complete
    assert conflict.reason == "complete"


def test_repeated_support_budget_cutoff_is_not_complete() -> None:
    outcome = search_assignment_product(
        n=2,
        assignment_groups=(),
        uncovered_domains={0: (0, 1), 1: (0, 1)},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=3,
    )
    assert outcome.secret is None
    assert not outcome.complete
    assert outcome.reason == "work_unit_cap"
    assert classify_no_solution(complete_domain=False, invariant_ok=True) is SolveStatus.CENSORED
    domains = ((0, 1),)
    traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=2,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    certificate = build_complete_domain_certificate(domains, traversal)
    assert (
        classify_no_solution(
            complete_domain=True,
            invariant_ok=True,
            certificate=certificate,
            domains=domains,
            validator=lambda _secret: False,
        )
        is SolveStatus.EXHAUSTED
    )
    assert classify_no_solution(complete_domain=True, invariant_ok=True) is SolveStatus.ERROR
    assert classify_no_solution(complete_domain=True, invariant_ok=False) is SolveStatus.ERROR

    timed_out = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0, 1)},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=2,
        deadline=0.0,
    )
    assert not timed_out.complete
    assert timed_out.reason == "timeout"

    memory_censored = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0, 1)},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=2,
        memory_cap_bytes=1,
    )
    assert not memory_censored.complete
    assert memory_censored.reason == "memory_cap"


def test_residual_global_budget_boundaries() -> None:
    assert residuals_within_budget(
        (1, -1, 0), max_abs=1, max_l1=2, max_l2_squared=2, max_nonzero=2
    )
    assert not residuals_within_budget(
        (2, 0), max_abs=1, max_l1=None, max_l2_squared=None, max_nonzero=None
    )
    assert not residuals_within_budget(
        (1, -1, 1), max_abs=1, max_l1=2, max_l2_squared=None, max_nonzero=None
    )
    assert not residuals_within_budget(
        (1, -1, 1), max_abs=1, max_l1=None, max_l2_squared=2, max_nonzero=None
    )
    assert not residuals_within_budget(
        (1, -1, 1), max_abs=1, max_l1=None, max_l2_squared=None, max_nonzero=2
    )


def test_complete_domain_certificate_rejects_gap_overlap_and_censor() -> None:
    domains = ((0, 1, 2, 3), (0, 1, 2))
    traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=12,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    valid = build_complete_domain_certificate(domains, traversal)
    with pytest.raises(ValueError, match="complete bound domain"):
        build_complete_domain_certificate(
            domains,
            replace(traversal, work_units=traversal.work_units - 1),
        )
    assert verify_complete_domain_certificate(
        valid,
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
    )
    gap_axis = replace(valid.axes[0], ranges=((0, 1), (2, 4)))
    assert not verify_complete_domain_certificate(
        replace(valid, axes=(gap_axis, valid.axes[1])),
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
    )
    overlap_axis = replace(valid.axes[0], ranges=((0, 3), (2, 4)))
    assert not verify_complete_domain_certificate(
        replace(valid, axes=(overlap_axis, valid.axes[1])),
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
    )
    assert not verify_complete_domain_certificate(
        replace(valid, censored=True),
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
    )
    assert not verify_complete_domain_certificate(
        replace(
            valid,
            traversal_ranges=((0, 1), (2, 12), (1, 2)),
        ),
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
    )


def test_certificate_binds_canonical_domains_and_observed_event_chain() -> None:
    domains = ((0, 1), (-1, 0, 1))
    traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=6,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    certificate = build_complete_domain_certificate(domains, traversal)
    assert verify_complete_domain_certificate(
        certificate,
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
    )
    assert not verify_complete_domain_certificate(
        certificate,
        domains=((0, 1), (0, 1, 2)),
        validator=lambda _secret: False,
        excluded=None,
    )
    assert not verify_complete_domain_certificate(
        replace(certificate, event_chain="0" * 64),
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
    )
    forged_full_range = replace(
        certificate,
        traversal_ranges=((0, 6),),
        candidate_count=6,
        event_chain="f" * 64,
    )
    assert not verify_complete_domain_certificate(
        forged_full_range,
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
    )
    reordered_axis = replace(certificate.axes[0], values=(1, 0))
    assert not verify_complete_domain_certificate(
        replace(certificate, axes=(reordered_axis, certificate.axes[1])),
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
    )

    singleton_domains = ((0,),)
    singleton_traversal = certifying_cartesian_search(
        domains=singleton_domains,
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=1,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    singleton_certificate = build_complete_domain_certificate(
        singleton_domains, singleton_traversal
    )
    assert not verify_complete_domain_certificate(
        replace(singleton_certificate, candidate_count=True),
        domains=singleton_domains,
        validator=lambda _secret: False,
    )
    with pytest.raises(ValueError, match="complete bound domain"):
        build_complete_domain_certificate(
            singleton_domains,
            replace(singleton_traversal, work_units=True),
        )


def test_complete_domain_certificate_is_independent_of_private_exclusion() -> None:
    domains = ((0, 1),)
    excluded_traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda candidate: candidate == (0,),
        excluded=(0,),
        work_unit_cap=2,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    assert not excluded_traversal.complete
    assert excluded_traversal.reason == "excluded_witness_requires_private_proof"
    ordinary_traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda _candidate: False,
        excluded=None,
        work_unit_cap=2,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )

    ordinary_certificate = build_complete_domain_certificate(
        domains, ordinary_traversal
    )
    assert not verify_complete_domain_certificate(
        ordinary_certificate,
        domains=domains,
        validator=lambda candidate: candidate == (0,),
        excluded=(0,),
    )


def test_assignment_search_rejects_success_after_validator_crosses_deadline(
    monkeypatch,
) -> None:
    crossed = False

    def validator(_candidate: tuple[int, ...]) -> bool:
        nonlocal crossed
        crossed = True
        return True

    monkeypatch.setattr(
        "tools.solvers.sparse_matrix.time.monotonic",
        lambda: 2.0 if crossed else 0.0,
    )
    outcome = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0,)},
        validator=validator,
        excluded=None,
        work_unit_cap=1,
        deadline=1.0,
    )

    assert outcome.secret is None
    assert not outcome.complete
    assert outcome.reason == "timeout"


def test_terminal_acceptance_rechecks_deadline_after_post_validator_guard(
    monkeypatch,
) -> None:
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

    monkeypatch.setattr("tools.solvers.sparse_matrix.time.monotonic", clock)
    outcome = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0,)},
        validator=validator,
        excluded=None,
        work_unit_cap=1,
        deadline=1.0,
    )
    assert outcome.secret is None
    assert outcome.reason == "timeout"


def test_certifying_search_rejects_success_after_validator_crosses_deadline(
    monkeypatch,
) -> None:
    crossed = False

    def validator(_candidate: tuple[int, ...]) -> bool:
        nonlocal crossed
        crossed = True
        return True

    monkeypatch.setattr(
        "tools.solvers.sparse_matrix.time.monotonic",
        lambda: 2.0 if crossed else 0.0,
    )
    outcome = certifying_cartesian_search(
        domains=((0,),),
        validator=validator,
        excluded=None,
        work_unit_cap=1,
        deadline=1.0,
        memory_cap_bytes=1_000_000,
    )

    assert outcome.secret is None
    assert not outcome.complete
    assert outcome.reason == "timeout"


def test_certifying_terminal_event_rechecks_deadline(monkeypatch) -> None:
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

    monkeypatch.setattr("tools.solvers.sparse_matrix.time.monotonic", clock)
    outcome = certifying_cartesian_search(
        domains=((0,),),
        validator=validator,
        excluded=None,
        work_unit_cap=1,
        deadline=1.0,
        memory_cap_bytes=1_000_000,
    )
    assert outcome.secret is None
    assert outcome.reason == "timeout"


def test_certificate_verifier_never_accepts_after_validator_crosses_deadline(
    monkeypatch,
) -> None:
    domains = ((0,),)
    traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda _candidate: False,
        excluded=None,
        work_unit_cap=1,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    certificate = build_complete_domain_certificate(domains, traversal)
    crossed = False

    def validator(_candidate: tuple[int, ...]) -> bool:
        nonlocal crossed
        crossed = True
        return False

    monkeypatch.setattr(
        "tools.solvers.sparse_matrix.time.monotonic",
        lambda: 2.0 if crossed else 0.0,
    )
    with pytest.raises(TraversalCutoff, match="timeout"):
        verify_complete_domain_certificate(
            certificate,
            domains=domains,
            validator=validator,
            deadline=1.0,
        )


def test_certificate_verifier_rechecks_deadline_before_true(monkeypatch) -> None:
    domains = ((0,),)
    traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda _candidate: False,
        excluded=None,
        work_unit_cap=1,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    certificate = build_complete_domain_certificate(domains, traversal)
    after_validator = False
    post_checks = 0

    def validator(_candidate: tuple[int, ...]) -> bool:
        nonlocal after_validator
        after_validator = True
        return False

    def clock() -> float:
        nonlocal post_checks
        if not after_validator:
            return 0.0
        post_checks += 1
        return 0.0 if post_checks == 1 else 2.0

    monkeypatch.setattr("tools.solvers.sparse_matrix.time.monotonic", clock)
    with pytest.raises(TraversalCutoff, match="timeout"):
        verify_complete_domain_certificate(
            certificate,
            domains=domains,
            validator=validator,
            deadline=1.0,
        )


def test_certificate_verifier_obeys_its_reserved_work_budget() -> None:
    domains = ((0, 1),)
    traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda _candidate: False,
        excluded=None,
        work_unit_cap=2,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    certificate = build_complete_domain_certificate(domains, traversal)
    seen = 0

    def validator(_candidate: tuple[int, ...]) -> bool:
        nonlocal seen
        seen += 1
        return False

    with pytest.raises(TraversalCutoff, match="work_unit_cap"):
        verify_complete_domain_certificate(
            certificate,
            domains=domains,
            validator=validator,
            work_unit_cap=1,
        )
    assert seen == 1


def test_repeated_product_counts_incompatible_branches_and_censors_promptly() -> None:
    conflicts = ({0: 1},) * 200_000
    started = time.monotonic()
    outcome = search_assignment_product(
        n=1,
        assignment_groups=(({0: 0},), conflicts),
        uncovered_domains={},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=1,
        deadline=started + 0.25,
        memory_cap_bytes=64 * 1024 * 1024,
    )
    assert not outcome.complete
    assert outcome.reason == "work_unit_cap"
    assert outcome.work_units == 1
    assert time.monotonic() - started < 0.25


def test_state_size_estimator_is_iterative_and_cap_aware() -> None:
    value: object = 0
    for _ in range(20_000):
        value = (value,)
    assert estimate_solver_state_bytes(value, cap=256) > 256


def test_state_size_estimator_traverses_slots_dataclass_fields() -> None:
    axis = DomainAxis(
        name="large-axis",
        domain_size=10_000,
        ranges=((0, 10_000),),
        values=tuple(range(10_000)),
        domain_digest="a" * 64,
    )

    assert estimate_solver_state_bytes(axis, cap=1_024) > 1_024


def test_certificate_verifier_accounts_for_slots_dataclass_state() -> None:
    domains = ((0,),)
    traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda _candidate: False,
        excluded=None,
        work_unit_cap=1,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    certificate = build_complete_domain_certificate(domains, traversal)
    memory_cap = (
        estimate_solver_state_bytes(domains)
        + estimate_solver_state_bytes((0,))
    )
    assert estimate_solver_state_bytes((domains, certificate)) > memory_cap

    with pytest.raises(TraversalCutoff, match="memory_cap"):
        verify_complete_domain_certificate(
            certificate,
            domains=domains,
            validator=lambda _candidate: False,
            memory_cap_bytes=memory_cap,
        )


def test_certifying_search_accounts_for_retained_event_chain_and_hash_transients() -> None:
    domains = ((0,),)
    memory_cap = 600
    assert estimate_solver_state_bytes((domains, (0,))) < memory_cap
    seen: list[tuple[int, ...]] = []

    outcome = certifying_cartesian_search(
        domains=domains,
        validator=lambda candidate: seen.append(candidate) or False,
        excluded=None,
        work_unit_cap=1,
        deadline=None,
        memory_cap_bytes=memory_cap,
    )

    assert not outcome.complete
    assert outcome.reason == "memory_cap"
    assert seen == [(0,)]


def test_event_chain_uses_fixed_schema_streaming_without_hidden_generators() -> None:
    source = inspect.getsource(sparse_matrix_module._advance_event_chain)
    assert ".iterencode(" not in source
    chain = "a" * 64
    candidate = (-1, 0, 1)
    payload = {
        "candidate": list(candidate),
        "ordinal": 7,
        "outcome": "not_returned",
        "previous": chain,
    }
    expected = hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    ).hexdigest()

    assert (
        sparse_matrix_module._advance_event_chain(
            chain,
            ordinal=7,
            candidate=candidate,
            outcome="not_returned",
            memory_cap_bytes=1_280,
        )
        == expected
    )


def test_certificate_verifier_accounts_for_replay_event_hash_transients() -> None:
    domains = ((0,),)
    traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda _candidate: False,
        excluded=None,
        work_unit_cap=1,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    certificate = build_complete_domain_certificate(domains, traversal)
    memory_cap = 1_300
    assert estimate_solver_state_bytes((certificate, domains)) < memory_cap
    seen: list[tuple[int, ...]] = []

    with pytest.raises(TraversalCutoff, match="memory_cap"):
        verify_complete_domain_certificate(
            certificate,
            domains=domains,
            validator=lambda candidate: seen.append(candidate) or False,
            memory_cap_bytes=memory_cap,
        )
    assert seen == []


def test_repeated_product_accounts_for_all_retained_candidate_memory() -> None:
    groups = (tuple({0: value} for value in range(1_000)),)
    memory_cap = 10_000
    assert estimate_solver_state_bytes(groups) > memory_cap

    outcome = search_assignment_product(
        n=1,
        assignment_groups=groups,
        uncovered_domains={},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=3_000,
        memory_cap_bytes=memory_cap,
    )
    assert not outcome.complete
    assert outcome.reason == "memory_cap"
    assert outcome.work_units == 0


def _task5_checkpoint_store(tmp_path: Path) -> CheckpointStore:
    return CheckpointStore(
        work_dir=tmp_path,
        solver_id="repeated_support",
        solver_revision="task5-repeated-v1",
        instance_digest="a" * 64,
        seed=11,
    )


def test_repeated_product_checkpoint_resume_matches_uninterrupted(tmp_path: Path) -> None:
    groups = (({0: 0}, {0: 1}),)
    uncovered = {1: (0, 1, 2)}
    uninterrupted = search_assignment_product(
        n=2,
        assignment_groups=groups,
        uncovered_domains=uncovered,
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=100,
        checkpoint_every_work_units=2,
    )
    store = _task5_checkpoint_store(tmp_path)
    partial = search_assignment_product(
        n=2,
        assignment_groups=groups,
        uncovered_domains=uncovered,
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=5,
        checkpoint_store=store,
        checkpoint_every_work_units=2,
    )
    assert not partial.complete
    assert partial.reason == "work_unit_cap"
    path = store.default_path
    assert path.is_file()
    partial_state = store.load(path)
    assert partial_state is not None
    partial_next = partial_state["next_ordinal"]
    assert type(partial_next) is int
    assert 0 <= partial_next < 6
    assert partial_state["covered_ranges"] == ((0, partial_next),)
    resumed = search_assignment_product(
        n=2,
        assignment_groups=groups,
        uncovered_domains=uncovered,
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=100,
        checkpoint_store=store,
        resume_checkpoint=path,
        checkpoint_every_work_units=2,
    )
    assert resumed.complete == uninterrupted.complete
    assert resumed.reason == uninterrupted.reason == "complete"
    assert resumed.traversal_ranges == uninterrupted.traversal_ranges
    resumed_state = store.load(path)
    assert resumed_state is not None
    assert resumed_state["next_ordinal"] == 6
    assert resumed_state["covered_ranges"] == ((0, 6),)


def test_repeated_product_crash_after_durable_save_revalidates_accepted_candidate(
    tmp_path: Path,
) -> None:
    store = _task5_checkpoint_store(tmp_path)
    partial = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0, 1)},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=1,
        checkpoint_store=store,
        checkpoint_every_work_units=1,
    )
    assert partial.reason == "work_unit_cap"

    class SimulatedInterruption(RuntimeError):
        pass

    class InterruptAfterDurableSave:
        def load(self, path: Path | None = None):
            return store.load(path)

        def save(
            self,
            state,
            *,
            work_units: int,
            path: Path | None = None,
        ) -> Path:
            durable_path = store.save(
                state,
                work_units=work_units,
                path=path,
            )
            raise SimulatedInterruption("crash after durable checkpoint save")

    with pytest.raises(SimulatedInterruption, match="durable checkpoint"):
        search_assignment_product(
            n=1,
            assignment_groups=(),
            uncovered_domains={0: (0, 1)},
            validator=lambda candidate: candidate == (1,),
            excluded=None,
            work_unit_cap=2,
            checkpoint_store=InterruptAfterDurableSave(),
            resume_checkpoint=store.default_path,
            checkpoint_every_work_units=1,
        )

    interrupted_state = store.load(store.default_path)
    assert interrupted_state is not None
    assert interrupted_state["next_ordinal"] == 1
    resumed = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0, 1)},
        validator=lambda candidate: candidate == (1,),
        excluded=None,
        work_unit_cap=2,
        checkpoint_store=store,
        resume_checkpoint=store.default_path,
        checkpoint_every_work_units=1,
    )
    assert resumed.secret == (1,)
    assert resumed.reason == "success"


@pytest.mark.parametrize("forged_work_units", [0, 2], ids=("regressed", "advanced"))
def test_repeated_checkpoint_binds_work_units_to_ordinal_coverage(
    tmp_path: Path,
    forged_work_units: int,
) -> None:
    store = _task5_checkpoint_store(tmp_path)
    partial = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0, 1)},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=1,
        checkpoint_store=store,
        checkpoint_every_work_units=1,
    )
    assert not partial.complete
    state = store.load(store.default_path)
    assert state is not None
    assert state["work_units"] == state["next_ordinal"] == 1

    forged = dict(state)
    forged["work_units"] = forged_work_units
    forged_path = tmp_path / f"forged-{forged_work_units}.checkpoint.json"
    store.save(
        forged,
        work_units=forged_work_units,
        path=forged_path,
    )
    with pytest.raises(SolverContractError, match="work units"):
        search_assignment_product(
            n=1,
            assignment_groups=(),
            uncovered_domains={0: (0, 1)},
            validator=lambda _secret: False,
            excluded=None,
            work_unit_cap=2,
            checkpoint_store=store,
            resume_checkpoint=forged_path,
            checkpoint_every_work_units=1,
        )


def test_repeated_checkpoint_rejects_search_mismatch_and_corruption(
    tmp_path: Path,
) -> None:
    store = _task5_checkpoint_store(tmp_path)
    partial = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0, 1)},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=1,
        checkpoint_store=store,
        checkpoint_every_work_units=1,
    )
    assert not partial.complete
    path = store.default_path
    with pytest.raises(SolverContractError, match="search binding"):
        search_assignment_product(
            n=1,
            assignment_groups=(),
            uncovered_domains={0: (0, 1, 2)},
            validator=lambda _secret: False,
            excluded=None,
            work_unit_cap=100,
            checkpoint_store=store,
            resume_checkpoint=path,
            checkpoint_every_work_units=1,
        )
    path.write_text("not-json", encoding="ascii")
    with pytest.raises(SolverContractError, match="checkpoint"):
        search_assignment_product(
            n=1,
            assignment_groups=(),
            uncovered_domains={0: (0, 1)},
            validator=lambda _secret: False,
            excluded=None,
            work_unit_cap=100,
            checkpoint_store=store,
            resume_checkpoint=path,
            checkpoint_every_work_units=1,
        )


@pytest.mark.parametrize(
    ("field", "forged_value", "expected_error"),
    [
        ("combination_count", True, "search state"),
        ("covered_ranges", ((False, True),), "covered ranges"),
    ],
)
def test_repeated_checkpoint_rejects_bool_typed_scalar_and_range_forgery(
    tmp_path: Path,
    field: str,
    forged_value: object,
    expected_error: str,
) -> None:
    store = _task5_checkpoint_store(tmp_path)
    partial = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0,)},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=0,
        checkpoint_store=store,
        checkpoint_every_work_units=1,
    )
    assert not partial.complete
    state = store.load(store.default_path)
    assert state is not None
    forged = dict(state)
    forged[field] = forged_value
    forged_path = tmp_path / f"bool-{field}.checkpoint.json"
    store.save(forged, work_units=0, path=forged_path)

    with pytest.raises(SolverContractError, match=expected_error):
        search_assignment_product(
            n=1,
            assignment_groups=(),
            uncovered_domains={0: (0,)},
            validator=lambda _secret: False,
            excluded=None,
            work_unit_cap=1,
            checkpoint_store=store,
            resume_checkpoint=forged_path,
            checkpoint_every_work_units=1,
        )


def test_repeated_checkpoint_rejects_changed_exclusion(tmp_path: Path) -> None:
    store = _task5_checkpoint_store(tmp_path)
    partial = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0, 1)},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=1,
        checkpoint_store=store,
        checkpoint_every_work_units=1,
    )
    assert not partial.complete

    with pytest.raises(SolverContractError, match="search binding"):
        search_assignment_product(
            n=1,
            assignment_groups=(),
            uncovered_domains={0: (0, 1)},
            validator=lambda _secret: False,
            excluded=(0,),
            work_unit_cap=100,
            checkpoint_store=store,
            resume_checkpoint=store.default_path,
            checkpoint_every_work_units=1,
        )


@pytest.mark.parametrize(
    "forged_ranges",
    [
        ((0, 2),),
        ((0, 1), (2, 3)),
        (),
    ],
    ids=("forged-forward", "gapped", "regressed"),
)
def test_repeated_checkpoint_rejects_forged_covered_ranges(
    tmp_path: Path,
    forged_ranges: tuple[tuple[int, int], ...],
) -> None:
    store = _task5_checkpoint_store(tmp_path)
    partial = search_assignment_product(
        n=1,
        assignment_groups=(),
        uncovered_domains={0: (0, 1)},
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=1,
        checkpoint_store=store,
        checkpoint_every_work_units=1,
    )
    assert not partial.complete
    state = store.load(store.default_path)
    assert state is not None
    assert state["next_ordinal"] == 1
    forged = dict(state)
    forged["covered_ranges"] = forged_ranges
    work_units = state["work_units"]
    assert type(work_units) is int
    store.save(forged, work_units=work_units, path=store.default_path)

    with pytest.raises(SolverContractError, match="covered ranges"):
        search_assignment_product(
            n=1,
            assignment_groups=(),
            uncovered_domains={0: (0, 1)},
            validator=lambda _secret: False,
            excluded=None,
            work_unit_cap=100,
            checkpoint_store=store,
            resume_checkpoint=store.default_path,
            checkpoint_every_work_units=1,
        )


def test_certifying_cartesian_search_records_exact_ordered_branch_coverage() -> None:
    complete = certifying_cartesian_search(
        domains=((0, 1), (0, 1, 2)),
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=6,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    assert complete.complete
    assert complete.traversal_ranges == ((0, 6),)

    memory_censored = certifying_cartesian_search(
        domains=((0, 1),),
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=2,
        deadline=None,
        memory_cap_bytes=1,
    )
    assert not memory_censored.complete
    assert memory_censored.reason == "memory_cap"


def test_graph_peeling_commits_only_singleton_exact_intersections() -> None:
    singleton = classify_leaf_intersection(({0, 1}, {1, 2}), votes={0: 100, 1: 1})
    assert singleton.kind == "singleton"
    assert singleton.values == (1,)

    ambiguous = classify_leaf_intersection(({0, 1}, {0, 1}), votes={0: 100, 1: 1})
    assert ambiguous.kind == "ambiguous"
    assert ambiguous.values == (0, 1)

    contradiction = classify_leaf_intersection(({0}, {1}), votes={0: 100})
    assert contradiction.kind == "contradiction"
    assert contradiction.values == ()


def test_leaf_candidates_use_public_error_predicate_and_centered_residues() -> None:
    assert leaf_candidates(
        coefficient=1,
        adjusted_rhs=0,
        q=5,
        domain=(0, 1, 4),
        max_abs=1,
        max_l1=1,
        max_l2_squared=1,
        max_nonzero=1,
    ) == (0, 1, 4)
    assert leaf_candidates(
        coefficient=2,
        adjusted_rhs=0,
        q=5,
        domain=(0, 1, 2, 3, 4),
        max_abs=0,
        max_l1=None,
        max_l2_squared=None,
        max_nonzero=None,
    ) == (0,)


def test_graph_peeling_reports_stall_without_guessing() -> None:
    state = peel_public_graph(
        rows=((1, 1), (1, 2)),
        rhs=(0, 0),
        q=5,
        domains=((0, 1), (0, 1)),
        max_abs=0,
        max_l1=None,
        max_l2_squared=None,
        max_nonzero=None,
    )
    assert state.kind == "stalled"
    assert state.assignments == ()
    assert state.unresolved == (0, 1)

    complete = peel_public_graph(
        rows=((1, 0), (0, 1)),
        rhs=(1, 0),
        q=5,
        domains=((0, 1), (0, 1)),
        max_abs=0,
        max_l1=0,
        max_l2_squared=0,
        max_nonzero=0,
    )
    assert complete.kind == "complete"
    assert complete.assignments == ((0, 1), (1, 0))

    contradiction = peel_public_graph(
        rows=((1,), (1,)),
        rhs=(0, 1),
        q=5,
        domains=((0,),),
        max_abs=0,
        max_l1=0,
        max_l2_squared=0,
        max_nonzero=0,
    )
    assert contradiction.kind == "contradiction"


def test_sparse_matrix_applicability_is_fail_closed() -> None:
    repeated = SimpleNamespace(
        matrix_kind="sparse_uniform",
        q=5,
        materialize_rows=lambda: ((1, 0), (1, 0), (0, 1)),
    )
    assert repeated_support_applicability(repeated)
    assert not repeated_support_applicability(
        SimpleNamespace(**{**repeated.__dict__, "materialize_rows": lambda: ((1, 0), (0, 1))})
    )

    graph = SimpleNamespace(matrix_kind="sparse_small_alphabet", matrix_row_weight=2)
    assert graph_peeling_applicability(graph)
    assert not graph_peeling_applicability(
        SimpleNamespace(matrix_kind="sparse_uniform", matrix_row_weight=2)
    )


def test_dense_minor_applicability_requires_prime_and_full_column_rank() -> None:
    rows = ((1, 0, 0), (0, 1, 0), (1, 1, 0), (0, 0, 1))
    minor = find_dense_minor(rows, q=7, r=2)
    assert minor is not None
    assert minor.coordinates == (0, 1)
    assert minor.row_indices == (0, 1, 2)
    induced = tuple(
        tuple(rows[i][j] for j in minor.coordinates) for i in minor.row_indices
    )
    assert rank_mod_prime(induced, 7) == 2
    assert find_dense_minor(rows, q=8, r=2) is None
    assert find_dense_minor(((1, 0), (2, 0), (3, 0)), q=7, r=2) is None
    assert find_dense_minor(((1, 0), (0, 1)), q=7, r=2) is None


def test_dense_minor_accounts_for_contained_and_induced_growth_before_rank() -> None:
    rows = ((1, 0, 0), (0, 1, 0), (1, 1, 0), (0, 0, 1))
    memory_cap = 1_400
    assert estimate_solver_state_bytes(rows) < memory_cap

    with pytest.raises(TraversalCutoff, match="memory_cap"):
        find_dense_minor(
            rows,
            q=7,
            r=2,
            memory_cap_bytes=memory_cap,
        )


def test_rank_mod_prime_accounts_for_live_replacement_row_growth() -> None:
    width = 20
    matrix = tuple(
        tuple(1 if row == column else 0 for column in range(width))
        for row in range(width)
    )
    work: list[list[int]] = []
    for row in matrix:
        reduced_row: list[int] = []
        for value in row:
            reduced_row.append(value % 101)
        work.append(reduced_row)
    normalized: list[int] = []
    for value in work[0]:
        normalized.append(value)
    memory_cap = estimate_solver_state_bytes((matrix, work))
    assert estimate_solver_state_bytes((matrix, work, normalized)) > memory_cap

    with pytest.raises(TraversalCutoff, match="memory_cap"):
        rank_mod_prime(matrix, 101, memory_cap_bytes=memory_cap)


def test_dense_minor_applicability_checks_public_instance_conditions() -> None:
    base = dict(
        matrix_kind="sparse_uniform",
        matrix_row_weight=2,
        n=3,
        m=4,
        q=7,
        materialize_rows=lambda: ((1, 0, 0), (0, 1, 0), (1, 1, 0), (0, 0, 1)),
    )
    assert dense_minor_applicability(SimpleNamespace(**base), None)
    assert not dense_minor_applicability(SimpleNamespace(**{**base, "q": 8}), None)
    assert not dense_minor_applicability(SimpleNamespace(**{**base, "matrix_row_weight": 0}), None)


def test_dense_minor_applicability_is_bounded_on_production_shape(
    tmp_path: Path,
) -> None:
    def fail_if_materialized():
        pytest.fail("applicability must not inspect the combination space")

    instance = SimpleNamespace(
        matrix_kind="sparse_uniform",
        matrix_row_weight=23,
        n=122,
        m=244,
        q=1229,
        materialize_rows=fail_if_materialized,
    )
    solve_request = SolveRequest(
        seed=11,
        max_seconds=0.01,
        work_dir=tmp_path,
        parameters={"subset_cap": 1},
    )

    assert dense_minor_applicability(instance, solve_request)


def test_dense_minor_applicability_obeys_deadline(monkeypatch, tmp_path: Path) -> None:
    instance = SimpleNamespace(
        matrix_kind="sparse_uniform",
        matrix_row_weight=23,
        n=122,
        m=244,
        q=1229,
        materialize_rows=lambda: pytest.fail("expired applicability enumerated rows"),
    )
    ticks = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(
        "tools.solvers.sparse_matrix.time.monotonic",
        lambda: next(ticks, 2.0),
    )

    assert not dense_minor_applicability(
        instance,
        SolveRequest(
            seed=11,
            max_seconds=1.0,
            work_dir=tmp_path,
            parameters={"subset_cap": 1},
        ),
    )


def test_dense_minor_samples_one_production_ordinal_above_sys_maxsize(
    tmp_path: Path,
) -> None:
    class Problem:
        n = 122
        q = 1229
        matrix_kind = "sparse_uniform"
        matrix_row_weight = 23

        def iter_rows(self):
            return iter(())

    assert math.comb(Problem.n, Problem.matrix_row_weight) > sys.maxsize
    result = DenseMinorRecovery()._solve(
        Problem(),
        SolveRequest(
            seed=11,
            max_seconds=20.0,
            work_dir=tmp_path,
            parameters={"subset_cap": 1},
        ),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.detail["code"] == "subset_cap_or_inapplicable"


def test_dense_minor_subset_cap_does_not_materialize_the_full_combination_space(
    monkeypatch, dense_minor_fixture, tmp_path: Path
) -> None:
    import itertools

    real_combinations = itertools.combinations

    def one_then_fail(*args, **kwargs):
        for index, value in enumerate(real_combinations(*args, **kwargs)):
            if index:
                raise AssertionError("enumerated beyond subset_cap")
            yield value

    monkeypatch.setattr(sparse_matrix_module.itertools, "combinations", one_then_fail)
    result = DenseMinorRecovery()._solve(
        dense_minor_fixture,
        SolveRequest(
            seed=11,
            max_seconds=20.0,
            work_dir=tmp_path,
            parameters={"subset_cap": 1},
        ),
    )

    assert result.status in {SolveStatus.SUCCESS, SolveStatus.CENSORED}


def test_dense_minor_iterates_all_local_candidates_and_backtracks_globally() -> None:
    candidates = tuple(
        iter_local_candidates(
            rows=((1, 0), (0, 1), (1, 1)),
            rhs=(0, 0, 1),
            coordinates=(0, 1),
            domains=((0, 1), (0, 1)),
            q=5,
            max_abs=1,
            max_l1=3,
            max_l2_squared=3,
            max_nonzero=3,
        )
    )
    assert len(candidates) > 1
    seen: list[tuple[int, ...]] = []

    def validator(secret: tuple[int, ...]) -> bool:
        seen.append(secret)
        return secret == (1, 1, 1)

    outcome = search_local_completions(
        n=3,
        coordinates=(0, 1),
        local_candidates=candidates,
        remaining_domains={2: (0, 1)},
        validator=validator,
        excluded=None,
        work_unit_cap=100,
    )
    assert outcome.secret == (1, 1, 1)
    assert len(seen) > 1


def test_task5_result_details_scrub_for_every_status_without_a_recovery_call() -> None:
    domains = ((0, 1),)
    traversal = certifying_cartesian_search(
        domains=domains,
        validator=lambda _secret: False,
        excluded=None,
        work_unit_cap=2,
        deadline=None,
        memory_cap_bytes=1_000_000,
    )
    certificate = build_complete_domain_certificate(domains, traversal)
    details = {
        SolveStatus.SUCCESS: make_public_result_detail("accepted_witness", tested_count=1),
        SolveStatus.EXHAUSTED: make_public_result_detail(
            "complete_domain", certificate=certificate, tested_count=2
        ),
        SolveStatus.CENSORED: make_public_result_detail("work_unit_cap", tested_count=1),
        SolveStatus.ERROR: make_public_result_detail("malformed_invariant"),
    }
    request_value = request()
    accepted = SimpleNamespace(ok=True, code="ok")
    instance = SimpleNamespace(validate_secret=lambda _secret: accepted)
    results = {
        SolveStatus.SUCCESS: validate_solve_result(
            instance,
            request_value,
            SolveResult.success(
                secret=(1,), elapsed_seconds=0.0, work_units=1,
                detail=details[SolveStatus.SUCCESS],
            ),
        ),
        SolveStatus.EXHAUSTED: SolveResult.exhausted(
            elapsed_seconds=0.0, work_units=2, detail=details[SolveStatus.EXHAUSTED]
        ),
        SolveStatus.CENSORED: SolveResult.censored(
            elapsed_seconds=0.0, work_units=1, detail=details[SolveStatus.CENSORED]
        ),
        SolveStatus.ERROR: SolveResult.error(
            elapsed_seconds=0.0, work_units=0, detail=details[SolveStatus.ERROR]
        ),
    }
    for status, result in results.items():
        public = scrub_result(result)
        assert public["status"] == status.value
        assert "secret" not in public
        assert set(public["detail"]) <= {
            "code", "reason", "certificate_id", "certificate_digest", "public_parameters"
        }


@pytest.mark.recovery
def test_repeated_support_recovers(repeated_support_fixture, tmp_path: Path) -> None:
    result = RepeatedSupportRecovery().solve(
        repeated_support_fixture,
        replace(request(), work_dir=tmp_path),
    )
    assert result.status is SolveStatus.SUCCESS
    assert repeated_support_fixture.validate_secret(result.secret).ok


@pytest.mark.recovery
def test_dense_minor_recovers(dense_minor_fixture) -> None:
    result = DenseMinorRecovery().solve(dense_minor_fixture, request())
    assert result.status is SolveStatus.SUCCESS
    assert dense_minor_fixture.validate_secret(result.secret).ok


@pytest.mark.recovery
def test_graph_peeling_recovers(graph_peeling_fixture) -> None:
    result = GraphPeelingRecovery().solve(graph_peeling_fixture, request())
    assert result.status is SolveStatus.SUCCESS
    assert graph_peeling_fixture.validate_secret(result.secret).ok
