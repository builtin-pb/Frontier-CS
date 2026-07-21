from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.solvers.api import SolveRequest, SolveStatus, ValidatedExactSolver
from tools.solvers.support_incidence import (
    SupportIncidenceRecovery,
    _hitting_pairs,
    applicability,
)


def request(**parameters: object) -> SolveRequest:
    return SolveRequest(
        seed=7,
        max_seconds=20.0,
        work_dir=Path("build/lwe-test"),
        parameters=parameters,
    )


class PairProblem:
    instance_id = "pair-fixture"
    instance_digest = "0" * 64
    n = 5
    m = 4
    q = 257
    b = (10, 252, 253, 1)
    family = "MIX_Q_SPARSE"
    tier = "easy"
    cohort = "test"
    runtime_bin = "E0"
    octave = None
    matrix_kind = "sparse_uniform"
    matrix_alphabet = ()
    matrix_row_weight = 2
    secret_distribution_kind = "exact_weight_alphabet"
    secret_predicate_kind = "alphabet"
    secret_alphabet = (-1, 0, 1)
    secret_weight = 2
    secret_eta = None
    secret_min_nonzero = 2
    secret_max_nonzero = 2
    error_distribution_kind = "bounded_uniform"
    error_sigma = None
    error_eta = None
    error_bound = 2
    error_weight = None
    error_max_abs = 2
    error_max_l1 = 8
    error_max_l2_squared = 16
    error_max_nonzero = 4
    rows = (
        (0, 10, 0, 0, 20),
        (0, 0, 30, 5, 0),
        (0, 7, 0, 11, 0),
        (4, 0, 9, 0, 0),
    )
    witness = (0, 1, 0, -1, 0)

    def iter_rows(self):
        return iter(self.rows)

    def validate_secret(self, candidate):
        return SimpleNamespace(ok=tuple(candidate) == self.witness, code="ok")


def test_support_incidence_solver_uses_common_validation_wrapper() -> None:
    assert issubclass(SupportIncidenceRecovery, ValidatedExactSolver)
    assert "solve" not in SupportIncidenceRecovery.__dict__
    assert SupportIncidenceRecovery.solver_id == "support_incidence"


def test_hitting_pairs_are_complete_for_weight_two_active_rows() -> None:
    active = (
        frozenset({1, 4}),
        frozenset({2, 3}),
        frozenset({1, 3}),
    )

    assert tuple(_hitting_pairs(active, n=5)) == ((1, 2), (1, 3), (3, 4))


def test_hitting_pairs_handle_one_coordinate_that_hits_every_active_row() -> None:
    active = (
        frozenset({1, 2}),
        frozenset({1, 3}),
        frozenset({1, 4}),
    )

    pairs = tuple(_hitting_pairs(active, n=5))

    assert pairs == ((0, 1), (1, 2), (1, 3), (1, 4))


def test_support_incidence_recovers_pair_fixture() -> None:
    problem = PairProblem()

    result = SupportIncidenceRecovery().solve(problem, request())

    assert result.status is SolveStatus.SUCCESS
    assert result.secret == problem.witness
    assert result.detail["code"] == "support_incidence_hitting_pair"
    assert result.detail["public_parameters"]["row_count"] == 3
    assert result.detail["public_parameters"]["support_count"] == 2
    assert result.detail["public_parameters"]["candidate_count"] == 7


def test_support_incidence_excludes_requested_witness_without_success() -> None:
    problem = PairProblem()

    result = SupportIncidenceRecovery().solve(
        problem,
        SolveRequest(
            seed=7,
            max_seconds=20.0,
            work_dir=Path("build/lwe-test"),
            exclude_secret=problem.witness,
        ),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.detail["code"] == "excluded_witness_requires_private_proof"


def test_support_incidence_reports_inapplicable_instances() -> None:
    problem = PairProblem()
    problem.secret_min_nonzero = 3
    problem.secret_max_nonzero = 3

    assert not applicability(problem)
    result = SupportIncidenceRecovery().solve(problem, request())

    assert result.status is SolveStatus.CENSORED
    assert result.detail["code"] == "inapplicable_support_incidence"


def test_support_incidence_honors_work_unit_cap() -> None:
    problem = PairProblem()
    problem.rows = (
        (0, 10, 0, 0, 20),
        (0, 9, 0, 0, 30),
    )
    problem.b = (10, 9)
    problem.m = 2

    result = SupportIncidenceRecovery().solve(problem, request(work_unit_cap=1))

    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == "work_unit_cap"


def test_support_incidence_rejects_invalid_request_parameters() -> None:
    result = SupportIncidenceRecovery().solve(PairProblem(), request(work_unit_cap=-1))

    assert result.status is SolveStatus.ERROR
    assert result.detail["code"] == "invalid_public_parameters"
