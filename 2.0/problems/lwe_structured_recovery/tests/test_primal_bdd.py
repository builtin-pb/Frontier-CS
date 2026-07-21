from __future__ import annotations

import os
import inspect
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools.solvers.api import (
    ValidatedExactSolver,
    SolveRequest,
    SolveResult,
    SolveStatus,
    SolverContractError,
)
from tools.solvers.bounded_error import (
    CleanSubsetRecovery,
    MemoryLimitExceeded,
    SolverRunControl,
    TimeLimitExceeded,
    applicability as clean_subset_applicability,
    invert_matrix_mod_prime,
    is_prime,
    sampled_subset_candidate,
)
from tools.solvers.primal_bdd import (
    BackendOutcome,
    PrimalBDD,
    build_construction_a,
    candidate_from_codeword,
    classify_unsuccessful_cvp,
    map_secret_representatives,
    single_thread_policy_satisfied,
    run_deadline_bounded_backend,
    verify_independent_exact_cvp,
    applicability as primal_applicability,
)
from tools.solvers.small_secret_hybrid import (
    NestedDispatchError,
    SmallSecretHybrid,
    build_nested_request,
    dispatch_registered_primal,
    hybrid_partition,
    merge_secret,
    propagate_nested_result,
    applicability as hybrid_applicability,
)


def request(
    *, work_dir: Path | None = None, **parameters: object
) -> SolveRequest:
    return SolveRequest(
        seed=7,
        max_seconds=30.0,
        work_dir=Path("build/lwe-test") if work_dir is None else work_dir,
        parameters=parameters,
    )


def _sleeping_backend_worker(connection, *_args) -> None:
    try:
        time.sleep(1.0)
    finally:
        connection.close()


def _reporting_backend_worker(connection, *_args) -> None:
    try:
        connection.send(("ok", (1, 1), 200 * 1024 * 1024))
    finally:
        connection.close()


def test_generic_solvers_use_only_the_validated_wrapper() -> None:
    for solver_type in (CleanSubsetRecovery, PrimalBDD, SmallSecretHybrid):
        assert issubclass(solver_type, ValidatedExactSolver)
        assert "solve" not in solver_type.__dict__
        assert callable(solver_type.__dict__.get("_solve"))


def test_task6_run_control_checkpoints_typed_progress_and_resumes(
    tmp_path: Path,
) -> None:
    instance = SimpleNamespace(
        instance_id="task6-static",
        instance_digest="a" * 64,
    )
    request_one = SolveRequest(
        seed=19,
        max_seconds=30.0,
        work_dir=tmp_path,
        parameters={"memory_cap_bytes": 10_000},
        checkpoint_every_work_units=2,
    )
    ticks = iter((100.0, 101.0, 102.0, 103.0))
    control = SolverRunControl.create(
        instance=instance,
        request=request_one,
        solver_id="bounded_error",
        solver_revision="task6-test-v1",
        search_descriptor={"algorithm": "clean_subset"},
        memory_cap_bytes=10_000,
        clock=lambda: next(ticks),
        rss_reader=lambda: 100,
        peak_rss_reader=lambda: 120,
    )
    control.advance(cursor=2, work_units=2, solver_state={"singular_count": 1})
    checkpoint = control.checkpoint(force=True, phase="clean_subset_checkpoint")
    assert checkpoint is not None

    progress = [
        __import__("json").loads(line)
        for line in (tmp_path / "bounded_error.progress.jsonl")
        .read_text(encoding="ascii")
        .splitlines()
    ]
    assert progress == [
        {
            "checkpoint_count": 1,
            "elapsed_seconds": 1.0,
            "instance_id": "task6-static",
            "peak_rss_bytes": 120,
            "phase": "clean_subset_checkpoint",
            "solver_id": "bounded_error",
            "work_units": 2,
        }
    ]

    request_two = SolveRequest(
        seed=19,
        max_seconds=30.0,
        work_dir=tmp_path,
        parameters={"memory_cap_bytes": 10_000},
        resume_checkpoint=checkpoint,
        checkpoint_every_work_units=2,
    )
    resumed = SolverRunControl.create(
        instance=instance,
        request=request_two,
        solver_id="bounded_error",
        solver_revision="task6-test-v1",
        search_descriptor={"algorithm": "clean_subset"},
        memory_cap_bytes=10_000,
        clock=lambda: 200.0,
        rss_reader=lambda: 100,
        peak_rss_reader=lambda: 120,
    )
    assert resumed.cursor == 2
    assert resumed.work_units == 2
    assert resumed.checkpoint_count == 1
    assert dict(resumed.solver_state) == {"singular_count": 1}


def test_task6_run_control_rejects_hostile_resume_and_enforces_caps(
    tmp_path: Path,
) -> None:
    instance = SimpleNamespace(
        instance_id="task6-static",
        instance_digest="b" * 64,
    )
    request_one = SolveRequest(
        seed=23,
        max_seconds=5.0,
        work_dir=tmp_path,
        parameters={"memory_cap_bytes": 150},
    )
    clock = iter((10.0, 16.0, 17.0))
    control = SolverRunControl.create(
        instance=instance,
        request=request_one,
        solver_id="primal_bdd",
        solver_revision="task6-test-v1",
        search_descriptor={"mode": "nearest_plane"},
        memory_cap_bytes=150,
        clock=lambda: next(clock),
        rss_reader=lambda: 100,
        peak_rss_reader=lambda: 100,
    )
    assert control.stop_reason() == "time_cap"
    with pytest.raises(MemoryLimitExceeded):
        control.preflight(51)
    checkpoint = control.checkpoint(force=True, phase="primal_checkpoint")
    assert checkpoint is not None

    hostile = SolveRequest(
        seed=23,
        max_seconds=5.0,
        work_dir=tmp_path,
        parameters={"memory_cap_bytes": 151},
        resume_checkpoint=checkpoint,
    )
    with pytest.raises(SolverContractError, match="binding"):
        SolverRunControl.create(
            instance=instance,
            request=hostile,
            solver_id="primal_bdd",
            solver_revision="task6-test-v1",
            search_descriptor={"mode": "nearest_plane"},
            memory_cap_bytes=151,
            clock=lambda: 20.0,
            rss_reader=lambda: 100,
            peak_rss_reader=lambda: 100,
        )

    shortened_deadline = SolveRequest(
        seed=23,
        max_seconds=4.0,
        work_dir=tmp_path,
        parameters={"memory_cap_bytes": 150},
        resume_checkpoint=checkpoint,
    )
    shortened = SolverRunControl.create(
        instance=instance,
        request=shortened_deadline,
        solver_id="primal_bdd",
        solver_revision="task6-test-v1",
        search_descriptor={"mode": "nearest_plane"},
        memory_cap_bytes=150,
        clock=lambda: 20.0,
        rss_reader=lambda: 100,
        peak_rss_reader=lambda: 100,
    )
    assert shortened.stop_reason() == "time_cap"

    extended_deadline = SolveRequest(
        seed=23,
        max_seconds=6.0,
        work_dir=tmp_path,
        parameters={"memory_cap_bytes": 150},
        resume_checkpoint=checkpoint,
    )
    with pytest.raises(SolverContractError, match="binding"):
        SolverRunControl.create(
            instance=instance,
            request=extended_deadline,
            solver_id="primal_bdd",
            solver_revision="task6-test-v1",
            search_descriptor={"mode": "nearest_plane"},
            memory_cap_bytes=150,
            clock=lambda: 20.0,
            rss_reader=lambda: 100,
            peak_rss_reader=lambda: 100,
        )


def test_static_imports_do_not_touch_native_solver_dependencies(tmp_path: Path) -> None:
    maintainer_dir = Path(__file__).resolve().parents[1] / "maintainer"
    probe = (
        "import builtins\n"
        "real_import = builtins.__import__\n"
        "blocked = {'numpy', 'scipy', 'fpylll', 'cysignals', 'psutil'}\n"
        "def guarded(name, *args, **kwargs):\n"
        "    if name.partition('.')[0] in blocked:\n"
        "        raise RuntimeError('native import attempted: ' + name)\n"
        "    return real_import(name, *args, **kwargs)\n"
        "builtins.__import__ = guarded\n"
        "import tools.solvers.bounded_error\n"
        "import tools.solvers.primal_bdd\n"
        "import tools.solvers.small_secret_hybrid\n"
    )
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        cwd=maintainer_dir,
        env={
            "HOME": str(tmp_path),
            "PATH": os.environ.get("PATH", ""),
            "LC_ALL": "C.UTF-8",
        },
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_modular_inverse_and_singular_minor_are_exact() -> None:
    assert invert_matrix_mod_prime(((1, 2), (3, 4)), 5) == ((3, 1), (4, 2))
    assert invert_matrix_mod_prime(((1, 2), (2, 4)), 5) is None
    with pytest.raises(ValueError, match="prime"):
        invert_matrix_mod_prime(((1,),), 9)


def test_primality_is_deterministic_and_bounded_by_the_phase2_modulus_cap() -> None:
    assert is_prime(4_294_967_291)
    assert not is_prime(4_294_967_311)


def test_clean_subset_candidate_counts_singular_minor_without_guessing() -> None:
    singular = sampled_subset_candidate(
        rows=((1, 2), (2, 4), (0, 1)),
        rhs=(3, 1, 2),
        row_indices=(0, 1),
        q=5,
        predicate_kind="mod_q",
        alphabet=(),
    )
    assert singular.kind == "singular"
    assert singular.secret is None

    solved = sampled_subset_candidate(
        rows=((1, 0), (0, 1), (1, 1)),
        rhs=(1, 4, 0),
        row_indices=(0, 1),
        q=5,
        predicate_kind="alphabet",
        alphabet=(-1, 0, 1),
    )
    assert solved.kind == "candidate"
    assert solved.secret == (1, -1)


def test_clean_subset_applicability_requires_exact_public_sparse_error_contract() -> None:
    base = dict(m=8, n=4, q=17, error_distribution_kind="sparse_bounded", error_weight=2)
    assert clean_subset_applicability(SimpleNamespace(**base))
    assert not clean_subset_applicability(SimpleNamespace(**{**base, "m": 5}))
    assert not clean_subset_applicability(SimpleNamespace(**{**base, "q": 15}))
    assert not clean_subset_applicability(
        SimpleNamespace(**{**base, "error_distribution_kind": "bounded_uniform"})
    )
    assert not clean_subset_applicability(SimpleNamespace(**{**base, "error_weight": None}))


def _static_clean_subset_problem(*, block_calls: list[tuple[int, int]]):
    rows = ((1, 0), (0, 1), (1, 1))

    def materialize_row_block(start: int, stop: int):
        block_calls.append((start, stop))
        return rows[start:stop]

    return SimpleNamespace(
        instance_id="clean-static",
        instance_digest="c" * 64,
        n=2,
        m=3,
        q=5,
        b=(2, 2, 4),
        error_distribution_kind="sparse_bounded",
        error_weight=1,
        secret_predicate_kind="alphabet",
        secret_alphabet=(0, 1),
        materialize_rows=lambda: pytest.fail("unbounded row materialization"),
        materialize_row_block=materialize_row_block,
        validate_secret=lambda _candidate: SimpleNamespace(ok=False),
    )


def test_clean_subset_memory_cap_precedes_any_row_materialization(tmp_path: Path) -> None:
    calls: list[tuple[int, int]] = []
    result = CleanSubsetRecovery()._solve(
        _static_clean_subset_problem(block_calls=calls),
        SolveRequest(
            seed=5,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters={"clean_subset_cap": 2, "memory_cap_bytes": 1},
        ),
    )
    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == "memory_cap"
    assert calls == []


def test_clean_subset_checkpoint_resume_skips_completed_attempts(tmp_path: Path) -> None:
    first_calls: list[tuple[int, int]] = []
    first_request = SolveRequest(
        seed=11,
        max_seconds=10.0,
        work_dir=tmp_path,
        parameters={"clean_subset_cap": 2, "memory_cap_bytes": 512 * 1024 * 1024},
        checkpoint_every_work_units=1,
    )
    first = CleanSubsetRecovery()._solve(
        _static_clean_subset_problem(block_calls=first_calls),
        first_request,
    )
    assert first.status is SolveStatus.CENSORED
    assert first.work_units == 2
    checkpoint = tmp_path / "bounded_error.checkpoint.json"
    assert checkpoint.is_file()

    resumed_calls: list[tuple[int, int]] = []
    resumed = CleanSubsetRecovery()._solve(
        _static_clean_subset_problem(block_calls=resumed_calls),
        SolveRequest(
            seed=11,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters={
                "clean_subset_cap": 2,
                "memory_cap_bytes": 512 * 1024 * 1024,
            },
            resume_checkpoint=checkpoint,
            checkpoint_every_work_units=1,
        ),
    )
    assert resumed.status is SolveStatus.CENSORED, resumed.detail
    assert resumed.work_units == 2
    assert resumed_calls == []


def test_clean_subset_resume_revalidates_a_checkpointed_pending_candidate(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.bounded_error as bounded_module

    candidate_calls = 0

    def candidate_outcome(**_kwargs):
        nonlocal candidate_calls
        candidate_calls += 1
        return SimpleNamespace(kind="candidate", secret=(0, 0))

    monkeypatch.setattr(
        bounded_module,
        "sampled_subset_candidate",
        candidate_outcome,
    )
    validation_calls = 0
    problem = _static_clean_subset_problem(block_calls=[])

    def interrupted_validation(candidate):
        nonlocal validation_calls
        validation_calls += 1
        assert candidate == (0, 0)
        if validation_calls == 1:
            raise RuntimeError("simulated interruption before success return")
        return SimpleNamespace(ok=True)

    problem.validate_secret = interrupted_validation
    request = SolveRequest(
        seed=17,
        max_seconds=10.0,
        work_dir=tmp_path,
        parameters={"clean_subset_cap": 1},
        checkpoint_every_work_units=1,
    )
    with pytest.raises(RuntimeError, match="simulated interruption"):
        CleanSubsetRecovery()._solve(problem, request)

    resumed = CleanSubsetRecovery()._solve(
        problem,
        replace(
            request,
            resume_checkpoint=tmp_path / "bounded_error.checkpoint.json",
        ),
    )
    assert resumed.status is SolveStatus.SUCCESS
    assert resumed.secret == (0, 0)
    assert resumed.work_units == 1
    assert candidate_calls == 1


def test_systematic_construction_a_uses_independent_rows_and_public_permutation() -> None:
    construction = build_construction_a(
        ((1, 0), (2, 0), (0, 1)),
        q=5,
    )
    assert construction.independent_rows == (0, 2)
    assert construction.remaining_rows == (1,)
    assert construction.permutation == (0, 2, 1)
    assert construction.a0_inverse == ((1, 0), (0, 1))
    assert construction.c == ((2, 0),)
    assert construction.basis == (
        (1, 0, 2),
        (0, 1, 0),
        (0, 0, 5),
    )


def test_construction_a_rejects_composite_and_rank_deficient_inputs() -> None:
    with pytest.raises(ValueError, match="prime"):
        build_construction_a(((1,), (2,)), q=8)
    with pytest.raises(ValueError, match="rank"):
        build_construction_a(((1, 2), (2, 4), (3, 6)), q=5)


@pytest.mark.parametrize(
    ("residues", "kind", "alphabet", "expected"),
    [
        ((0, 16, 1), "alphabet", (-1, 0, 1), (0, -1, 1)),
        ((0, 16, 1), "mod_q", (), (0, 16, 1)),
    ],
)
def test_secret_representatives_are_unique_and_public(
    residues: tuple[int, ...],
    kind: str,
    alphabet: tuple[int, ...],
    expected: tuple[int, ...],
) -> None:
    assert map_secret_representatives(residues, q=17, predicate_kind=kind, alphabet=alphabet) == expected


def test_secret_representative_mapping_rejects_absent_or_ambiguous_values() -> None:
    with pytest.raises(ValueError, match="representative"):
        map_secret_representatives((2,), q=17, predicate_kind="alphabet", alphabet=(-1, 0, 1))
    with pytest.raises(ValueError, match="unique"):
        map_secret_representatives((0,), q=5, predicate_kind="alphabet", alphabet=(0, 5))


def test_candidate_recovery_uses_the_independent_codeword_coordinates() -> None:
    construction = build_construction_a(((1, 0), (2, 0), (0, 1)), q=5)
    # In public row order the codeword is (1, 2, 4); in construction order it is
    # (1, 4, 2), so y_0=(1,4) and A_0^{-1}y_0=(1,4).
    assert candidate_from_codeword(
        construction,
        (1, 4, 2),
        predicate_kind="alphabet",
        alphabet=(-1, 0, 1),
    ) == (1, -1)


def test_nearest_plane_and_exact_cvp_failure_are_both_censored_without_certificate() -> None:
    for mode in ("nearest_plane", "exact_cvp"):
        result = classify_unsuccessful_cvp(mode=mode, elapsed_seconds=1.0, work_units=1)
        assert result.status is SolveStatus.CENSORED
        assert result.secret is None
        assert result.detail["code"] == f"{mode}_candidate_rejected"
    with pytest.raises(ValueError, match="mode"):
        classify_unsuccessful_cvp(mode="heuristic", elapsed_seconds=1.0, work_units=1)


def test_independent_exact_cvp_check_proves_or_refutes_the_backend_candidate() -> None:
    construction = build_construction_a(((1,), (1,)), q=5)
    verified = verify_independent_exact_cvp(
        construction,
        target=(1, 2),
        candidate=(1, 1),
        work_unit_cap=100,
    )
    assert verified.complete
    assert verified.exact
    assert verified.reason == "verified_exact"
    assert verified.tested_vectors == 1

    refuted = verify_independent_exact_cvp(
        construction,
        target=(1, 2),
        candidate=(0, 0),
        work_unit_cap=100,
    )
    assert refuted.complete
    assert not refuted.exact
    assert refuted.reason == "shorter_lattice_vector"
    repeated = verify_independent_exact_cvp(
        construction,
        target=(1, 2),
        candidate=(0, 0),
        work_unit_cap=100,
        start_ordinal=refuted.next_ordinal,
    )
    assert repeated.reason == "shorter_lattice_vector"
    assert repeated.next_ordinal == refuted.next_ordinal


def test_independent_exact_cvp_check_censors_when_bounded_proof_is_infeasible() -> None:
    construction = build_construction_a(((1,), (1,)), q=5)
    capped = verify_independent_exact_cvp(
        construction,
        target=(1, 2),
        candidate=(1, 1),
        work_unit_cap=0,
    )
    assert not capped.complete
    assert not capped.exact
    assert capped.reason == "work_unit_cap"


def test_independent_exact_cvp_resumes_from_a_deterministic_ordinal() -> None:
    construction = build_construction_a(((1,), (1,)), q=5)
    checkpoints: list[tuple[int, int]] = []
    first = verify_independent_exact_cvp(
        construction,
        target=(1, 3),
        candidate=(2, 2),
        work_unit_cap=2,
        progress_callback=lambda ordinal, tested: checkpoints.append(
            (ordinal, tested)
        ),
    )
    assert not first.complete
    assert first.next_ordinal == 2
    assert checkpoints == [(1, 1), (2, 2)]

    resumed = verify_independent_exact_cvp(
        construction,
        target=(1, 3),
        candidate=(2, 2),
        work_unit_cap=100,
        start_ordinal=first.next_ordinal,
    )
    full = verify_independent_exact_cvp(
        construction,
        target=(1, 3),
        candidate=(2, 2),
        work_unit_cap=100,
    )
    assert resumed.complete and resumed.exact
    assert first.tested_vectors + resumed.tested_vectors == full.tested_vectors
    assert resumed.next_ordinal == full.next_ordinal


def test_native_backend_supervisor_enforces_deadline_without_post_call_polling() -> None:
    assert (
        inspect.signature(run_deadline_bounded_backend)
        .parameters["context_name"]
        .default
        == "fork"
    )
    construction = build_construction_a(((1,), (1,)), q=5)
    started = time.monotonic()
    outcome = run_deadline_bounded_backend(
        construction,
        target=(1, 2),
        mode="nearest_plane",
        block_size=2,
        deadline=started + 0.05,
        memory_cap_bytes=512 * 1024 * 1024,
        worker=_sleeping_backend_worker,
        context_name="fork",
    )
    assert outcome.reason == "time_cap"
    assert outcome.vector is None
    assert outcome.peak_rss_bytes > 0
    assert time.monotonic() - started < 0.75


def test_native_backend_supervisor_reports_the_worker_peak() -> None:
    construction = build_construction_a(((1,), (1,)), q=5)
    outcome = run_deadline_bounded_backend(
        construction,
        target=(1, 2),
        mode="nearest_plane",
        block_size=2,
        deadline=time.monotonic() + 1.0,
        memory_cap_bytes=512 * 1024 * 1024,
        worker=_reporting_backend_worker,
        context_name="fork",
    )
    assert outcome.reason == "ok"
    assert outcome.vector == (1, 1)
    assert outcome.peak_rss_bytes >= 200 * 1024 * 1024


def _static_primal_problem(*, block_calls: list[tuple[int, int]]):
    rows = ((1,), (1,))

    def materialize_row_block(start: int, stop: int):
        block_calls.append((start, stop))
        return rows[start:stop]

    return SimpleNamespace(
        instance_id="primal-static",
        instance_digest="d" * 64,
        n=1,
        m=2,
        q=5,
        b=(1, 2),
        secret_predicate_kind="mod_q",
        secret_alphabet=(),
        materialize_rows=lambda: pytest.fail("unbounded row materialization"),
        materialize_row_block=materialize_row_block,
        validate_secret=lambda _candidate: SimpleNamespace(ok=False),
    )


def _set_single_thread_policy(monkeypatch) -> None:
    for name in (
        "MKL_NUM_THREADS",
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
    ):
        monkeypatch.setenv(name, "1")


def test_primal_memory_cap_precedes_public_row_and_native_backend(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.primal_bdd as primal_module

    _set_single_thread_policy(monkeypatch)
    monkeypatch.setattr(
        primal_module,
        "run_deadline_bounded_backend",
        lambda *_args, **_kwargs: pytest.fail("native backend must not start"),
    )
    calls: list[tuple[int, int]] = []
    result = PrimalBDD()._solve(
        _static_primal_problem(block_calls=calls),
        SolveRequest(
            seed=31,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters={"memory_cap_bytes": 1},
        ),
    )
    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == "memory_cap"
    assert calls == []


def test_primal_resume_reuses_checkpointed_backend_candidate(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.primal_bdd as primal_module

    _set_single_thread_policy(monkeypatch)
    calls: list[tuple[int, int]] = []
    backend_calls = 0

    def fake_backend(*_args, **_kwargs):
        nonlocal backend_calls
        backend_calls += 1
        return BackendOutcome("ok", (1, 1), 256 * 1024 * 1024)

    monkeypatch.setattr(primal_module, "run_deadline_bounded_backend", fake_backend)
    parameters = {
        "memory_cap_bytes": 512 * 1024 * 1024,
        "primal_cvp_mode": "nearest_plane",
    }
    first = PrimalBDD()._solve(
        _static_primal_problem(block_calls=calls),
        SolveRequest(
            seed=37,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters=parameters,
            checkpoint_every_work_units=1,
        ),
    )
    assert first.status is SolveStatus.CENSORED
    assert backend_calls == 1
    assert first.peak_rss_bytes >= 256 * 1024 * 1024
    checkpoint = tmp_path / "primal_bdd.checkpoint.json"
    assert checkpoint.is_file()

    monkeypatch.setattr(
        primal_module,
        "run_deadline_bounded_backend",
        lambda *_args, **_kwargs: pytest.fail("resumed backend must be skipped"),
    )
    resumed = PrimalBDD()._solve(
        _static_primal_problem(block_calls=[]),
        SolveRequest(
            seed=37,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters=parameters,
            resume_checkpoint=checkpoint,
            checkpoint_every_work_units=1,
        ),
    )
    assert resumed.status is SolveStatus.CENSORED, resumed.detail
    assert resumed.work_units == first.work_units


def test_primal_memory_capped_backend_attempt_is_charged_and_not_repeated(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.primal_bdd as primal_module

    _set_single_thread_policy(monkeypatch)
    backend_calls = 0

    def memory_capped_backend(*_args, **_kwargs):
        nonlocal backend_calls
        backend_calls += 1
        return BackendOutcome("memory_cap", None)

    monkeypatch.setattr(
        primal_module,
        "run_deadline_bounded_backend",
        memory_capped_backend,
    )
    request = SolveRequest(
        seed=79,
        max_seconds=10.0,
        work_dir=tmp_path,
        parameters={"work_unit_cap": 10},
        checkpoint_every_work_units=1,
    )
    first = PrimalBDD()._solve(_static_primal_problem(block_calls=[]), request)
    assert first.status is SolveStatus.CENSORED
    assert first.detail["reason"] == "memory_cap"
    assert first.work_units == 1

    resumed = PrimalBDD()._solve(
        _static_primal_problem(block_calls=[]),
        replace(
            request,
            resume_checkpoint=tmp_path / "primal_bdd.checkpoint.json",
        ),
    )
    assert resumed.status is SolveStatus.CENSORED
    assert resumed.detail == {"code": "primal_backend_attempt_incomplete"}
    assert resumed.work_units == 1
    assert backend_calls == 1


def test_primal_rejects_charged_work_with_forged_fresh_backend_state(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import json
    import tools.solvers.primal_bdd as primal_module

    _set_single_thread_policy(monkeypatch)
    backend_calls = 0

    def memory_capped_backend(*_args, **_kwargs):
        nonlocal backend_calls
        backend_calls += 1
        return BackendOutcome("memory_cap", None)

    monkeypatch.setattr(
        primal_module,
        "run_deadline_bounded_backend",
        memory_capped_backend,
    )
    request = SolveRequest(
        seed=89,
        max_seconds=10.0,
        work_dir=tmp_path,
        parameters={"work_unit_cap": 10},
        checkpoint_every_work_units=1,
    )
    first = PrimalBDD()._solve(_static_primal_problem(block_calls=[]), request)
    assert first.work_units == 1

    checkpoint = tmp_path / "primal_bdd.checkpoint.json"
    payload = json.loads(checkpoint.read_text(encoding="ascii"))
    payload["state"]["solver_state"] = {}
    checkpoint.write_text(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n",
        encoding="ascii",
    )
    resumed = PrimalBDD()._solve(
        _static_primal_problem(block_calls=[]),
        replace(request, resume_checkpoint=checkpoint),
    )
    assert resumed.status is SolveStatus.ERROR
    assert resumed.detail == {"code": "checkpoint_invalid"}
    assert backend_calls == 1


def test_exact_cvp_mode_never_accepts_backend_label_without_independent_proof(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.primal_bdd as primal_module

    for name in (
        "MKL_NUM_THREADS",
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
    ):
        monkeypatch.setenv(name, "1")
    monkeypatch.setattr(
        primal_module,
        "run_deadline_bounded_backend",
        lambda *_args, **_kwargs: BackendOutcome("ok", (1, 1)),
    )
    problem = SimpleNamespace(
        instance_id="exact-static",
        instance_digest="e" * 64,
        n=1,
        m=2,
        q=5,
        b=(1, 2),
        secret_predicate_kind="mod_q",
        secret_alphabet=(),
        materialize_row_block=lambda start, stop: ((1,), (1,))[start:stop],
        validate_secret=lambda _candidate: pytest.fail(
            "candidate validation must not run without independent proof"
        ),
    )
    result = PrimalBDD()._solve(
        problem,
        SolveRequest(
            seed=31,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters={
                "primal_cvp_mode": "exact_cvp",
                "primal_exact_verification_cap": 0,
            },
        ),
    )
    assert result.status is SolveStatus.CENSORED
    assert result.detail == {"code": "exact_cvp_independent_proof_infeasible"}


def test_primal_exact_verification_checkpoints_periodically(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.primal_bdd as primal_module

    _set_single_thread_policy(monkeypatch)
    monkeypatch.setattr(
        primal_module,
        "run_deadline_bounded_backend",
        lambda *_args, **_kwargs: BackendOutcome("ok", (2, 2)),
    )
    problem = SimpleNamespace(
        instance_id="exact-progress-static",
        instance_digest="9" * 64,
        n=1,
        m=2,
        q=5,
        b=(1, 3),
        secret_predicate_kind="mod_q",
        secret_alphabet=(),
        materialize_row_block=lambda start, stop: ((1,), (1,))[start:stop],
        validate_secret=lambda _candidate: SimpleNamespace(ok=False),
    )
    result = PrimalBDD()._solve(
        problem,
        SolveRequest(
            seed=59,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters={
                "primal_cvp_mode": "exact_cvp",
                "primal_exact_verification_cap": 100,
            },
            checkpoint_every_work_units=2,
        ),
    )
    assert result.status is SolveStatus.CENSORED
    phases = [
        __import__("json").loads(line)["phase"]
        for line in (tmp_path / "primal_bdd.progress.jsonl")
        .read_text(encoding="ascii")
        .splitlines()
    ]
    assert "primal_exact_checkpoint" in phases


def test_primal_exact_refutation_remains_terminal_across_resume(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.primal_bdd as primal_module

    _set_single_thread_policy(monkeypatch)
    backend_calls = 0

    def refuted_backend(*_args, **_kwargs):
        nonlocal backend_calls
        backend_calls += 1
        return BackendOutcome("ok", (0, 0))

    monkeypatch.setattr(
        primal_module,
        "run_deadline_bounded_backend",
        refuted_backend,
    )
    problem = SimpleNamespace(
        n=1,
        m=2,
        q=5,
        instance_id="exact-refutation-resume",
        instance_digest="a" * 64,
        b=(1, 2),
        secret_predicate_kind="mod_q",
        secret_alphabet=(),
        materialize_row_block=lambda start, stop: ((1,), (1,))[start:stop],
        validate_secret=lambda _candidate: pytest.fail(
            "a refuted exact-CVP candidate must never reach validation"
        ),
    )
    parameters = {
        "primal_cvp_mode": "exact_cvp",
        "primal_exact_verification_cap": 100,
    }
    request = SolveRequest(
        seed=71,
        max_seconds=10.0,
        work_dir=tmp_path,
        parameters=parameters,
        checkpoint_every_work_units=1,
    )
    first = PrimalBDD()._solve(problem, request)
    assert first.status is SolveStatus.CENSORED
    assert first.detail == {"code": "exact_cvp_backend_candidate_refuted"}
    refuted_work_units = first.work_units

    checkpoint = tmp_path / "primal_bdd.checkpoint.json"
    for _ in range(2):
        resumed = PrimalBDD()._solve(
            problem,
            replace(request, resume_checkpoint=checkpoint),
        )
        assert resumed.status is SolveStatus.CENSORED
        assert resumed.detail == {
            "code": "exact_cvp_backend_candidate_refuted"
        }
        assert resumed.work_units == refuted_work_units
    assert backend_calls == 1


def test_primal_requires_the_complete_single_thread_policy() -> None:
    policy = {
        "MKL_NUM_THREADS": "1",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
    }
    assert single_thread_policy_satisfied(policy)
    assert not single_thread_policy_satisfied({**policy, "OMP_NUM_THREADS": "2"})
    incomplete = dict(policy)
    incomplete.pop("MKL_NUM_THREADS")
    assert not single_thread_policy_satisfied(incomplete)


def test_primal_ordinary_solve_configures_single_thread_policy(
    monkeypatch, tmp_path: Path
) -> None:
    import tools.solvers.primal_bdd as primal_module

    for name in (
        "MKL_NUM_THREADS",
        "OMP_NUM_THREADS",
        "OPENBLAS_NUM_THREADS",
        "VECLIB_MAXIMUM_THREADS",
    ):
        monkeypatch.setenv(name, "8")
    monkeypatch.setattr(
        primal_module,
        "run_deadline_bounded_backend",
        lambda *_args, **_kwargs: BackendOutcome("backend_error", None),
    )

    result = PrimalBDD().solve(
        _static_primal_problem(block_calls=[]),
        SolveRequest(seed=7, max_seconds=10.0, work_dir=tmp_path),
    )

    assert result.detail.get("code") != "single_thread_policy_required"
    assert single_thread_policy_satisfied()


def test_primal_worker_uses_supervisor_when_address_space_limit_is_unavailable(
    monkeypatch,
) -> None:
    import tools.solvers.primal_bdd as primal_module

    monkeypatch.setattr(
        primal_module.resource,
        "setrlimit",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            ValueError("current limit exceeds maximum limit")
        ),
    )

    primal_module._set_worker_memory_limit(512 * 1024 * 1024)


def test_primal_applicability_requires_prime_full_rank_overdetermined_system() -> None:
    applicable_problem = SimpleNamespace(
        n=2,
        m=3,
        q=5,
        materialize_row_block=lambda start, stop: (
            (1, 0),
            (2, 0),
            (0, 1),
        )[start:stop],
    )
    assert primal_applicability(applicable_problem)
    assert not primal_applicability(SimpleNamespace(**{**vars(applicable_problem), "q": 9}))
    assert not primal_applicability(
        SimpleNamespace(
            n=2,
            m=3,
            q=5,
            materialize_row_block=lambda start, stop: (
                (1, 0),
                (2, 0),
                (3, 0),
            )[start:stop],
        )
    )
    assert not primal_applicability(
        SimpleNamespace(
            n=2,
            m=2,
            q=5,
            materialize_row_block=lambda start, stop: (
                (1, 0),
                (0, 1),
            )[start:stop],
        )
    )


def test_construction_a_preprocessing_honors_the_cooperative_deadline() -> None:
    checks = 0

    def check_budget() -> None:
        nonlocal checks
        checks += 1
        if checks == 4:
            raise TimeLimitExceeded

    with pytest.raises(TimeLimitExceeded):
        build_construction_a(
            (
                (1, 0),
                (2, 0),
                (0, 1),
            ),
            q=5,
            budget_check=check_budget,
        )


def test_hybrid_partition_is_declared_deterministic_complete_and_disjoint() -> None:
    partition = hybrid_partition(n=5, guessed_count=2)
    assert partition.remaining == (0, 1, 2)
    assert partition.guessed == (3, 4)
    assert set(partition.remaining).isdisjoint(partition.guessed)
    assert sorted((*partition.remaining, *partition.guessed)) == list(range(5))
    with pytest.raises(ValueError, match="guessed_count"):
        hybrid_partition(n=5, guessed_count=5)


def test_hybrid_merge_places_guesses_back_in_original_coordinates() -> None:
    partition = hybrid_partition(n=5, guessed_count=2)
    assert merge_secret(partition, remaining_values=(1, 2, 3), guessed_values=(-1, 0)) == (
        1,
        2,
        3,
        -1,
        0,
    )


def test_nested_request_preserves_single_worker_and_remaining_budget(tmp_path: Path) -> None:
    outer = SolveRequest(seed=13, max_seconds=30.0, work_dir=tmp_path)
    nested = build_nested_request(
        outer,
        seed=17,
        remaining_seconds=12.5,
        parameters={"primal_cvp_mode": "nearest_plane"},
        exclude_secret=(1, 2),
    )
    assert nested.seed == 17
    assert nested.max_seconds == 12.5
    assert nested.single_worker is True
    assert nested.work_dir == tmp_path.resolve()
    assert dict(nested.parameters) == {"primal_cvp_mode": "nearest_plane"}
    assert nested.exclude_secret == (1, 2)


def test_nested_dispatch_uses_primal_directly_and_preserves_request(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.primal_bdd as primal_module
    from tools.solvers import registry

    observed: dict[str, object] = {}

    class FakeSolver:
        def solve(self, instance, nested_request):
            observed["instance"] = instance
            observed["request"] = nested_request
            return SolveResult.censored(elapsed_seconds=0.1, work_units=1)

    monkeypatch.setattr(primal_module, "PrimalBDD", FakeSolver)
    monkeypatch.setattr(
        registry,
        "load_registry",
        lambda: pytest.fail("nested dispatch must not revalidate the registry per guess"),
    )
    nested_request = SolveRequest(seed=1, max_seconds=1.0, work_dir=tmp_path)
    problem = object()
    result = dispatch_registered_primal(problem, nested_request)
    assert result.status is SolveStatus.CENSORED
    assert observed == {"instance": problem, "request": nested_request}
    assert nested_request.single_worker is True


def test_hybrid_translates_nested_exclusion_and_skips_an_excluded_merge(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.small_secret_hybrid as hybrid_module

    class Verdict:
        def __init__(self, ok: bool) -> None:
            self.ok = ok

    problem = SimpleNamespace(
        instance_id="public-fake",
        instance_digest="0" * 64,
        n=2,
        m=3,
        q=5,
        b=(0, 0, 0),
        family="DS_SMALL",
        secret_predicate_kind="alphabet",
        secret_alphabet=(0, 1),
        secret_min_nonzero=0,
        secret_max_nonzero=2,
        error_max_abs=1,
        error_max_l1=1,
        error_max_l2_squared=1,
        error_max_nonzero=1,
        materialize_row_block=lambda start, stop: (
            (1, 0),
            (0, 1),
            (1, 1),
        )[start:stop],
        validate_secret=lambda candidate: Verdict(candidate == (0, 1)),
    )
    observed_exclusions: list[tuple[int, ...] | None] = []
    observed_exact_caps: list[object] = []

    def fake_dispatch(reduced, nested_request):
        assert reduced.materialize_row_block(0, 2) == ((1,), (0,))
        observed_exclusions.append(nested_request.exclude_secret)
        observed_exact_caps.append(
            nested_request.parameters.get("primal_exact_verification_cap")
        )
        # Deliberately return the excluded nested candidate on the first guess;
        # the outer solver must skip it rather than converting it to ERROR.
        return SolveResult.success(
            secret=(0,),
            elapsed_seconds=0.01,
            work_units=1,
        )

    monkeypatch.setattr(hybrid_module, "dispatch_registered_primal", fake_dispatch)
    result = SmallSecretHybrid()._solve(
        problem,
        SolveRequest(
            seed=29,
            max_seconds=10.0,
            work_dir=tmp_path,
            exclude_secret=(0, 0),
            parameters={
                "hybrid_guess_count": 1,
                "primal_cvp_mode": "exact_cvp",
                "primal_exact_verification_cap": 37,
            },
        ),
    )
    assert observed_exclusions == [(0,), None]
    assert observed_exact_caps == [37, 37]
    assert result.status is SolveStatus.SUCCESS
    assert result.secret == (0, 1)


def _static_hybrid_problem(*, block_calls: list[tuple[int, int]]):
    rows = ((1, 0), (0, 1), (1, 1))

    def materialize_row_block(start: int, stop: int):
        block_calls.append((start, stop))
        return rows[start:stop]

    return SimpleNamespace(
        instance_id="hybrid-static",
        instance_digest="f" * 64,
        n=2,
        m=3,
        q=5,
        b=(0, 0, 0),
        family="DS_SMALL",
        secret_predicate_kind="alphabet",
        secret_alphabet=(0, 1),
        secret_min_nonzero=0,
        secret_max_nonzero=2,
        error_max_abs=1,
        error_max_l1=1,
        error_max_l2_squared=1,
        error_max_nonzero=1,
        materialize_rows=lambda: pytest.fail("unbounded row materialization"),
        materialize_row_block=materialize_row_block,
        validate_secret=lambda _candidate: SimpleNamespace(ok=False),
    )


def test_hybrid_memory_cap_precedes_reduction_and_nested_dispatch(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.small_secret_hybrid as hybrid_module

    monkeypatch.setattr(
        hybrid_module,
        "dispatch_registered_primal",
        lambda *_args, **_kwargs: pytest.fail("nested solver must not start"),
    )
    calls: list[tuple[int, int]] = []
    result = SmallSecretHybrid()._solve(
        _static_hybrid_problem(block_calls=calls),
        SolveRequest(
            seed=41,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters={
                "hybrid_guess_count": 1,
                "memory_cap_bytes": 1,
            },
        ),
    )
    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == "memory_cap"
    assert calls == []


def test_hybrid_outer_checkpoint_resume_and_nested_budget_binding(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.small_secret_hybrid as hybrid_module

    observed_requests: list[SolveRequest] = []

    def fake_dispatch(_reduced, nested_request):
        observed_requests.append(nested_request)
        return SolveResult.censored(
            elapsed_seconds=0.01,
            work_units=2,
            peak_rss_bytes=123,
            checkpoint_count=3,
            detail={"code": "nearest_plane_candidate_rejected"},
        )

    monkeypatch.setattr(hybrid_module, "dispatch_registered_primal", fake_dispatch)
    parameters = {
        "hybrid_guess_count": 1,
        "hybrid_work_unit_cap": 1,
        "memory_cap_bytes": 512 * 1024 * 1024,
        "primal_cvp_mode": "exact_cvp",
        "primal_exact_verification_cap": 17,
        "work_unit_cap": 50,
    }
    first = SmallSecretHybrid()._solve(
        _static_hybrid_problem(block_calls=[]),
        SolveRequest(
            seed=43,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters=parameters,
            checkpoint_every_work_units=1,
        ),
    )
    assert first.status is SolveStatus.CENSORED
    assert first.work_units == 3
    assert first.checkpoint_count >= 4
    assert len(observed_requests) == 1
    nested_request = observed_requests[0]
    assert nested_request.parameters["memory_cap_bytes"] == 512 * 1024 * 1024
    assert nested_request.parameters["primal_exact_verification_cap"] == 17
    assert nested_request.parameters["work_unit_cap"] == 49
    assert nested_request.work_dir.parent.name == "hybrid-nested"

    checkpoint = tmp_path / "small_secret_hybrid.checkpoint.json"
    assert checkpoint.is_file()
    observed_requests.clear()
    resumed = SmallSecretHybrid()._solve(
        _static_hybrid_problem(block_calls=[]),
        SolveRequest(
            seed=43,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters=parameters,
            resume_checkpoint=checkpoint,
            checkpoint_every_work_units=1,
        ),
    )
    assert resumed.status is SolveStatus.CENSORED
    assert resumed.work_units == 3
    assert observed_requests == []


def test_hybrid_fresh_run_ignores_a_stale_per_guess_primal_checkpoint(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.small_secret_hybrid as hybrid_module

    nested_checkpoint = (
        tmp_path
        / "hybrid-nested"
        / "guess-0"
        / "primal_bdd.checkpoint.json"
    )
    nested_checkpoint.parent.mkdir(parents=True)
    nested_checkpoint.write_text("{}\n", encoding="ascii")
    observed: list[SolveRequest] = []

    def fake_dispatch(_reduced, nested_request):
        observed.append(nested_request)
        return SolveResult.censored(
            elapsed_seconds=0.01,
            work_units=1,
            detail={"reason": "work_unit_cap"},
        )

    monkeypatch.setattr(hybrid_module, "dispatch_registered_primal", fake_dispatch)
    result = SmallSecretHybrid()._solve(
        _static_hybrid_problem(block_calls=[]),
        SolveRequest(
            seed=47,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters={
                "hybrid_guess_count": 1,
                "hybrid_work_unit_cap": 1,
                "work_unit_cap": 10,
            },
        ),
    )
    assert result.status is SolveStatus.CENSORED
    assert len(observed) == 1
    assert observed[0].resume_checkpoint is None
    assert observed[0].work_dir != nested_checkpoint.parent.resolve()


def test_hybrid_reduced_problem_runs_through_real_primal_preprocessing(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.primal_bdd as primal_module
    import tools.solvers.small_secret_hybrid as hybrid_module

    _set_single_thread_policy(monkeypatch)
    monkeypatch.setattr(
        primal_module,
        "run_deadline_bounded_backend",
        lambda *_args, **_kwargs: BackendOutcome("ok", (0, 0, 0)),
    )
    monkeypatch.setattr(
        hybrid_module,
        "dispatch_registered_primal",
        lambda reduced, nested_request: PrimalBDD()._solve(
            reduced,
            nested_request,
        ),
    )
    problem = _static_hybrid_problem(block_calls=[])
    problem.validate_secret = lambda candidate: SimpleNamespace(
        ok=candidate == (0, 0)
    )
    result = SmallSecretHybrid()._solve(
        problem,
        SolveRequest(
            seed=61,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters={"hybrid_guess_count": 1},
        ),
    )
    assert result.status is SolveStatus.SUCCESS
    assert result.secret == (0, 0)


def test_hybrid_reuses_inner_checkpoint_after_interrupted_dispatch(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.primal_bdd as primal_module
    import tools.solvers.small_secret_hybrid as hybrid_module

    _set_single_thread_policy(monkeypatch)
    backend_calls = 0

    def fake_backend(*_args, **_kwargs):
        nonlocal backend_calls
        backend_calls += 1
        return BackendOutcome("ok", (0, 0, 0))

    monkeypatch.setattr(
        primal_module,
        "run_deadline_bounded_backend",
        fake_backend,
    )
    dispatch_calls = 0

    def interrupted_dispatch(reduced, nested_request):
        nonlocal dispatch_calls
        dispatch_calls += 1
        result = PrimalBDD()._solve(reduced, nested_request)
        if dispatch_calls == 1:
            raise RuntimeError("simulated interruption after inner checkpoint")
        return result

    monkeypatch.setattr(
        hybrid_module,
        "dispatch_registered_primal",
        interrupted_dispatch,
    )
    problem = _static_hybrid_problem(block_calls=[])
    problem.validate_secret = lambda candidate: SimpleNamespace(
        ok=candidate == (0, 0)
    )
    outer_request = SolveRequest(
        seed=67,
        max_seconds=10.0,
        work_dir=tmp_path,
        parameters={
            "hybrid_guess_count": 1,
            "hybrid_work_unit_cap": 1,
        },
        checkpoint_every_work_units=1,
    )
    with pytest.raises(RuntimeError, match="simulated interruption"):
        SmallSecretHybrid()._solve(problem, outer_request)
    nested_checkpoints = list(
        (tmp_path / "hybrid-nested").glob(
            "guess-0-*/primal_bdd.checkpoint.json"
        )
    )
    assert len(nested_checkpoints) == 1

    resumed = SmallSecretHybrid()._solve(
        problem,
        replace(
            outer_request,
            resume_checkpoint=tmp_path / "small_secret_hybrid.checkpoint.json",
        ),
    )
    assert resumed.status is SolveStatus.SUCCESS, resumed.detail
    assert backend_calls == 1


def test_hybrid_resume_revalidates_a_checkpointed_pending_success(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.small_secret_hybrid as hybrid_module

    dispatch_calls = 0

    def successful_dispatch(_reduced, _nested_request):
        nonlocal dispatch_calls
        dispatch_calls += 1
        return SolveResult.success(
            secret=(0,),
            elapsed_seconds=0.01,
            work_units=1,
        )

    monkeypatch.setattr(
        hybrid_module,
        "dispatch_registered_primal",
        successful_dispatch,
    )
    validation_calls = 0
    problem = _static_hybrid_problem(block_calls=[])

    def interrupted_validation(candidate):
        nonlocal validation_calls
        validation_calls += 1
        assert candidate == (0, 0)
        if validation_calls == 1:
            raise RuntimeError("simulated interruption before hybrid success")
        return SimpleNamespace(ok=True)

    problem.validate_secret = interrupted_validation
    request = SolveRequest(
        seed=83,
        max_seconds=10.0,
        work_dir=tmp_path,
        parameters={
            "hybrid_guess_count": 1,
            "hybrid_work_unit_cap": 1,
        },
        checkpoint_every_work_units=1,
    )
    with pytest.raises(RuntimeError, match="simulated interruption"):
        SmallSecretHybrid()._solve(problem, request)

    resumed = SmallSecretHybrid()._solve(
        problem,
        replace(
            request,
            resume_checkpoint=tmp_path / "small_secret_hybrid.checkpoint.json",
        ),
    )
    assert resumed.status is SolveStatus.SUCCESS
    assert resumed.secret == (0, 0)
    assert dispatch_calls == 1


def test_hybrid_resume_charges_cumulative_nested_elapsed_before_later_guesses(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import tools.solvers.small_secret_hybrid as hybrid_module

    dispatch_calls = 0

    def interrupted_then_cumulative(_reduced, _nested_request):
        nonlocal dispatch_calls
        dispatch_calls += 1
        if dispatch_calls == 1:
            raise RuntimeError("simulated interruption during nested guess")
        if dispatch_calls > 2:
            pytest.fail("cumulative nested time must stop later outer guesses")
        return SolveResult.censored(
            elapsed_seconds=10.0,
            work_units=1,
            detail={"code": "nested_incomplete"},
        )

    monkeypatch.setattr(
        hybrid_module,
        "dispatch_registered_primal",
        interrupted_then_cumulative,
    )
    request = SolveRequest(
        seed=73,
        max_seconds=10.0,
        work_dir=tmp_path,
        parameters={
            "hybrid_guess_count": 1,
            "hybrid_work_unit_cap": 2,
        },
        checkpoint_every_work_units=1,
    )
    problem = _static_hybrid_problem(block_calls=[])
    with pytest.raises(RuntimeError, match="simulated interruption"):
        SmallSecretHybrid()._solve(problem, request)

    resumed = SmallSecretHybrid()._solve(
        problem,
        replace(
            request,
            resume_checkpoint=tmp_path / "small_secret_hybrid.checkpoint.json",
        ),
    )
    assert resumed.status is SolveStatus.CENSORED
    assert resumed.detail["reason"] == "time_cap"
    assert resumed.elapsed_seconds >= 10.0
    assert dispatch_calls == 2


def test_nested_censor_and_error_propagation_are_closed_and_witness_free() -> None:
    censored = propagate_nested_result(
        SolveResult.censored(elapsed_seconds=1.0, work_units=3, detail={"code": "timeout"}),
        elapsed_seconds=2.0,
        outer_work_units=4,
    )
    assert censored.status is SolveStatus.CENSORED
    assert censored.work_units == 7
    assert censored.detail == {"code": "nested_primal_censored"}

    error = propagate_nested_result(
        SolveResult.error(elapsed_seconds=1.0, work_units=2, detail={"code": "dependency_unavailable"}),
        elapsed_seconds=2.0,
        outer_work_units=4,
    )
    assert error.status is SolveStatus.ERROR
    assert error.work_units == 6
    assert error.detail == {"code": "nested_primal_error"}

    incomplete = propagate_nested_result(
        SolveResult.exhausted(elapsed_seconds=1.0, work_units=2),
        elapsed_seconds=2.0,
        outer_work_units=4,
    )
    assert incomplete.status is SolveStatus.CENSORED
    assert incomplete.detail == {
        "code": "nested_primal_exhausted_without_outer_certificate"
    }

    with pytest.raises(ValueError, match="successful"):
        propagate_nested_result(
            SolveResult.success(secret=(1,), elapsed_seconds=0.1, work_units=1),
            elapsed_seconds=0.2,
            outer_work_units=1,
        )


def test_hybrid_applicability_requires_a_declared_small_alphabet_and_remaining_dimension() -> None:
    base = dict(
        n=4,
        q=17,
        family="DS_SMALL",
        secret_predicate_kind="alphabet",
        secret_alphabet=(-2, -1, 0, 1, 2),
    )
    assert hybrid_applicability(SimpleNamespace(**base), request(hybrid_guess_count=2))
    assert not hybrid_applicability(SimpleNamespace(**{**base, "family": "DA_TER"}), request())
    assert not hybrid_applicability(SimpleNamespace(**{**base, "secret_predicate_kind": "mod_q"}), request())
    assert not hybrid_applicability(SimpleNamespace(**{**base, "secret_alphabet": tuple(range(17))}), request())
    assert not hybrid_applicability(SimpleNamespace(**base), request(hybrid_guess_count=4))


@pytest.mark.recovery
def test_clean_subset_recovers(sparse_error_fixture, tmp_path: Path) -> None:
    result = CleanSubsetRecovery().solve(
        sparse_error_fixture,
        request(work_dir=tmp_path, clean_subset_cap=200),
    )
    assert result.status is SolveStatus.SUCCESS
    assert sparse_error_fixture.validate_secret(result.secret).ok


@pytest.mark.recovery
def test_primal_bdd_recovers(primal_fixture, tmp_path: Path) -> None:
    assert not primal_fixture.validate_secret((0,) * primal_fixture.n).ok
    result = PrimalBDD().solve(
        primal_fixture,
        request(work_dir=tmp_path, primal_cvp_mode="nearest_plane"),
    )
    assert result.status is SolveStatus.SUCCESS
    assert primal_fixture.validate_secret(result.secret).ok


@pytest.mark.recovery
def test_small_secret_hybrid_recovers(hybrid_fixture, tmp_path: Path) -> None:
    result = SmallSecretHybrid().solve(
        hybrid_fixture,
        request(
            work_dir=tmp_path,
            hybrid_guess_count=1,
            primal_cvp_mode="nearest_plane",
        ),
    )
    assert result.status is SolveStatus.SUCCESS
    assert hybrid_fixture.validate_secret(result.secret).ok


@pytest.mark.recovery
def test_generic_timeout_and_nonapplicability_never_claim_exhaustion(
    sparse_error_fixture,
    hybrid_fixture,
    tmp_path: Path,
) -> None:
    tiny = SolveRequest(
        seed=19,
        max_seconds=1e-12,
        work_dir=tmp_path / "clean-subset",
        parameters={"clean_subset_cap": 1},
    )
    assert CleanSubsetRecovery().solve(sparse_error_fixture, tiny).status is SolveStatus.CENSORED

    hybrid_tiny = SolveRequest(
        seed=23,
        max_seconds=1e-12,
        work_dir=tmp_path / "hybrid",
        parameters={"hybrid_guess_count": 1},
    )
    assert SmallSecretHybrid().solve(hybrid_fixture, hybrid_tiny).status is SolveStatus.CENSORED

    composite = SimpleNamespace(
        n=1,
        m=2,
        q=8,
        materialize_rows=lambda: ((1,), (1,)),
    )
    assert PrimalBDD().solve(composite, request()).status is SolveStatus.CENSORED
