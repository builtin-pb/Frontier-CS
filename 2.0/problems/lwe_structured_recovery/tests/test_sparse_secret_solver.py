from __future__ import annotations

import inspect
import json
import shutil
from dataclasses import dataclass, field, replace
from math import comb
from pathlib import Path
from types import SimpleNamespace

import pytest

import tools.solvers.sparse_secret as sparse_secret_module
from tools.solvers.api import (
    CheckpointStore,
    SolveRequest,
    SolveResult,
    SolveStatus,
    SolverContractError,
    scrub_result,
)
from tools.solvers.sparse_secret import (
    _RangeLedger,
    _RetainedMemoryBudget,
    _SparseRunProtocol,
    SparseSecretEnumerator,
    SparseSecretMitM,
    CoverageRange,
    MitmCoverageManifest,
    build_mitm_coverage_manifest,
    budget_stop_result,
    centered_representative,
    checkpoint_ranges,
    coverage_summary,
    complete_domain_certificate,
    complete_mitm_certificate,
    cyclic_bucket_index,
    cyclic_neighborhood_bucket_keys,
    enumerator_applicability,
    iter_exact_weight_candidates,
    inapplicable_result,
    iter_cyclic_neighborhood_bucket_keys,
    memory_censored_result,
    mitm_applicability,
    mitm_partition_counts,
    select_mitm_rows,
    sparse_secret_domain_size,
    split_coordinate_ranges,
    streaming_residual_feasible,
    timeout_result,
    traversal_stop_reason,
    verify_mitm_coverage,
    verify_public_mitm_certificate,
    verify_coverage_summary,
    verify_ordered_ranges,
)


@dataclass
class _RecordingProblem:
    rows: tuple[tuple[int, ...], ...]
    b: tuple[int, ...]
    q: int = 101
    error_max_abs: int = 100
    error_max_l1: int | None = None
    error_max_l2_squared: int | None = None
    error_max_nonzero: int | None = None
    yielded: list[int] = field(default_factory=list)
    secret_distribution_kind: str = "exact_weight_alphabet"
    secret_alphabet: tuple[int, ...] = (0, 1)
    secret_weight: int | None = 1
    m: int = field(init=False)
    n: int = field(init=False)

    def __post_init__(self) -> None:
        self.m = len(self.rows)
        self.n = len(self.rows[0]) if self.rows else 1

    def iter_rows(self):
        for index, row in enumerate(self.rows):
            self.yielded.append(index)
            yield row

    def materialize_row_block(self, start: int, stop: int):
        return self.rows[start:stop]


def _problem_for_residuals(
    residuals: tuple[int, ...],
    *,
    max_abs: int,
    max_l1: int | None = None,
    max_l2: int | None = None,
    max_nonzero: int | None = None,
) -> _RecordingProblem:
    return _RecordingProblem(
        rows=tuple((0,) for _ in residuals),
        b=residuals,
        error_max_abs=max_abs,
        error_max_l1=max_l1,
        error_max_l2_squared=max_l2,
        error_max_nonzero=max_nonzero,
    )


def _static_mitm_manifest() -> MitmCoverageManifest:
    problem = _RecordingProblem(
        rows=((1, 0), (0, 1)),
        b=(1, 0),
        q=17,
        error_max_abs=1,
        error_max_l1=1,
        error_max_l2_squared=1,
        error_max_nonzero=1,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[attr-defined]
        ok=False
    )
    request = SolveRequest(
        seed=3,
        max_seconds=1.0,
        work_dir=Path("/private/tmp/frontier-cs-task4-static"),
        parameters={"mitm_row_count": 2},
        checkpoint_every_work_units=2,
    )
    return build_mitm_coverage_manifest(problem, request)


def _checkpoint_problem() -> _RecordingProblem:
    problem = _RecordingProblem(rows=((1, 0),), b=(1,))
    problem.instance_id = "checkpoint_fixture"  # type: ignore[attr-defined]
    problem.instance_digest = "1" * 64  # type: ignore[attr-defined]
    return problem


def test_sparse_run_protocol_resumes_and_emits_typed_monotone_progress(
    tmp_path: Path,
) -> None:
    problem = _checkpoint_problem()
    request = SolveRequest(
        seed=7,
        max_seconds=10.0,
        work_dir=tmp_path,
        checkpoint_every_work_units=2,
    )
    descriptor = {"kind": "enum", "domain_size": 5, "unit_cost": 3}
    first = _SparseRunProtocol.create(
        instance=problem,
        request=request,
        solver_id="sparse_secret_enum",
        solver_revision="task4-enum-v2",
        search_descriptor=descriptor,
        domain_size=5,
        minimum_work=lambda ordinal: ordinal * 3,
    )
    first.advance(next_ordinal=2, work_units=6, phase="enumerating")
    checkpoint = first.checkpoint(force=True)
    assert checkpoint is not None and checkpoint.is_file()

    resumed_request = replace(request, resume_checkpoint=checkpoint)
    resumed = _SparseRunProtocol.create(
        instance=problem,
        request=resumed_request,
        solver_id="sparse_secret_enum",
        solver_revision="task4-enum-v2",
        search_descriptor=descriptor,
        domain_size=5,
        minimum_work=lambda ordinal: ordinal * 3,
    )
    assert (resumed.next_ordinal, resumed.work_units) == (2, 6)
    resumed.elapsed_base = 4.0
    assert (
        sparse_secret_module._cumulative_deadline(resumed) - resumed.started
    ) == pytest.approx(6.0)
    resumed.advance(next_ordinal=3, work_units=9, phase="enumerating")
    resumed.checkpoint(force=True)
    records = (tmp_path / "sparse_secret_enum.progress.jsonl").read_text().splitlines()
    assert len(records) == 3
    decoded = tuple(json.loads(record) for record in records)
    assert decoded[1]["phase"] == "resume"
    assert decoded[2]["elapsed_seconds"] >= decoded[1]["elapsed_seconds"]
    loaded = resumed.store.load(checkpoint)
    assert loaded is not None
    assert loaded["elapsed_seconds"] == decoded[2]["elapsed_seconds"]


@pytest.mark.parametrize(
    "forgery",
    [
        {"next_ordinal": True},
        {"next_ordinal": 6},
        {"work_units": 0},
        {"search_digest": "0" * 64},
        {"domain_size": False},
        {"checkpoint_count": -1},
        {"elapsed_seconds": True},
        {"unexpected": 1},
    ],
)
def test_sparse_run_protocol_rejects_hostile_or_mismatched_state(
    tmp_path: Path, forgery: dict[str, object]
) -> None:
    problem = _checkpoint_problem()
    request = SolveRequest(seed=7, max_seconds=10.0, work_dir=tmp_path)
    descriptor = {"kind": "mitm", "domain_size": 5, "rows": (0,)}
    protocol = _SparseRunProtocol.create(
        instance=problem,
        request=request,
        solver_id="sparse_secret_mitm",
        solver_revision="task4-mitm-v2",
        search_descriptor=descriptor,
        domain_size=5,
        minimum_work=lambda ordinal: ordinal + 4,
    )
    state = protocol.checkpoint_state(
        next_ordinal=2, work_units=6, checkpoint_count=1
    )
    state.update(forgery)
    store = CheckpointStore(
        work_dir=tmp_path,
        solver_id="sparse_secret_mitm",
        solver_revision="task4-mitm-v2",
        instance_digest=problem.instance_digest,  # type: ignore[attr-defined]
        seed=7,
    )
    path = store.save(state, work_units=6)
    with pytest.raises(SolverContractError, match="checkpoint"):
        _SparseRunProtocol.create(
            instance=problem,
            request=replace(request, resume_checkpoint=path),
            solver_id="sparse_secret_mitm",
            solver_revision="task4-mitm-v2",
            search_descriptor=descriptor,
            domain_size=5,
            minimum_work=lambda ordinal: ordinal + 4,
        )


def test_sparse_checkpoint_state_binds_canonical_phase_and_phase_ordinal(
    tmp_path: Path,
) -> None:
    problem = _checkpoint_problem()
    request = SolveRequest(seed=7, max_seconds=10.0, work_dir=tmp_path)
    descriptor = {"kind": "mitm", "left_domain_size": 3, "right_domain_size": 2}
    protocol = _SparseRunProtocol.create(
        instance=problem,
        request=request,
        solver_id="sparse_secret_mitm",
        solver_revision="task4-mitm-v3",
        search_descriptor=descriptor,
        domain_size=5,
        minimum_work=lambda ordinal: ordinal,
        phase_sizes=(("mitm_left", 3), ("mitm_right", 2)),
    )
    state = protocol.checkpoint_state(
        next_ordinal=2, work_units=2, checkpoint_count=1
    )
    assert (state["phase"], state["phase_ordinal"]) == ("mitm_left", 2)

    state["phase"] = "mitm_right"
    store = CheckpointStore(
        work_dir=tmp_path,
        solver_id="sparse_secret_mitm",
        solver_revision="task4-mitm-v3",
        instance_digest=problem.instance_digest,  # type: ignore[attr-defined]
        seed=7,
    )
    path = store.save(state, work_units=2)
    with pytest.raises(SolverContractError, match="checkpoint"):
        _SparseRunProtocol.create(
            instance=problem,
            request=replace(request, resume_checkpoint=path),
            solver_id="sparse_secret_mitm",
            solver_revision="task4-mitm-v3",
            search_descriptor=descriptor,
            domain_size=5,
            minimum_work=lambda ordinal: ordinal,
            phase_sizes=(("mitm_left", 3), ("mitm_right", 2)),
        )


def test_sparse_resume_rejects_cumulative_work_or_elapsed_deflation(
    tmp_path: Path,
) -> None:
    problem = _checkpoint_problem()
    request = SolveRequest(seed=7, max_seconds=10.0, work_dir=tmp_path)
    descriptor = {"kind": "enum", "domain_size": 5}
    protocol = _SparseRunProtocol.create(
        instance=problem,
        request=request,
        solver_id="sparse_secret_enum",
        solver_revision="task4-enum-v3",
        search_descriptor=descriptor,
        domain_size=5,
        minimum_work=lambda ordinal: ordinal,
    )
    protocol.advance(next_ordinal=2, work_units=10, phase="enumerating")
    original_path = protocol.checkpoint(force=True)
    assert original_path is not None
    loaded = protocol.store.load(original_path)
    assert loaded is not None
    forged = dict(loaded)
    forged["work_units"] = 2
    forged["elapsed_seconds"] = 0.0
    forged_path = protocol.store.save(
        forged, work_units=2, path=tmp_path / "forged.checkpoint.json"
    )

    with pytest.raises(SolverContractError, match="progress chain"):
        _SparseRunProtocol.create(
            instance=problem,
            request=replace(request, resume_checkpoint=forged_path),
            solver_id="sparse_secret_enum",
            solver_revision="task4-enum-v3",
            search_descriptor=descriptor,
            domain_size=5,
            minimum_work=lambda ordinal: ordinal,
        )


def test_sparse_resume_rejects_checkpoint_copied_to_another_work_directory(
    tmp_path: Path,
) -> None:
    problem = _checkpoint_problem()
    original_dir = tmp_path / "original"
    request = SolveRequest(seed=7, max_seconds=10.0, work_dir=original_dir)
    descriptor = {"kind": "enum", "domain_size": 5}
    protocol = _SparseRunProtocol.create(
        instance=problem,
        request=request,
        solver_id="sparse_secret_enum",
        solver_revision="task4-enum-v3",
        search_descriptor=descriptor,
        domain_size=5,
        minimum_work=lambda ordinal: ordinal,
    )
    protocol.advance(next_ordinal=2, work_units=10, phase="enumerating")
    checkpoint = protocol.checkpoint(force=True)
    assert checkpoint is not None

    copied_dir = tmp_path / "copied"
    copied_dir.mkdir()
    copied_checkpoint = copied_dir / checkpoint.name
    shutil.copyfile(checkpoint, copied_checkpoint)

    with pytest.raises(SolverContractError, match="progress identity"):
        _SparseRunProtocol.create(
            instance=problem,
            request=replace(
                request,
                work_dir=copied_dir,
                resume_checkpoint=copied_checkpoint,
            ),
            solver_id="sparse_secret_enum",
            solver_revision="task4-enum-v3",
            search_descriptor=descriptor,
            domain_size=5,
            minimum_work=lambda ordinal: ordinal,
        )


def test_sparse_resume_rejects_checkpoint_orphaned_from_progress_chain(
    tmp_path: Path,
) -> None:
    problem = _checkpoint_problem()
    request = SolveRequest(seed=7, max_seconds=10.0, work_dir=tmp_path)
    descriptor = {"kind": "enum", "domain_size": 5}
    protocol = _SparseRunProtocol.create(
        instance=problem,
        request=request,
        solver_id="sparse_secret_enum",
        solver_revision="task4-enum-v3",
        search_descriptor=descriptor,
        domain_size=5,
        minimum_work=lambda ordinal: ordinal,
    )
    protocol.advance(next_ordinal=2, work_units=10, phase="enumerating")
    checkpoint = protocol.checkpoint(force=True)
    assert checkpoint is not None
    (tmp_path / "sparse_secret_enum.progress.jsonl").unlink()

    with pytest.raises(SolverContractError, match="progress chain"):
        _SparseRunProtocol.create(
            instance=problem,
            request=replace(request, resume_checkpoint=checkpoint),
            solver_id="sparse_secret_enum",
            solver_revision="task4-enum-v3",
            search_descriptor=descriptor,
            domain_size=5,
            minimum_work=lambda ordinal: ordinal,
        )


def test_sparse_checkpoint_binds_exclusion_seed_and_solver_identity(
    tmp_path: Path,
) -> None:
    problem = _checkpoint_problem()
    request = SolveRequest(seed=7, max_seconds=10.0, work_dir=tmp_path)
    descriptor = {"kind": "enum", "domain_size": 2}
    protocol = _SparseRunProtocol.create(
        instance=problem,
        request=request,
        solver_id="sparse_secret_enum",
        solver_revision="task4-enum-v2",
        search_descriptor=descriptor,
        domain_size=2,
        minimum_work=lambda ordinal: ordinal,
    )
    protocol.advance(next_ordinal=1, work_units=1, phase="enumerating")
    path = protocol.checkpoint(force=True)
    assert path is not None

    variants = (
        (
            replace(request, resume_checkpoint=path, exclude_secret=(1, 0)),
            "sparse_secret_enum",
            "task4-enum-v2",
        ),
        (
            replace(request, resume_checkpoint=path, seed=8),
            "sparse_secret_enum",
            "task4-enum-v2",
        ),
        (
            replace(request, resume_checkpoint=path),
            "sparse_secret_mitm",
            "task4-mitm-v2",
        ),
    )
    for resumed_request, solver_id, revision in variants:
        with pytest.raises(
            SolverContractError, match="checkpoint|progress identity"
        ):
            _SparseRunProtocol.create(
                instance=problem,
                request=resumed_request,
                solver_id=solver_id,
                solver_revision=revision,
                search_descriptor=descriptor,
                domain_size=2,
                minimum_work=lambda ordinal: ordinal,
            )


def test_work_callbacks_cover_residual_and_syndrome_inner_loops() -> None:
    problem = _RecordingProblem(rows=((1, 2), (3, 4)), b=(0, 0))
    charged: list[str] = []
    assert streaming_residual_feasible(
        problem, (0, 0), charge_work=lambda phase: charged.append(phase)
    )
    assert charged == [
        "residual_coefficient",
        "residual_coefficient",
        "residual_row",
        "residual_coefficient",
        "residual_coefficient",
        "residual_row",
    ]

    charged.clear()
    assert sparse_secret_module._syndrome(
        problem.rows,
        (0, 0),
        problem.q,
        charge_work=lambda phase: charged.append(phase),
    ) == (0, 0)
    assert charged == [
        "syndrome_coefficient",
        "syndrome_coefficient",
        "syndrome_row",
        "syndrome_coefficient",
        "syndrome_coefficient",
        "syndrome_row",
    ]


def test_residual_budget_check_runs_before_fetching_the_first_row() -> None:
    problem = _RecordingProblem(rows=((1, 2), (3, 4)), b=(0, 0))

    def stop() -> None:
        raise RuntimeError("deadline")

    with pytest.raises(RuntimeError, match="deadline"):
        streaming_residual_feasible(
            problem, (0, 0), check_budget=stop
        )
    assert problem.yielded == []


def test_retained_memory_budget_is_global_and_preallocation_safe() -> None:
    budget = _RetainedMemoryBudget(cap_bytes=100, rss_reader=lambda: 10)
    budget.retain(60)
    budget.preflight(30)
    with pytest.raises(RuntimeError):
        budget.preflight(31)
    with pytest.raises(RuntimeError):
        budget.retain(31)
    assert budget.retained_bytes == 60
    budget.release(25)
    assert budget.retained_bytes == 35


def test_enumerator_rechecks_deadline_after_public_validator_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]
    problem = _ExplicitRecoveryProblem(
        rows=((0,),),
        b=(0,),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )

    def validate(candidate):
        del candidate
        now[0] = 2.0
        return SimpleNamespace(ok=True)

    problem.validate_secret = validate  # type: ignore[method-assign]
    traversal_budget = sparse_secret_module._TraversalBudget

    def budget_with_fake_clock(**kwargs):
        return traversal_budget(**kwargs, clock=lambda: now[0])

    monkeypatch.setattr(sparse_secret_module, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        sparse_secret_module, "_TraversalBudget", budget_with_fake_clock
    )

    result = SparseSecretEnumerator()._solve(
        problem,
        SolveRequest(seed=1, max_seconds=1.0, work_dir=tmp_path),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == "time_cap"


def test_mitm_rechecks_deadline_after_public_validator_before_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]
    problem = _ExplicitRecoveryProblem(
        rows=((1, 0), (0, 1)),
        b=(1, 0),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )

    def validate(candidate):
        now[0] = 2.0
        return SimpleNamespace(ok=tuple(candidate) == (1, 0))

    problem.validate_secret = validate  # type: ignore[method-assign]
    traversal_budget = sparse_secret_module._TraversalBudget

    def budget_with_fake_clock(**kwargs):
        return traversal_budget(**kwargs, clock=lambda: now[0])

    monkeypatch.setattr(sparse_secret_module, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        sparse_secret_module, "_TraversalBudget", budget_with_fake_clock
    )

    result = SparseSecretMitM()._solve(
        problem,
        SolveRequest(
            seed=1,
            max_seconds=1.0,
            work_dir=tmp_path,
            parameters={"mitm_row_count": 2},
        ),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == "time_cap"


@pytest.mark.parametrize("stop_reason", ("time_cap", "memory_cap"))
def test_enumerator_rechecks_budget_after_terminal_success_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stop_reason: str,
) -> None:
    now = [0.0]
    over_memory_cap = [False]
    memory_cap = 1_000_000
    problem = _ExplicitRecoveryProblem(
        rows=((1,),),
        b=(1,),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    original_save = CheckpointStore.save

    def save_then_exceed_budget(self, state, *, work_units, path=None):
        saved = original_save(self, state, work_units=work_units, path=path)
        if saved.name == "sparse_secret_enum.checkpoint.json":
            if stop_reason == "time_cap":
                now[0] = 2.0
            else:
                over_memory_cap[0] = True
        return saved

    traversal_budget = sparse_secret_module._TraversalBudget

    def budget_with_fake_clock(**kwargs):
        return traversal_budget(**kwargs, clock=lambda: now[0])

    monkeypatch.setattr(sparse_secret_module, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        sparse_secret_module,
        "_peak_rss_bytes",
        lambda: memory_cap + 1 if over_memory_cap[0] else 0,
    )
    monkeypatch.setattr(
        sparse_secret_module, "_TraversalBudget", budget_with_fake_clock
    )
    monkeypatch.setattr(CheckpointStore, "save", save_then_exceed_budget)

    result = SparseSecretEnumerator()._solve(
        problem,
        SolveRequest(
            seed=1,
            max_seconds=1.0,
            work_dir=tmp_path,
            parameters={"memory_cap_bytes": memory_cap},
        ),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == stop_reason


def test_enumerator_rechecks_deadline_after_terminal_exhaustion_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]
    problem = _ExplicitRecoveryProblem(
        rows=((1,),),
        b=(8,),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[method-assign]
        ok=False
    )
    original_save = CheckpointStore.save

    def save_then_expire(self, state, *, work_units, path=None):
        saved = original_save(self, state, work_units=work_units, path=path)
        if saved.name == "sparse_secret_enum.checkpoint.json":
            now[0] = 2.0
        return saved

    traversal_budget = sparse_secret_module._TraversalBudget

    def budget_with_fake_clock(**kwargs):
        return traversal_budget(**kwargs, clock=lambda: now[0])

    monkeypatch.setattr(sparse_secret_module, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        sparse_secret_module, "_TraversalBudget", budget_with_fake_clock
    )
    monkeypatch.setattr(CheckpointStore, "save", save_then_expire)

    result = SparseSecretEnumerator()._solve(
        problem,
        SolveRequest(seed=1, max_seconds=1.0, work_dir=tmp_path),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == "time_cap"


@pytest.mark.parametrize(
    ("solver_kind", "checkpoint_name"),
    (
        ("enum", "sparse_secret_enum.checkpoint.json"),
        ("mitm", "sparse_secret_mitm.checkpoint.json"),
    ),
)
def test_terminal_success_checkpoint_revalidates_witness_after_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    solver_kind: str,
    checkpoint_name: str,
) -> None:
    class SimulatedProcessExit(BaseException):
        pass

    if solver_kind == "enum":
        solver = SparseSecretEnumerator()
        problem = _ExplicitRecoveryProblem(
            rows=((1,),),
            b=(1,),
            q=17,
            error_max_abs=0,
            secret_alphabet=(0, 1),
            secret_weight=1,
        )
        parameters: dict[str, int] = {}
    else:
        solver = SparseSecretMitM()
        problem = _ExplicitRecoveryProblem(
            rows=((1, 0), (0, 1)),
            b=(1, 0),
            q=17,
            error_max_abs=0,
            secret_alphabet=(0, 1),
            secret_weight=1,
        )
        parameters = {"mitm_row_count": 2}

    original_save = CheckpointStore.save

    def save_then_exit(self, state, *, work_units, path=None):
        saved = original_save(self, state, work_units=work_units, path=path)
        if saved.name == checkpoint_name:
            raise SimulatedProcessExit
        return saved

    request = SolveRequest(
        seed=1,
        max_seconds=10.0,
        work_dir=tmp_path,
        parameters=parameters,
    )
    monkeypatch.setattr(CheckpointStore, "save", save_then_exit)
    with pytest.raises(SimulatedProcessExit):
        solver._solve(problem, request)
    checkpoint_path = tmp_path / checkpoint_name
    assert checkpoint_path.is_file()

    monkeypatch.setattr(CheckpointStore, "save", original_save)
    resumed = solver._solve(
        problem,
        replace(request, resume_checkpoint=checkpoint_path),
    )

    assert resumed.status is SolveStatus.SUCCESS
    assert resumed.secret == tuple(1 if index == 0 else 0 for index in range(problem.n))


def test_actual_mitm_checkpoints_left_table_ordinal_and_resumes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    problem = _ExplicitRecoveryProblem(
        rows=((1, 0), (0, 1)),
        b=(8, 8),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[method-assign]
        ok=False
    )
    class SimulatedProcessExit(BaseException):
        pass

    recorded: list[dict[str, object]] = []
    original_save = CheckpointStore.save

    def recording_save(self, state, *, work_units, path=None):
        recorded.append(dict(state))
        saved = original_save(self, state, work_units=work_units, path=path)
        if state.get("phase") == "mitm_left":
            raise SimulatedProcessExit
        return saved

    monkeypatch.setattr(CheckpointStore, "save", recording_save)
    request = SolveRequest(
        seed=1,
        max_seconds=10.0,
        work_dir=tmp_path / "first",
        parameters={"mitm_row_count": 2},
        checkpoint_every_work_units=1,
    )
    with pytest.raises(SimulatedProcessExit):
        SparseSecretMitM()._solve(problem, request)
    left_states = [state for state in recorded if state.get("phase") == "mitm_left"]
    assert left_states
    assert [state["phase_ordinal"] for state in left_states] == sorted(
        state["phase_ordinal"] for state in left_states
    )

    monkeypatch.setattr(CheckpointStore, "save", original_save)
    resume_path = request.work_dir / "sparse_secret_mitm.checkpoint.json"
    resumed = SparseSecretMitM()._solve(
        problem,
        replace(request, resume_checkpoint=resume_path),
    )
    assert resumed.status is SolveStatus.EXHAUSTED


def test_actual_mitm_uses_live_rss_for_retained_and_transient_preflights(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cap = 1_000_000_000
    preflight_reads = 0

    def rising_rss() -> int:
        nonlocal preflight_reads
        caller = inspect.currentframe().f_back
        if caller is not None and caller.f_code.co_name == "preflight":
            preflight_reads += 1
            return cap + 1
        return 0

    problem = _ExplicitRecoveryProblem(
        rows=((1, 0), (0, 1)),
        b=(8, 8),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[method-assign]
        ok=False
    )
    monkeypatch.setattr(sparse_secret_module, "_peak_rss_bytes", rising_rss)

    result = SparseSecretMitM()._solve(
        problem,
        SolveRequest(
            seed=1,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters={
                "mitm_row_count": 2,
                "memory_cap_bytes": cap,
            },
        ),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == "memory_cap"
    assert preflight_reads >= 1


def test_actual_mitm_preflights_candidate_syndrome_key_and_retained_bucket_together(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    problem = _ExplicitRecoveryProblem(
        rows=((1,),),
        b=(8,),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[method-assign]
        ok=False
    )
    bucket_calls = 0
    original_bucket_index = sparse_secret_module.cyclic_bucket_index

    def recording_bucket_index(residue: int, *, q: int, bucket_width: int) -> int:
        nonlocal bucket_calls
        bucket_calls += 1
        return original_bucket_index(residue, q=q, bucket_width=bucket_width)

    monkeypatch.setattr(sparse_secret_module, "_peak_rss_bytes", lambda: 0)
    monkeypatch.setattr(
        sparse_secret_module, "cyclic_bucket_index", recording_bucket_index
    )
    result = SparseSecretMitM()._solve(
        problem,
        SolveRequest(
            seed=1,
            max_seconds=10.0,
            work_dir=tmp_path,
            parameters={
                "mitm_row_count": 1,
                "memory_cap_bytes": 750,
            },
        ),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == "memory_cap"
    assert bucket_calls == 0


def test_actual_enumerator_rejects_hostile_resume_counter_deflation(
    tmp_path: Path,
) -> None:
    problem = _ExplicitRecoveryProblem(
        rows=((1,),),
        b=(8,),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[method-assign]
        ok=False
    )
    request = SolveRequest(seed=1, max_seconds=10.0, work_dir=tmp_path)
    assert SparseSecretEnumerator()._solve(problem, request).status is SolveStatus.EXHAUSTED
    store = CheckpointStore(
        work_dir=tmp_path,
        solver_id="sparse_secret_enum",
        solver_revision="task4-enum-v3",
        instance_digest=problem.instance_digest,
        seed=1,
    )
    loaded = store.load()
    assert loaded is not None
    forged = dict(loaded)
    forged["work_units"] = forged["next_ordinal"]
    forged_path = store.save(
        forged,
        work_units=forged["work_units"],
        path=tmp_path / "forged-enum.checkpoint.json",
    )

    result = SparseSecretEnumerator()._solve(
        problem, replace(request, resume_checkpoint=forged_path)
    )
    assert result.status is SolveStatus.ERROR
    assert result.detail["code"] == "invalid_checkpoint"


def test_actual_enumerator_rejects_forged_exhaustion_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    problem = _ExplicitRecoveryProblem(
        rows=((1,),),
        b=(8,),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[method-assign]
        ok=False
    )
    original = sparse_secret_module.complete_domain_certificate
    calls = 0

    def forge_first_certificate(**kwargs):
        nonlocal calls
        calls += 1
        certificate = original(**kwargs)
        if calls == 1:
            certificate["certificate_digest"] = "0" * 64
        return certificate

    monkeypatch.setattr(
        sparse_secret_module,
        "complete_domain_certificate",
        forge_first_certificate,
    )
    result = SparseSecretEnumerator()._solve(
        problem, SolveRequest(seed=1, max_seconds=10.0, work_dir=tmp_path)
    )

    assert result.status is SolveStatus.ERROR
    assert result.detail["code"] == "coverage_verification_failed"
    assert calls == 2


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "10"])
def test_work_unit_cap_requires_an_exact_positive_integer(
    tmp_path: Path, value: object
) -> None:
    request = SolveRequest(
        seed=1,
        max_seconds=1.0,
        work_dir=tmp_path,
        parameters={"work_unit_cap": value},
    )
    with pytest.raises(ValueError, match="work_unit_cap"):
        sparse_secret_module._work_unit_cap(request)


def test_mitm_memory_cap_accounts_for_table_entries_after_rows(
    tmp_path: Path,
) -> None:
    problem = _RecordingProblem(
        rows=((1, 0, 0, 0),),
        b=(0,),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=2,
    )
    request = SolveRequest(
        seed=1,
        max_seconds=1.0,
        work_dir=tmp_path,
        parameters={"mitm_row_count": 1},
    )
    with pytest.raises(RuntimeError):
        build_mitm_coverage_manifest(
            problem,
            request,
            memory_cap_bytes=800,
            rss_reader=lambda: 0,
        )
    assert problem.yielded == []


def test_mitm_manifest_is_exclusion_free_but_public_certificate_rejects_exclusion(
    tmp_path: Path,
) -> None:
    problem = _RecordingProblem(
        rows=((1, 0), (0, 1)),
        b=(8, 8),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[attr-defined]
        ok=False
    )
    base = SolveRequest(
        seed=3,
        max_seconds=1.0,
        work_dir=tmp_path,
        parameters={"mitm_row_count": 2},
    )
    excluded = replace(base, exclude_secret=(1, 0))
    first = build_mitm_coverage_manifest(problem, base)
    second = build_mitm_coverage_manifest(problem, excluded)
    assert first == second
    assert not hasattr(first, "events")
    assert not hasattr(first, "excluded_count")
    certificate = complete_mitm_certificate(
        n=2,
        weight=1,
        alphabet_size=1,
        selected_rows=(0, 1),
        bucket_width=1,
        coverage_manifest=first,
    )
    verify_public_mitm_certificate(problem, base, certificate)
    with pytest.raises(ValueError, match="exclusion"):
        verify_public_mitm_certificate(problem, excluded, certificate)


def test_public_mitm_certificate_requires_exact_nested_json_types(
    tmp_path: Path,
) -> None:
    problem = _RecordingProblem(
        rows=((1, 0), (0, 1)),
        b=(8, 8),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[attr-defined]
        ok=False
    )
    request = SolveRequest(
        seed=3,
        max_seconds=1.0,
        work_dir=tmp_path,
        parameters={"mitm_row_count": 2},
    )
    manifest = build_mitm_coverage_manifest(problem, request)
    certificate = complete_mitm_certificate(
        n=2,
        weight=1,
        alphabet_size=1,
        selected_rows=(0, 1),
        bucket_width=1,
        coverage_manifest=manifest,
    )

    forged_bool = json.loads(json.dumps(certificate))
    forged_bool["public_parameters"]["alphabet_size"] = True
    with pytest.raises(ValueError, match="canonical JSON types"):
        verify_public_mitm_certificate(problem, request, forged_bool)

    forged_float = json.loads(json.dumps(certificate))
    forged_float["public_parameters"]["n"] = 2.0
    with pytest.raises(ValueError, match="canonical JSON types"):
        verify_public_mitm_certificate(problem, request, forged_float)

    class DictSubclass(dict):
        pass

    forged_container = json.loads(json.dumps(certificate))
    forged_container["public_parameters"] = DictSubclass(
        forged_container["public_parameters"]
    )
    with pytest.raises(ValueError, match="canonical JSON types"):
        verify_public_mitm_certificate(problem, request, forged_container)


def test_public_mitm_exhaustion_replay_rejects_a_valid_public_witness(
    tmp_path: Path,
) -> None:
    problem = _RecordingProblem(
        rows=((1, 0), (0, 1)),
        b=(1, 0),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[attr-defined]
        ok=tuple(candidate) == (1, 0)
    )
    request = SolveRequest(
        seed=1,
        max_seconds=1.0,
        work_dir=tmp_path,
        parameters={"mitm_row_count": 2},
    )
    manifest = build_mitm_coverage_manifest(problem, request)
    certificate = complete_mitm_certificate(
        n=2,
        weight=1,
        alphabet_size=1,
        selected_rows=(0, 1),
        bucket_width=1,
        coverage_manifest=manifest,
    )
    with pytest.raises(ValueError, match="valid witness"):
        verify_public_mitm_certificate(problem, request, certificate)


def test_public_enum_certificate_replay_rejects_forgery_and_exclusion(
    tmp_path: Path,
) -> None:
    problem = _RecordingProblem(
        rows=((1, 0), (0, 1)),
        b=(8, 8),
        q=17,
        error_max_abs=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    problem.validate_secret = lambda candidate: SimpleNamespace(  # type: ignore[attr-defined]
        ok=False
    )
    request = SolveRequest(seed=1, max_seconds=1.0, work_dir=tmp_path)
    domain_size = sparse_secret_domain_size(2, 1, 1)
    certificate = complete_domain_certificate(
        solver_id="sparse_secret_enum",
        n=2,
        weight=1,
        alphabet_size=1,
        tested_count=domain_size,
        traversal_ranges=coverage_summary(
            domain_size, request.checkpoint_every_work_units
        ),
        checkpoint_interval=request.checkpoint_every_work_units,
        excluded_count=0,
    )

    sparse_secret_module.verify_public_enum_certificate(
        problem, request, certificate
    )
    forged = json.loads(json.dumps(certificate))
    forged["public_parameters"]["candidate_count"] += 1
    with pytest.raises(ValueError, match="replay"):
        sparse_secret_module.verify_public_enum_certificate(
            problem, request, forged
        )
    with pytest.raises(ValueError, match="exclusion"):
        sparse_secret_module.verify_public_enum_certificate(
            problem, replace(request, exclude_secret=(1, 0)), certificate
        )

    forged_bool = json.loads(json.dumps(certificate))
    forged_bool["public_parameters"]["alphabet_size"] = True
    with pytest.raises(ValueError, match="canonical JSON types"):
        sparse_secret_module.verify_public_enum_certificate(
            problem, request, forged_bool
        )

    forged_float = json.loads(json.dumps(certificate))
    forged_float["public_parameters"]["n"] = 2.0
    with pytest.raises(ValueError, match="canonical JSON types"):
        sparse_secret_module.verify_public_enum_certificate(
            problem, request, forged_float
        )


def test_exact_weight_candidates_follow_support_then_alphabet_lexicographic_order() -> None:
    assert tuple(iter_exact_weight_candidates(3, 2, (1, -1))) == (
        (-1, -1, 0),
        (-1, 1, 0),
        (1, -1, 0),
        (1, 1, 0),
        (-1, 0, -1),
        (-1, 0, 1),
        (1, 0, -1),
        (1, 0, 1),
        (0, -1, -1),
        (0, -1, 1),
        (0, 1, -1),
        (0, 1, 1),
    )


def test_exact_weight_candidate_domain_has_no_duplicates() -> None:
    candidates = tuple(iter_exact_weight_candidates(5, 2, (-1, 1)))
    assert len(candidates) == sparse_secret_domain_size(5, 2, 2)
    assert len(set(candidates)) == len(candidates) == comb(5, 2) * 4


def test_balanced_planting_kind_keeps_full_signed_exact_weight_search_domain() -> None:
    problem = _RecordingProblem(
        rows=((1, 0), (0, 1)),
        b=(1, 1),
        q=17,
        error_max_abs=0,
        error_max_l1=0,
        error_max_l2_squared=0,
        error_max_nonzero=0,
        secret_distribution_kind="balanced_exact_weight_signed",
        secret_alphabet=(-1, 0, 1),
        secret_weight=2,
    )

    applicable, reason, parameters = enumerator_applicability(problem)

    assert applicable is True
    assert reason == "applicable"
    # The public predicate permits all four sign assignments, including the
    # unbalanced planted-independent candidates (1, 1) and (-1, -1).
    assert parameters["domain_size"] == comb(2, 2) * 2**2 == 4


@pytest.mark.parametrize(
    ("n", "weight", "values"),
    [
        (True, 1, (1,)),
        (3, True, (1,)),
        (3, 4, (1,)),
        (3, 1, ()),
        (3, 1, (0, 1)),
        (3, 1, (1, 1)),
        (3, 1, (1, True)),
    ],
)
def test_exact_weight_iterator_rejects_noncanonical_domains(
    n: object, weight: object, values: tuple[object, ...]
) -> None:
    with pytest.raises(ValueError):
        tuple(iter_exact_weight_candidates(n, weight, values))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("residue", "q", "expected"),
    [
        (0, 17, 0),
        (8, 17, 8),
        (9, 17, -8),
        (16, 17, -1),
        (7, 16, 7),
        (8, 16, -8),
        (15, 16, -1),
        (17, 17, 0),
        (-1, 17, -1),
    ],
)
def test_centered_representative_matches_phase2_boundary(
    residue: int, q: int, expected: int
) -> None:
    assert centered_representative(residue, q) == expected


def test_streaming_filter_rejects_linf_on_first_row_without_materializing_later_rows() -> None:
    problem = _problem_for_residuals((2, 0, 0), max_abs=1)
    assert not streaming_residual_feasible(problem, (0,))
    assert problem.yielded == [0]


@pytest.mark.parametrize(
    ("problem", "expected"),
    [
        (_problem_for_residuals((3,), max_abs=3), True),
        (_problem_for_residuals((3,), max_abs=2), False),
        (_problem_for_residuals((2, -3), max_abs=4, max_l1=5), True),
        (_problem_for_residuals((2, -3), max_abs=4, max_l1=4), False),
        (_problem_for_residuals((2, -3), max_abs=4, max_l2=13), True),
        (_problem_for_residuals((2, -3), max_abs=4, max_l2=12), False),
        (_problem_for_residuals((2, 0, -3), max_abs=4, max_nonzero=2), True),
        (_problem_for_residuals((2, 0, -3), max_abs=4, max_nonzero=1), False),
        (_problem_for_residuals((3, -4, 0), max_abs=4), True),
        (
            _problem_for_residuals(
                (3, -4, 0),
                max_abs=4,
                max_l1=7,
                max_l2=25,
                max_nonzero=2,
            ),
            True,
        ),
    ],
)
def test_streaming_filter_preserves_equalities_and_rejects_one_over(
    problem: _RecordingProblem, expected: bool
) -> None:
    assert streaming_residual_feasible(problem, (0,)) is expected
    if expected:
        assert problem.yielded == list(range(problem.m))


def test_streaming_filter_wraps_across_zero_and_q() -> None:
    problem = _RecordingProblem(
        rows=((1,),),
        b=(0,),
        q=17,
        error_max_abs=1,
        error_max_l1=1,
        error_max_l2_squared=1,
        error_max_nonzero=1,
    )
    assert streaming_residual_feasible(problem, (1,))
    assert problem.yielded == [0]


def test_support_partition_and_candidate_counts_cover_domain_exactly() -> None:
    assert split_coordinate_ranges(5) == ((0, 2), (2, 5))
    partitions = mitm_partition_counts(5, 2, 2)
    assert tuple(item[0] for item in partitions) == (0, 1, 2)
    assert sum(item[3] for item in partitions) == comb(5, 2) * 4
    assert sum(item[3] for item in partitions) == sparse_secret_domain_size(5, 2, 2)


def test_cyclic_buckets_wrap_at_zero_and_q() -> None:
    assert cyclic_bucket_index(-1, q=17, bucket_width=3) == 5
    assert cyclic_bucket_index(0, q=17, bucket_width=3) == 0
    assert cyclic_bucket_index(16, q=17, bucket_width=3) == 5
    assert cyclic_bucket_index(17, q=17, bucket_width=3) == 0


def test_neighborhood_includes_nonzero_errors_and_wrapped_buckets() -> None:
    keys = cyclic_neighborhood_bucket_keys(
        (0,),
        q=17,
        max_abs=1,
        bucket_width=3,
        max_l1=1,
        max_l2_squared=1,
        max_nonzero=1,
    )
    assert keys == ((0,), (5,))
    assert cyclic_neighborhood_bucket_keys(
        (0,),
        q=17,
        max_abs=1,
        bucket_width=3,
        max_l1=0,
        max_l2_squared=0,
        max_nonzero=0,
    ) == ((0,),)


def test_multidimensional_neighborhood_applies_monotone_public_caps() -> None:
    unconstrained = cyclic_neighborhood_bucket_keys(
        (0, 0), q=17, max_abs=1, bucket_width=3
    )
    l1_zero = cyclic_neighborhood_bucket_keys(
        (0, 0), q=17, max_abs=1, bucket_width=3, max_l1=0
    )
    assert l1_zero == ((0, 0),)
    assert set(unconstrained) == {(0, 0), (0, 5), (5, 0), (5, 5)}


def test_streamed_neighborhood_checks_memory_during_generation() -> None:
    checks = 0

    def memory_exceeded() -> bool:
        nonlocal checks
        checks += 1
        return checks >= 3

    neighborhoods = iter_cyclic_neighborhood_bucket_keys(
        (0, 0, 0),
        q=17,
        max_abs=1,
        bucket_width=3,
        should_stop_memory=memory_exceeded,
    )
    with pytest.raises(RuntimeError):
        tuple(neighborhoods)
    assert checks == 3


def test_already_exceeded_memory_stops_before_huge_error_alphabet_allocation() -> None:
    checks = 0

    def already_exceeded() -> bool:
        nonlocal checks
        checks += 1
        return True

    neighborhoods = iter_cyclic_neighborhood_bucket_keys(
        (0,),
        q=10**100,
        max_abs=10**100,
        bucket_width=1,
        should_stop_memory=already_exceeded,
    )
    with pytest.raises(RuntimeError):
        next(neighborhoods)
    assert checks == 1


def test_neighborhood_iteration_handles_more_than_python_recursion_limit() -> None:
    targets = (0,) * 1_100
    neighborhoods = iter_cyclic_neighborhood_bucket_keys(
        targets,
        q=17,
        max_abs=0,
        bucket_width=1,
        max_l1=0,
        max_l2_squared=0,
        max_nonzero=0,
    )
    assert next(neighborhoods) == targets
    with pytest.raises(StopIteration):
        next(neighborhoods)


def test_checkpoint_ranges_are_contiguous_complete_and_nonoverlapping() -> None:
    assert tuple(checkpoint_ranges(0, 4)) == ()
    ranges = tuple(checkpoint_ranges(10, 4))
    assert ranges == ((0, 4), (4, 8), (8, 10))
    assert tuple(index for start, stop in ranges for index in range(start, stop)) == tuple(
        range(10)
    )


def test_huge_checkpoint_summary_is_constant_size_and_constant_time() -> None:
    summary = coverage_summary(10**30, 1)
    verify_coverage_summary(summary)
    assert summary.range_count == 10**30
    assert len(summary.digest) == 64


def test_interval_one_ledger_storage_does_not_grow_with_checkpoint_count() -> None:
    ledger = _RangeLedger(1)
    for ordinal in range(50_000):
        ledger.record(ordinal)
    summary = ledger.finish(50_000)
    assert summary.range_count == 50_000
    assert not any(
        isinstance(value, (dict, list, set, tuple))
        for value in vars(ledger).values()
    )


@pytest.mark.parametrize(
    "forged",
    [
        (CoverageRange(0, 4), CoverageRange(5, 8), CoverageRange(8, 10)),
        (CoverageRange(0, 4), CoverageRange(3, 8), CoverageRange(8, 10)),
        (CoverageRange(4, 8), CoverageRange(0, 4), CoverageRange(8, 10)),
        (CoverageRange(0, 4), CoverageRange(4, 7), CoverageRange(7, 10)),
    ],
)
def test_ordered_range_verifier_rejects_gap_overlap_reorder_and_same_total_forgery(
    forged: tuple[CoverageRange, ...],
) -> None:
    with pytest.raises(ValueError, match="coverage ranges"):
        verify_ordered_ranges(forged, total=10, interval=4)


def test_enum_certificate_rejects_private_exclusion_dependent_counts() -> None:
    canonical = coverage_summary(10, 4)
    with pytest.raises(ValueError, match="excluded count must be zero"):
        complete_domain_certificate(
            solver_id="sparse_secret_enum",
            n=5,
            weight=2,
            alphabet_size=1,
            tested_count=10,
            traversal_ranges=canonical,
            checkpoint_interval=4,
            excluded_count=1,
        )


def test_complete_domain_certificate_is_public_deterministic_and_range_complete() -> None:
    ranges = coverage_summary(40, 9)
    first = complete_domain_certificate(
        solver_id="sparse_secret_enum",
        n=5,
        weight=2,
        alphabet_size=2,
        tested_count=40,
        traversal_ranges=ranges,
        checkpoint_interval=9,
        excluded_count=0,
    )
    second = complete_domain_certificate(
        solver_id="sparse_secret_enum",
        n=5,
        weight=2,
        alphabet_size=2,
        tested_count=40,
        traversal_ranges=ranges,
        checkpoint_interval=9,
        excluded_count=0,
    )
    assert first == second
    assert first["certificate_id"] == "complete_exact_weight_domain_v1"
    assert len(first["certificate_digest"]) == 64
    assert first["public_parameters"] == {
        "alphabet_size": 2,
        "candidate_count": 40,
        "checkpoint_interval": 9,
        "covered_work_units": 40,
        "domain_size": 40,
        "n": 5,
        "range_start": 0,
        "range_stop": 40,
        "support_count": 10,
        "tested_count": 40,
        "weight": 2,
    }


@pytest.mark.parametrize(
    "mutator",
    [
        lambda manifest: {"selected_rows": ()},
        lambda manifest: {"selected_rows": (0, 2)},
        lambda manifest: {"bucket_width": 0},
        lambda manifest: {"coverage_manifest": replace(manifest, left_entries=1)},
        lambda manifest: {"coverage_manifest": replace(manifest, right_entries=1)},
        lambda manifest: {
            "coverage_manifest": replace(manifest, collision_count=3)
        },
        lambda manifest: {
            "coverage_manifest": replace(manifest, neighborhood_count=-1)
        },
    ],
)
def test_mitm_certificate_rejects_incomplete_or_malformed_coverage(
    mutator,
) -> None:
    manifest = _static_mitm_manifest()
    arguments: dict[str, object] = {
        "n": 2,
        "weight": 1,
        "alphabet_size": 1,
        "selected_rows": (0, 1),
        "bucket_width": 3,
        "coverage_manifest": manifest,
    }
    arguments.update(mutator(manifest))
    with pytest.raises(ValueError):
        complete_mitm_certificate(**arguments)  # type: ignore[arg-type]


def test_timeout_helper_always_returns_censored() -> None:
    result = timeout_result(started=10.0, work_units=7, clock=lambda: 12.5)
    assert result.status is SolveStatus.CENSORED
    assert result.elapsed_seconds == 2.5
    assert result.work_units == 7
    assert result.detail["reason"] == "time_cap"


def test_post_table_budget_stop_distinguishes_memory_from_time_deterministically() -> None:
    assert traversal_stop_reason(
        started=10.0,
        max_seconds=5.0,
        memory_cap_bytes=100,
        clock=lambda: 11.0,
        rss_reader=lambda: 101,
    ) == "memory_cap"
    assert traversal_stop_reason(
        started=10.0,
        max_seconds=0.5,
        memory_cap_bytes=100,
        clock=lambda: 11.0,
        rss_reader=lambda: 99,
    ) == "time_cap"
    memory = budget_stop_result(
        started=10.0,
        max_seconds=5.0,
        work_units=17,
        memory_cap_bytes=100,
        clock=lambda: 11.0,
        rss_reader=lambda: 101,
    )
    timed = budget_stop_result(
        started=10.0,
        max_seconds=0.5,
        work_units=17,
        memory_cap_bytes=100,
        clock=lambda: 11.0,
        rss_reader=lambda: 99,
    )
    assert memory is not None and memory.status is SolveStatus.CENSORED
    assert memory.detail["reason"] == "memory_cap"
    assert memory.work_units == 17
    assert timed is not None and timed.status is SolveStatus.CENSORED
    assert timed.detail["reason"] == "time_cap"


def test_every_task4_result_detail_shape_passes_closed_public_scrubber() -> None:
    enum_certificate = complete_domain_certificate(
        solver_id="sparse_secret_enum",
        n=2,
        weight=1,
        alphabet_size=1,
        tested_count=2,
        traversal_ranges=coverage_summary(2, 2),
        checkpoint_interval=2,
        excluded_count=0,
    )
    manifest = _static_mitm_manifest()
    mitm_certificate = complete_mitm_certificate(
        n=2,
        weight=1,
        alphabet_size=1,
        selected_rows=(0, 1),
        bucket_width=3,
        coverage_manifest=manifest,
    )
    results = (
        SolveResult.success(
            secret=(1, 0),
            elapsed_seconds=0.1,
            work_units=1,
        ),
        SolveResult.success(
            secret=(1, 0),
            elapsed_seconds=0.1,
            work_units=3,
            detail={
                "public_parameters": {
                    "bucket_width": 3,
                    "collision_count": 1,
                    "range_start": 0,
                    "range_stop": 2,
                    "row_count": 2,
                    "subset_size": 2,
                }
            },
        ),
        SolveResult.exhausted(
            elapsed_seconds=0.2, work_units=2, detail=enum_certificate
        ),
        SolveResult.exhausted(
            elapsed_seconds=0.2, work_units=5, detail=mitm_certificate
        ),
        timeout_result(
            started=10.0,
            work_units=4,
            clock=lambda: 11.0,
            public_parameters={"collision_count": 2, "tested_count": 2},
        ),
        memory_censored_result(
            started=10.0, work_units=4, memory_cap_bytes=1024
        ),
        inapplicable_result("not_exact_weight"),
        inapplicable_result("invalid_checkpoint"),
    )
    public = tuple(scrub_result(result) for result in results)
    assert tuple(item["status"] for item in public) == (
        "success",
        "success",
        "exhausted",
        "exhausted",
        "censored",
        "censored",
        "error",
        "error",
    )
    assert all("secret" not in item for item in public)


def test_applicability_and_public_row_selection_use_only_public_request_data(
    tmp_path: Path,
) -> None:
    problem = _problem_for_residuals((0, 0, 0, 0), max_abs=1)
    problem.secret_weight = 1
    request = SolveRequest(
        seed=9,
        max_seconds=1.0,
        work_dir=tmp_path,
        parameters={"mitm_row_count": 3},
    )
    assert enumerator_applicability(problem, request) == (
        True,
        "applicable",
        {"alphabet_size": 1, "domain_size": 1, "n": 1, "weight": 1},
    )
    assert select_mitm_rows(problem, request) == (0, 1, 2)
    applicable, reason, parameters = mitm_applicability(problem, request)
    assert applicable and reason == "applicable"
    assert parameters == {
        "bucket_width": 3,
        "range_start": 0,
        "range_stop": 3,
        "row_count": 3,
        "seed": 9,
        "subset_size": 3,
    }


def test_mitm_coverage_verifier_rejects_digest_and_range_forgery(
    tmp_path: Path,
) -> None:
    problem = _RecordingProblem(
        rows=((1, 0), (0, 1)),
        b=(1, 0),
        q=17,
        error_max_abs=1,
        error_max_l1=1,
        error_max_l2_squared=1,
        error_max_nonzero=1,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    request = SolveRequest(
        seed=3,
        max_seconds=1.0,
        work_dir=tmp_path,
        parameters={"mitm_row_count": 2},
        checkpoint_every_work_units=2,
    )
    manifest = build_mitm_coverage_manifest(problem, request)
    verify_mitm_coverage(problem, request, manifest)
    forged = replace(manifest, event_digest="0" * 64)
    with pytest.raises(ValueError, match="MITM coverage"):
        verify_mitm_coverage(problem, request, forged)
    forged_ranges = replace(
        manifest,
        left_ranges=replace(manifest.left_ranges, boundary_sum=999),
    )
    with pytest.raises(ValueError, match="MITM coverage"):
        verify_mitm_coverage(problem, request, forged_ranges)
    forged_left_weight = replace(manifest, partition_left_weights=(999,))
    with pytest.raises(ValueError):
        complete_mitm_certificate(
            n=problem.n,
            weight=1,
            alphabet_size=1,
            selected_rows=(0, 1),
            bucket_width=3,
            coverage_manifest=forged_left_weight,
        )


class _DigestSubclass(str):
    pass


@pytest.mark.parametrize(
    "mutator",
    [
        lambda manifest: replace(manifest, left_entries=False),
        lambda manifest: replace(manifest, right_entries=False),
        lambda manifest: replace(manifest, collision_count=False),
        lambda manifest: replace(manifest, neighborhood_count=False),
        lambda manifest: replace(
            manifest, event_digest=_DigestSubclass(manifest.event_digest)
        ),
    ],
)
def test_mitm_certificate_rejects_noncanonical_manifest_scalar_types(mutator) -> None:
    manifest = _static_mitm_manifest()
    forged = mutator(manifest)
    with pytest.raises(ValueError):
        complete_mitm_certificate(
            n=2,
            weight=1,
            alphabet_size=1,
            selected_rows=(0, 1),
            bucket_width=3,
            coverage_manifest=forged,
        )


def test_replay_memory_callback_runs_before_row_block_materialization(
    tmp_path: Path,
) -> None:
    problem = _RecordingProblem(
        rows=((1, 0), (0, 1)),
        b=(1, 0),
        q=17,
        error_max_abs=1,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    calls = 0
    original = problem.materialize_row_block

    def spy(start: int, stop: int):
        nonlocal calls
        calls += 1
        return original(start, stop)

    problem.materialize_row_block = spy  # type: ignore[method-assign]
    request = SolveRequest(
        seed=1,
        max_seconds=1.0,
        work_dir=tmp_path,
        parameters={"mitm_row_count": 2},
    )
    with pytest.raises(RuntimeError):
        build_mitm_coverage_manifest(
            problem, request, should_stop_memory=lambda: True
        )
    assert calls == 0
    with pytest.raises(RuntimeError):
        build_mitm_coverage_manifest(
            problem,
            request,
            should_stop_memory=lambda: False,
            memory_cap_bytes=200,
            rss_reader=lambda: 0,
        )
    assert calls == 0


def _marker_names(function) -> set[str]:
    return {marker.name for marker in getattr(function, "pytestmark", ())}


def test_recovery_nodes_are_explicitly_deferred_by_marker() -> None:
    assert all(
        "recovery" in _marker_names(function)
        for function in (
            test_enumerator_recovers_exact_weight_secret,
            test_mitm_recovers_with_nonzero_error_in_selected_rows,
            test_exclusion_censors_when_public_exhaustion_cannot_be_proved,
            test_no_witness_domain_produces_complete_certificate,
        )
    )


def test_solver_classes_keep_the_validation_wrapper_and_runtime_module_is_facade_only() -> None:
    assert "solve" not in SparseSecretEnumerator.__dict__
    assert "solve" not in SparseSecretMitM.__dict__
    source = inspect.getsource(sparse_secret_module)
    assert "lwe_challenge" not in source
    assert ".materialize_rows(" not in source


@pytest.mark.recovery
def test_enumerator_recovers_exact_weight_secret(binary_fixture, tmp_path: Path) -> None:
    result = SparseSecretEnumerator().solve(
        binary_fixture,
        SolveRequest(seed=7, max_seconds=10.0, work_dir=tmp_path),
    )
    assert result.status is SolveStatus.SUCCESS
    assert binary_fixture.validate_secret(result.secret).ok


@pytest.mark.recovery
def test_mitm_recovers_with_nonzero_error_in_selected_rows(
    binary_fixture, tmp_path: Path
) -> None:
    request = SolveRequest(
        seed=11,
        max_seconds=10.0,
        work_dir=tmp_path,
        parameters={"mitm_row_count": binary_fixture.m},
    )
    result = SparseSecretMitM().solve(binary_fixture, request)
    assert result.status is SolveStatus.SUCCESS
    assert binary_fixture.validate_secret(result.secret).ok
    selected = select_mitm_rows(binary_fixture, request)
    rows = binary_fixture.materialize_row_block(selected[0], selected[-1] + 1)
    residuals = tuple(
        centered_representative(
            binary_fixture.b[row_index]
            - sum(value * coefficient for value, coefficient in zip(result.secret, row)),
            binary_fixture.q,
        )
        for row_index, row in zip(selected, rows, strict=True)
    )
    assert any(residual != 0 for residual in residuals)


class _ExplicitRecoveryProblem(_RecordingProblem):
    instance_id = "explicit_sparse_secret"
    instance_digest = "0" * 64
    family = "DS_BIN"

    def validate_secret(self, candidate):
        return SimpleNamespace(
            ok=streaming_residual_feasible(self, tuple(candidate)), code="ok"
        )

    def materialize_row_block(self, start: int, stop: int):
        return self.rows[start:stop]


@pytest.mark.recovery
def test_exclusion_censors_when_public_exhaustion_cannot_be_proved(
    tmp_path: Path,
) -> None:
    problem = _ExplicitRecoveryProblem(
        rows=((1, 0), (0, 1)),
        b=(1, 0),
        q=17,
        error_max_abs=0,
        error_max_l1=0,
        error_max_l2_squared=0,
        error_max_nonzero=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    result = SparseSecretEnumerator().solve(
        problem,
        SolveRequest(
            seed=1,
            max_seconds=10.0,
            work_dir=tmp_path,
            exclude_secret=(1, 0),
        ),
    )
    assert result.status is SolveStatus.CENSORED
    assert result.detail["reason"] == "exclusion_prevents_public_certificate"


@pytest.mark.recovery
def test_no_witness_domain_produces_complete_certificate(tmp_path: Path) -> None:
    problem = _ExplicitRecoveryProblem(
        rows=((1, 0), (0, 1)),
        b=(2, 2),
        q=17,
        error_max_abs=0,
        error_max_l1=0,
        error_max_l2_squared=0,
        error_max_nonzero=0,
        secret_alphabet=(0, 1),
        secret_weight=1,
    )
    result = SparseSecretMitM().solve(
        problem,
        SolveRequest(seed=1, max_seconds=10.0, work_dir=tmp_path),
    )
    assert result.status is SolveStatus.EXHAUSTED
    assert result.detail["certificate_id"] == "complete_mitm_domain_v1"
    assert result.detail["public_parameters"]["covered_work_units"] == 2
