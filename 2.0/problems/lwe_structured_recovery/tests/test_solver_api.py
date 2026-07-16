from __future__ import annotations

import json
import math
import os
import stat
import threading
from collections import UserDict
from pathlib import Path
from types import SimpleNamespace

import pytest

import lwe_instance
import tools.solvers.api as solver_api

from tools.solvers.api import (
    CheckpointStore,
    ValidatedExactSolver,
    ProgressEvent,
    SolveRequest,
    SolveResult,
    SolveStatus,
    SolverContractError,
    append_progress,
    scrub_public_detail,
    scrub_result,
    validate_solve_result,
)


def test_cli_catalog_fd_uses_explicit_format_without_path_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tools.solvers import cli

    sentinel = SimpleNamespace(catalog_id="a" * 64)
    args = cli.parse_args(
        [
            "--catalog",
            "/mutable/catalog.json",
            "--catalog-fd",
            "17",
            "--catalog-format",
            "jsonl",
            "--catalog-sha256",
            "a" * 64,
            "--instance-id",
            "fixture",
            "--solver",
            "bounded_error",
            "--expected-solver-revision",
            "a" * 64,
        ]
    )
    monkeypatch.setattr(
        cli._lwe_instance.Catalog,
        "load",
        lambda _path: (_ for _ in ()).throw(AssertionError("pathname fallback")),
    )
    observed: list[tuple[int, str]] = []
    monkeypatch.setattr(
        cli._lwe_instance.Catalog,
        "load_fd",
        lambda descriptor, catalog_format: (
            observed.append((descriptor, catalog_format)),
            sentinel,
        )[1],
    )

    assert cli.load_catalog(args) is sentinel
    assert observed == [(17, "jsonl")]


@pytest.mark.parametrize(
    "extra",
    [
        ["--catalog-fd", "17"],
        ["--catalog-format", "json"],
        ["--catalog-sha256", "a" * 64],
        [
            "--catalog-fd",
            "-1",
            "--catalog-format",
            "json",
            "--catalog-sha256",
            "a" * 64,
        ],
    ],
)
def test_cli_catalog_fd_requires_complete_nonnegative_contract(
    extra: list[str],
) -> None:
    from tools.solvers import cli

    with pytest.raises(SystemExit):
        cli.parse_args(
            [
                "--catalog",
                "/mutable/catalog.json",
                "--instance-id",
                "fixture",
                "--solver",
                "bounded_error",
                "--expected-solver-revision",
                "a" * 64,
                *extra,
            ]
        )


def test_success_requires_valid_secret() -> None:
    result = SolveResult.success(
        secret=(0, 1, 0), elapsed_seconds=1.25, work_units=17
    )
    assert result.status is SolveStatus.SUCCESS
    assert result.secret == (0, 1, 0)


def test_scrubbed_result_has_no_secret() -> None:
    result = SolveResult.success(
        secret=(0, 1, 0), elapsed_seconds=1.25, work_units=17
    )
    public = scrub_result(result)
    assert "secret" not in public
    assert public == {
        "status": "success",
        "elapsed_seconds": 1.25,
        "work_units": 17,
        "peak_rss_bytes": 0,
        "checkpoint_count": 0,
        "detail": {},
    }


def test_base_wrapper_runs_solver_body(tmp_path) -> None:
    entered = False

    class Dummy(ValidatedExactSolver):
        solver_id = "dummy"

        def _solve(self, instance, request):
            nonlocal entered
            entered = True
            return SolveResult.error(elapsed_seconds=0.0, work_units=0)

    result = Dummy().solve(
        None, SolveRequest(seed=1, max_seconds=1.0, work_dir=tmp_path)
    )
    assert result.status is SolveStatus.ERROR
    assert entered


def test_common_wrapper_rejects_invalid_success(
    monkeypatch, catalog_path, tmp_path
) -> None:
    instance = lwe_instance.Catalog.load(catalog_path).get("toy-uniform")

    class Invalid(ValidatedExactSolver):
        solver_id = "invalid"

        def _solve(self, instance, request):
            return SolveResult.success(
                secret=(0,),
                elapsed_seconds=0.1,
                work_units=1,
            )

    with pytest.raises(SolverContractError, match="accepted witness"):
        Invalid().solve(
            instance,
            SolveRequest(seed=1, max_seconds=1.0, work_dir=tmp_path),
        )


def test_common_wrapper_censors_when_final_validation_crosses_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    now = [0.0]

    class Instance:
        def validate_secret(self, secret):
            assert secret == (1,)
            now[0] = 1.1
            return SimpleNamespace(ok=True)

    class Valid(ValidatedExactSolver):
        solver_id = "valid"

        def _solve(self, instance, request):
            del instance, request
            now[0] = 0.75
            return SolveResult.success(
                secret=(1,),
                elapsed_seconds=0.75,
                work_units=3,
                checkpoint_count=2,
            )

    monkeypatch.setattr(solver_api, "monotonic", lambda: now[0], raising=False)

    result = Valid().solve(
        Instance(),
        SolveRequest(seed=1, max_seconds=1.0, work_dir=tmp_path),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.secret is None
    assert result.elapsed_seconds == pytest.approx(1.1)
    assert result.work_units == 3
    assert result.checkpoint_count == 2
    assert result.detail["reason"] == "time_cap"


def test_common_wrapper_censors_when_final_validation_crosses_memory_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    peak_rss = [50]

    class Instance:
        def validate_secret(self, secret):
            assert secret == (1,)
            peak_rss[0] = 101
            return SimpleNamespace(ok=True)

    class Valid(ValidatedExactSolver):
        solver_id = "valid"

        def _solve(self, instance, request):
            del instance, request
            return SolveResult.success(
                secret=(1,),
                elapsed_seconds=0.5,
                work_units=3,
                peak_rss_bytes=50,
                checkpoint_count=2,
            )

    monkeypatch.setattr(
        solver_api,
        "_peak_rss_bytes",
        lambda: peak_rss[0],
        raising=False,
    )

    result = Valid().solve(
        Instance(),
        SolveRequest(
            seed=1,
            max_seconds=1.0,
            work_dir=tmp_path,
            parameters={"memory_cap_bytes": 100},
        ),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.secret is None
    assert result.peak_rss_bytes == 101
    assert result.work_units == 3
    assert result.checkpoint_count == 2
    assert result.detail == {
        "reason": "memory_cap",
        "public_parameters": {
            "cap": 100,
            "cap_unit": "bytes",
            "memory_cap_bytes": 100,
        },
    }


def test_common_wrapper_reports_final_validation_time_and_peak_rss(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    now = [0.0]
    peak_rss = [50]

    class Instance:
        def validate_secret(self, secret):
            assert secret == (1,)
            now[0] = 0.5
            peak_rss[0] = 75
            return SimpleNamespace(ok=True)

    class Valid(ValidatedExactSolver):
        solver_id = "valid"

        def _solve(self, instance, request):
            del instance, request
            now[0] = 0.25
            return SolveResult.success(
                secret=(1,),
                elapsed_seconds=0.25,
                work_units=3,
                peak_rss_bytes=50,
                detail={"public_parameters": {"candidate_count": 1}},
            )

    monkeypatch.setattr(solver_api, "monotonic", lambda: now[0])
    monkeypatch.setattr(solver_api, "_peak_rss_bytes", lambda: peak_rss[0])

    result = Valid().solve(
        Instance(),
        SolveRequest(seed=1, max_seconds=1.0, work_dir=tmp_path),
    )

    assert result.status is SolveStatus.SUCCESS
    assert result.secret == (1,)
    assert result.elapsed_seconds == pytest.approx(0.5)
    assert result.peak_rss_bytes == 75
    assert result.work_units == 3
    assert result.detail["public_parameters"]["candidate_count"] == 1


@pytest.mark.parametrize(
    ("factory", "expected_status", "detail"),
    [
        (
            SolveResult.exhausted,
            SolveStatus.EXHAUSTED,
            {"certificate_id": "complete_public_domain_v1"},
        ),
        (
            SolveResult.censored,
            SolveStatus.CENSORED,
            {"reason": "work_unit_cap"},
        ),
        (SolveResult.error, SolveStatus.ERROR, {"code": "backend_failed"}),
    ],
)
def test_common_wrapper_accounts_for_every_non_success_status(
    factory,
    expected_status: SolveStatus,
    detail: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    times = iter((0.0, 0.25, 0.5))

    class NonSuccess(ValidatedExactSolver):
        solver_id = "non_success"

        def _solve(self, instance, request):
            del instance, request
            return factory(
                elapsed_seconds=0.25,
                work_units=3,
                peak_rss_bytes=50,
                checkpoint_count=2,
                detail=detail,
            )

    monkeypatch.setattr(solver_api, "monotonic", lambda: next(times))
    monkeypatch.setattr(solver_api, "_peak_rss_bytes", lambda: 75)

    result = NonSuccess().solve(
        object(),
        SolveRequest(seed=1, max_seconds=1.0, work_dir=tmp_path),
    )

    assert result.status is expected_status
    assert result.elapsed_seconds == pytest.approx(0.5)
    assert result.peak_rss_bytes == 75
    assert result.work_units == 3
    assert result.checkpoint_count == 2
    assert dict(result.detail) == detail


@pytest.mark.parametrize(
    ("max_seconds", "parameters", "peak_rss", "expected_reason"),
    [
        (1.0, {}, 50, "time_cap"),
        (2.0, {"memory_cap_bytes": 100}, 101, "memory_cap"),
    ],
)
def test_common_wrapper_downgrades_over_budget_exhaustion_to_censored(
    max_seconds: float,
    parameters: dict[str, int],
    peak_rss: int,
    expected_reason: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    times = iter((0.0, 0.75, 1.1))

    class Exhausted(ValidatedExactSolver):
        solver_id = "exhausted"

        def _solve(self, instance, request):
            del instance, request
            return SolveResult.exhausted(
                elapsed_seconds=0.75,
                work_units=3,
                peak_rss_bytes=50,
                checkpoint_count=2,
                detail={"certificate_id": "complete_public_domain_v1"},
            )

    monkeypatch.setattr(solver_api, "monotonic", lambda: next(times))
    monkeypatch.setattr(solver_api, "_peak_rss_bytes", lambda: peak_rss)

    result = Exhausted().solve(
        object(),
        SolveRequest(
            seed=1,
            max_seconds=max_seconds,
            work_dir=tmp_path,
            parameters=parameters,
        ),
    )

    assert result.status is SolveStatus.CENSORED
    assert result.elapsed_seconds == pytest.approx(1.1)
    assert result.peak_rss_bytes == peak_rss
    assert result.work_units == 3
    assert result.checkpoint_count == 2
    assert result.detail["reason"] == expected_reason


@pytest.mark.parametrize(
    ("factory", "expected_status", "detail"),
    [
        (
            SolveResult.censored,
            SolveStatus.CENSORED,
            {"reason": "work_unit_cap"},
        ),
        (SolveResult.error, SolveStatus.ERROR, {"code": "backend_failed"}),
    ],
)
def test_common_wrapper_preserves_safe_non_success_semantics_over_budget(
    factory,
    expected_status: SolveStatus,
    detail: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    times = iter((0.0, 0.75, 1.1))

    class NonSuccess(ValidatedExactSolver):
        solver_id = "non_success"

        def _solve(self, instance, request):
            del instance, request
            return factory(
                elapsed_seconds=0.75,
                work_units=3,
                detail=detail,
            )

    monkeypatch.setattr(solver_api, "monotonic", lambda: next(times))
    monkeypatch.setattr(solver_api, "_peak_rss_bytes", lambda: 75)

    result = NonSuccess().solve(
        object(),
        SolveRequest(seed=1, max_seconds=1.0, work_dir=tmp_path),
    )

    assert result.status is expected_status
    assert result.elapsed_seconds == pytest.approx(1.1)
    assert result.peak_rss_bytes == 75
    assert dict(result.detail) == detail


@pytest.mark.parametrize("seed", [True, -1, 1.0, "1"])
def test_request_rejects_noncanonical_seed(tmp_path: Path, seed: object) -> None:
    with pytest.raises(SolverContractError, match="seed"):
        SolveRequest(seed=seed, max_seconds=1.0, work_dir=tmp_path)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "max_seconds", [True, 0, -1.0, math.nan, math.inf, "1"]
)
def test_request_rejects_invalid_time_cap(
    tmp_path: Path, max_seconds: object
) -> None:
    with pytest.raises(SolverContractError, match="max_seconds"):
        SolveRequest(seed=1, max_seconds=max_seconds, work_dir=tmp_path)  # type: ignore[arg-type]


def test_numeric_overflow_is_normalized_to_contract_error(tmp_path: Path) -> None:
    huge = 10**10_000
    with pytest.raises(SolverContractError, match="max_seconds"):
        SolveRequest(seed=1, max_seconds=huge, work_dir=tmp_path)
    with pytest.raises(SolverContractError, match="elapsed_seconds"):
        SolveResult.error(elapsed_seconds=huge, work_units=0)


@pytest.mark.parametrize("single_worker", [False, 0, 1, "true"])
def test_request_requires_exact_single_worker_flag(
    tmp_path: Path, single_worker: object
) -> None:
    with pytest.raises(SolverContractError, match="single_worker"):
        SolveRequest(
            seed=1,
            max_seconds=1.0,
            work_dir=tmp_path,
            single_worker=single_worker,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("interval", [True, False, 0, -1, 1.0])
def test_request_rejects_invalid_checkpoint_interval(
    tmp_path: Path, interval: object
) -> None:
    with pytest.raises(SolverContractError, match="checkpoint_every_work_units"):
        SolveRequest(
            seed=1,
            max_seconds=1.0,
            work_dir=tmp_path,
            checkpoint_every_work_units=interval,  # type: ignore[arg-type]
        )


def test_request_freezes_parameter_aliases(tmp_path: Path) -> None:
    parameters = {"limits": [1, {"enabled": True}]}
    request = SolveRequest(
        seed=1,
        max_seconds=1.0,
        work_dir=tmp_path,
        parameters=parameters,
    )
    parameters["limits"][1]["enabled"] = False  # type: ignore[index]
    assert request.parameters["limits"][1]["enabled"] is True  # type: ignore[index]
    with pytest.raises(TypeError):
        request.parameters["new"] = 1  # type: ignore[index]


def test_external_json_contract_rejects_arbitrary_mapping_types(
    tmp_path: Path,
) -> None:
    with pytest.raises(SolverContractError, match="JSON-native"):
        SolveRequest(
            seed=1,
            max_seconds=1,
            work_dir=tmp_path,
            parameters=UserDict({"limit": 1}),
        )
    with pytest.raises(SolverContractError, match="JSON-native"):
        SolveResult.error(
            elapsed_seconds=0,
            work_units=0,
            detail=UserDict({"reason": "malformed"}),
        )
    with pytest.raises(SolverContractError, match="JSON-native"):
        _checkpoint_store(tmp_path).save(
            UserDict({"next_index": 1}),
            work_units=1,
        )


def test_json_contract_normalizes_lone_surrogate_errors(tmp_path: Path) -> None:
    surrogate = "\ud800"
    for parameters in ({"value": surrogate}, {surrogate: 1}):
        with pytest.raises(SolverContractError, match="Unicode"):
            SolveRequest(
                seed=1,
                max_seconds=1,
                work_dir=tmp_path,
                parameters=parameters,
            )
    with pytest.raises(SolverContractError, match="Unicode"):
        SolveResult.error(
            elapsed_seconds=0,
            work_units=0,
            detail={"value": surrogate},
        )
    with pytest.raises(SolverContractError, match="Unicode"):
        _checkpoint_store(tmp_path).save(
            {"value": surrogate},
            work_units=1,
        )


@pytest.mark.parametrize(
    "parameters",
    [{"bad": math.nan}, {"bad": object()}, {1: "bad"}, {"bad": {1, 2}}],
)
def test_request_rejects_non_json_parameters(
    tmp_path: Path, parameters: object
) -> None:
    with pytest.raises(SolverContractError, match="parameters"):
        SolveRequest(
            seed=1,
            max_seconds=1.0,
            work_dir=tmp_path,
            parameters=parameters,  # type: ignore[arg-type]
        )


def test_request_rejects_mutable_or_boolean_exclusion(tmp_path: Path) -> None:
    for excluded in ([0, 1], (0, True)):
        with pytest.raises(SolverContractError, match="exclude_secret"):
            SolveRequest(
                seed=1,
                max_seconds=1.0,
                work_dir=tmp_path,
                exclude_secret=excluded,  # type: ignore[arg-type]
            )


def test_request_rejects_resume_path_outside_work_dir(tmp_path: Path) -> None:
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    with pytest.raises(SolverContractError, match="inside work_dir"):
        SolveRequest(
            seed=1,
            max_seconds=1.0,
            work_dir=work_dir,
            resume_checkpoint=tmp_path / "outside.json",
        )


def test_request_rejects_symlink_work_dir(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    symlink = tmp_path / "link"
    symlink.symlink_to(target, target_is_directory=True)
    with pytest.raises(SolverContractError, match="symlink"):
        SolveRequest(seed=1, max_seconds=1.0, work_dir=symlink)


def test_request_rejects_dangling_symlink_paths(tmp_path: Path) -> None:
    dangling_work = tmp_path / "dangling-work"
    dangling_work.symlink_to(tmp_path / "missing", target_is_directory=True)
    with pytest.raises(SolverContractError, match="symlink"):
        SolveRequest(seed=1, max_seconds=1.0, work_dir=dangling_work)

    work = tmp_path / "work"
    work.mkdir()
    dangling_checkpoint = work / "dangling-checkpoint"
    dangling_checkpoint.symlink_to(work / "missing.json")
    with pytest.raises(SolverContractError, match="symlink"):
        SolveRequest(
            seed=1,
            max_seconds=1.0,
            work_dir=work,
            resume_checkpoint=dangling_checkpoint,
        )


def test_result_is_factory_only_and_all_non_successes_are_secret_free() -> None:
    with pytest.raises(TypeError, match="status factory"):
        SolveResult()  # type: ignore[call-arg]
    for result, status in (
        (
            SolveResult.exhausted(elapsed_seconds=1, work_units=2),
            SolveStatus.EXHAUSTED,
        ),
        (
            SolveResult.censored(
                elapsed_seconds=1, work_units=2, detail={"reason": "time_cap"}
            ),
            SolveStatus.CENSORED,
        ),
        (
            SolveResult.error(
                elapsed_seconds=1, work_units=2, detail={"code": "malformed"}
            ),
            SolveStatus.ERROR,
        ),
    ):
        assert result.status is status
        assert result.secret is None


def test_result_factories_reject_positional_detail_or_secret() -> None:
    with pytest.raises(TypeError):
        SolveResult.error(0, 0, {"reason": "positional"})  # type: ignore[misc]
    with pytest.raises(TypeError):
        SolveResult.error(
            elapsed_seconds=0,
            work_units=0,
            secret=(0, 1),  # type: ignore[call-arg]
        )


@pytest.mark.parametrize(
    ("factory", "kwargs"),
    [
        (SolveResult.error, {"elapsed_seconds": True, "work_units": 0}),
        (SolveResult.error, {"elapsed_seconds": math.inf, "work_units": 0}),
        (SolveResult.error, {"elapsed_seconds": -1, "work_units": 0}),
        (SolveResult.error, {"elapsed_seconds": 0, "work_units": True}),
        (SolveResult.error, {"elapsed_seconds": 0, "work_units": -1}),
        (
            SolveResult.error,
            {"elapsed_seconds": 0, "work_units": 0, "peak_rss_bytes": True},
        ),
        (
            SolveResult.error,
            {"elapsed_seconds": 0, "work_units": 0, "checkpoint_count": -1},
        ),
    ],
)
def test_result_rejects_invalid_counters(factory, kwargs) -> None:
    with pytest.raises(SolverContractError):
        factory(**kwargs)


def test_success_rejects_mutable_or_boolean_secret() -> None:
    for secret in ([0, 1], (0, True)):
        with pytest.raises(SolverContractError, match="secret"):
            SolveResult.success(
                secret=secret,  # type: ignore[arg-type]
                elapsed_seconds=0,
                work_units=0,
            )


def test_result_detail_is_immutable_and_alias_free() -> None:
    detail = {"reason": "bounded", "public_parameters": [{"q": 17}]}
    result = SolveResult.censored(
        elapsed_seconds=0,
        work_units=0,
        detail=detail,
    )
    detail["public_parameters"][0]["q"] = 19  # type: ignore[index]
    assert result.detail["public_parameters"][0]["q"] == 17  # type: ignore[index]
    with pytest.raises(TypeError):
        result.detail["reason"] = "changed"  # type: ignore[index]


def test_private_vectors_are_redacted_from_request_and_result_repr(
    tmp_path: Path,
) -> None:
    canary = (9137, 8291, 7411)
    request = SolveRequest(
        seed=1,
        max_seconds=1,
        work_dir=tmp_path,
        exclude_secret=canary,
    )
    result = SolveResult.success(
        secret=canary,
        elapsed_seconds=0,
        work_units=1,
        detail={"answer": canary},
    )
    assert repr(canary) not in repr(request)
    assert repr(canary) not in repr(result)
    assert "answer" not in repr(result)


@pytest.mark.parametrize(
    "detail",
    [
        {"secret": [0, 1]},
        {"nested": {"Witness": [0, 1]}},
        {"nested": [{"candidate": [0, 1]}]},
        {"vector": [0, 1]},
        {"residual": [0, 1]},
        {"planted_secret": [0, 1]},
        {"planted_error": [0, 1]},
        {"answer": [0, 1]},
        {"solution": [0, 1]},
        {"error_vector": [0, 1]},
        {"secret_value": [0, 1]},
        {"public_parameters": {"planted_secret": [0, 1]}},
        {"public_parameters": {"error_vector": [0, 1]}},
        {"bounds": [9137, 8291, 7411]},
        {"public_parameters": {"n": [9137, 8291, 7411]}},
        {"public_parameters": {"candidate_count": [9137, 8291, 7411]}},
    ],
)
def test_scrubber_rejects_forbidden_keys_at_any_depth(detail) -> None:
    result = SolveResult.error(
        elapsed_seconds=0,
        work_units=0,
        detail=detail,
    )
    with pytest.raises(SolverContractError, match="public detail"):
        scrub_result(result)


def test_scrubber_uses_closed_public_detail_schema() -> None:
    result = SolveResult.error(
        elapsed_seconds=0,
        work_units=0,
        detail={"seemingly_harmless_new_field": 1},
    )
    with pytest.raises(SolverContractError, match="public detail"):
        scrub_result(result)


def test_scrubber_returns_json_native_copy() -> None:
    result = SolveResult.censored(
        elapsed_seconds=0,
        work_units=3,
        detail={
            "reason": "work_cap",
            "public_parameters": {"range_start": 1, "range_stop": 2},
        },
    )
    public = scrub_result(result)
    assert public["detail"] == {
        "reason": "work_cap",
        "public_parameters": {"range_start": 1, "range_stop": 2},
    }


@pytest.mark.parametrize(
    "public_parameters",
    [
        {"n": 0},
        {"q": True},
        {"candidate_count": -1},
        {"max_seconds": 0},
        {"cap": True},
        {"cap_unit": "secret_values"},
        {"range_start": 3, "range_stop": 2},
        pytest.param({"cap": 10**10_000}, id="huge-cap"),
    ],
)
def test_scrubber_enforces_exact_public_parameter_shapes(
    public_parameters: dict[str, object],
) -> None:
    result = SolveResult.error(
        elapsed_seconds=0,
        work_units=0,
        detail={"public_parameters": public_parameters},
    )
    with pytest.raises(SolverContractError, match="public detail"):
        scrub_result(result)


def test_scrubber_orders_public_object_keys_deterministically() -> None:
    result = SolveResult.error(
        elapsed_seconds=0,
        work_units=0,
        detail={"public_parameters": {"q": 17, "n": 3}, "reason": "bounded"},
    )
    detail = scrub_result(result)["detail"]
    assert list(detail) == ["public_parameters", "reason"]
    assert list(detail["public_parameters"]) == ["n", "q"]


def test_scrubber_enforces_depth_node_string_and_array_limits() -> None:
    too_deep: dict[str, object] = {}
    cursor = too_deep
    for index in range(9):
        child: dict[str, object] = {}
        cursor[f"level_{index}"] = child
        cursor = child
    invalid_details = (
        too_deep,
        {"nodes": list(range(2_049))},
        {"text": "x" * 4_097},
        {"items": list(range(1_025))},
    )
    for detail in invalid_details:
        with pytest.raises(SolverContractError):
            scrub_public_detail(detail)


def test_validation_rejects_excluded_success_without_calling_validator(
    tmp_path: Path,
) -> None:
    called = False

    class Instance:
        def validate_secret(self, secret):
            nonlocal called
            called = True
            return SimpleNamespace(ok=True, code="ok")

    request = SolveRequest(
        seed=1,
        max_seconds=1,
        work_dir=tmp_path,
        exclude_secret=(0, 1),
    )
    result = SolveResult.success(
        secret=(0, 1), elapsed_seconds=0, work_units=1
    )
    with pytest.raises(SolverContractError, match="excluded witness"):
        validate_solve_result(Instance(), request, result)
    assert not called


def test_validation_accepts_only_public_facade_verdict(tmp_path: Path) -> None:
    request = SolveRequest(seed=1, max_seconds=1, work_dir=tmp_path)
    result = SolveResult.success(
        secret=(0, 1), elapsed_seconds=0, work_units=1
    )

    class Instance:
        def __init__(self, ok: object) -> None:
            self.ok = ok

        def validate_secret(self, secret):
            return SimpleNamespace(ok=self.ok, code="fixed-public-code")

    assert validate_solve_result(Instance(True), request, result) is result
    for invalid_ok in (False, 1, None):
        with pytest.raises(SolverContractError, match="accepted witness"):
            validate_solve_result(Instance(invalid_ok), request, result)


def test_validation_rejects_non_request_at_public_boundary(tmp_path: Path) -> None:
    result = SolveResult.success(
        secret=(0, 1), elapsed_seconds=0, work_units=1
    )
    with pytest.raises(SolverContractError, match="SolveRequest"):
        validate_solve_result(
            SimpleNamespace(validate_secret=lambda secret: SimpleNamespace(ok=True)),
            object(),  # type: ignore[arg-type]
            result,
        )


def test_wrapper_rejects_non_result_from_body(monkeypatch, tmp_path: Path) -> None:
    class Invalid(ValidatedExactSolver):
        solver_id = "invalid"

        def _solve(self, instance, request):
            return {"status": "success"}

    with pytest.raises(SolverContractError, match="SolveResult"):
        Invalid().solve(
            object(), SolveRequest(seed=1, max_seconds=1, work_dir=tmp_path)
        )


def _progress(**overrides: object) -> ProgressEvent:
    values: dict[str, object] = {
        "solver_id": "solver-v1",
        "instance_id": "instance-1",
        "elapsed_seconds": 1.0,
        "work_units": 10,
        "phase": "search",
        "peak_rss_bytes": 1024,
        "checkpoint_count": 1,
    }
    values.update(overrides)
    return ProgressEvent(**values)  # type: ignore[arg-type]


def test_progress_is_canonical_secret_free_jsonl_and_monotone(tmp_path: Path) -> None:
    path = tmp_path / "progress.jsonl"
    append_progress(path, _progress())
    append_progress(
        path,
        _progress(
            elapsed_seconds=2.0,
            work_units=20,
            phase="verify",
            peak_rss_bytes=2048,
            checkpoint_count=2,
        ),
    )
    lines = path.read_text(encoding="ascii").splitlines()
    assert len(lines) == 2
    parsed = [json.loads(line) for line in lines]
    assert parsed == [
        _progress().to_public_dict(),
        _progress(
            elapsed_seconds=2.0,
            work_units=20,
            phase="verify",
            peak_rss_bytes=2048,
            checkpoint_count=2,
        ).to_public_dict(),
    ]
    assert all(
        forbidden not in path.read_text(encoding="ascii").casefold()
        for forbidden in ("secret", "witness", "candidate", "vector", "residual")
    )


@pytest.mark.parametrize(
    "override",
    [
        {"elapsed_seconds": 0.5},
        {"work_units": 9},
        {"peak_rss_bytes": 1023},
        {"checkpoint_count": 0},
        {"solver_id": "other"},
        {"instance_id": "other"},
    ],
)
def test_progress_rejects_regression_or_identity_change(
    tmp_path: Path, override: dict[str, object]
) -> None:
    path = tmp_path / "progress.jsonl"
    append_progress(path, _progress())
    with pytest.raises(SolverContractError, match="progress"):
        append_progress(path, _progress(**override))
    assert len(path.read_text(encoding="ascii").splitlines()) == 1


def test_progress_rejects_corrupt_or_symlink_log(tmp_path: Path) -> None:
    corrupt = tmp_path / "corrupt.jsonl"
    corrupt.write_text('{"work_units": 1}\n', encoding="ascii")
    with pytest.raises(SolverContractError, match="progress"):
        append_progress(corrupt, _progress())

    target = tmp_path / "target.jsonl"
    target.write_text("", encoding="ascii")
    symlink = tmp_path / "progress.jsonl"
    symlink.symlink_to(target)
    with pytest.raises(SolverContractError, match="symlink"):
        append_progress(symlink, _progress())


def test_progress_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(SolverContractError, match="symlink"):
        append_progress(linked_parent / "progress.jsonl", _progress())
    assert not (real_parent / "progress.jsonl").exists()


def test_progress_parent_swap_is_pinned_and_fails_closed(
    monkeypatch, tmp_path: Path
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir()
    displaced = tmp_path / "displaced-parent"
    outside = tmp_path / "outside"
    outside.mkdir()
    path = parent / "progress.jsonl"
    real_write = solver_api.os.write
    swapped = False

    def swap_parent_then_write(descriptor, data):
        nonlocal swapped
        if not swapped:
            swapped = True
            parent.rename(displaced)
            parent.symlink_to(outside, target_is_directory=True)
        return real_write(descriptor, data)

    monkeypatch.setattr(solver_api.os, "write", swap_parent_then_write)
    with pytest.raises(SolverContractError, match="parent directory changed"):
        append_progress(path, _progress())
    assert not (outside / "progress.jsonl").exists()
    assert (displaced / "progress.jsonl").is_file()


def test_progress_leaf_replacement_after_open_fails_closed(
    monkeypatch, tmp_path: Path
) -> None:
    path = tmp_path / "progress.jsonl"
    displaced = tmp_path / "displaced-progress.jsonl"
    real_write = solver_api.os.write
    replaced = False

    def replace_leaf_then_write(descriptor, data):
        nonlocal replaced
        if not replaced:
            replaced = True
            path.rename(displaced)
            path.write_bytes(b"")
            path.chmod(0o600)
        return real_write(descriptor, data)

    monkeypatch.setattr(solver_api.os, "write", replace_leaf_then_write)
    with pytest.raises(SolverContractError, match="changed during write"):
        append_progress(path, _progress())

    assert path.read_bytes() == b""
    assert displaced.read_bytes()


def test_progress_transaction_lock_prevents_deterministic_regression_race(
    monkeypatch, tmp_path: Path
) -> None:
    path = tmp_path / "progress.jsonl"
    append_progress(
        path,
        _progress(
            elapsed_seconds=0,
            work_units=0,
            peak_rss_bytes=0,
            checkpoint_count=0,
        ),
    )
    high_at_write = threading.Event()
    low_lock_attempt = threading.Event()
    real_write = solver_api.os.write
    real_flock = solver_api.fcntl.flock

    def coordinated_flock(descriptor, operation):
        if (
            threading.current_thread().name == "progress-low"
            and operation == solver_api.fcntl.LOCK_EX
        ):
            low_lock_attempt.set()
        return real_flock(descriptor, operation)

    def coordinated_write(descriptor, data):
        if threading.current_thread().name == "progress-high":
            high_at_write.set()
            assert low_lock_attempt.wait(5)
        return real_write(descriptor, data)

    monkeypatch.setattr(solver_api.fcntl, "flock", coordinated_flock)
    monkeypatch.setattr(solver_api.os, "write", coordinated_write)

    def append(event: ProgressEvent) -> BaseException | None:
        try:
            append_progress(path, event)
        except BaseException as exc:
            return exc
        return None

    high = threading.Thread(
        name="progress-high",
        target=lambda: results.append(
            append(
                _progress(
                    elapsed_seconds=10,
                    work_units=10,
                    peak_rss_bytes=2048,
                    checkpoint_count=2,
                )
            )
        ),
    )
    results: list[BaseException | None] = []
    high.start()
    assert high_at_write.wait(5)
    low = threading.Thread(
        name="progress-low",
        target=lambda: results.append(
            append(
                _progress(
                    elapsed_seconds=6,
                    work_units=6,
                    peak_rss_bytes=1024,
                    checkpoint_count=1,
                )
            )
        ),
    )
    low.start()
    high.join(5)
    low.join(5)
    assert not high.is_alive() and not low.is_alive()
    assert sum(result is None for result in results) == 1
    failures = [result for result in results if result is not None]
    assert len(failures) == 1
    assert isinstance(failures[0], SolverContractError)
    assert "regressed" in str(failures[0])
    observed_work = [
        json.loads(line)["work_units"] for line in path.read_text().splitlines()
    ]
    assert observed_work == [0, 10]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"work_units":' + b"9" * 5_000 + b"}\n",
        b'{"nested":' + b"[" * 2_000 + b"0" + b"]" * 2_000 + b"}\n",
    ],
    ids=("huge-integer", "deep-json"),
)
def test_progress_normalizes_huge_integer_and_deep_json_errors(
    tmp_path: Path, raw: bytes
) -> None:
    path = tmp_path / "progress.jsonl"
    path.write_bytes(raw)
    with pytest.raises(SolverContractError, match="progress"):
        append_progress(path, _progress())


def _checkpoint_store(tmp_path: Path, **overrides: object) -> CheckpointStore:
    values: dict[str, object] = {
        "work_dir": tmp_path,
        "solver_id": "solver_v1",
        "solver_revision": "clean-room-v1",
        "instance_digest": "a" * 64,
        "seed": 7,
    }
    values.update(overrides)
    return CheckpointStore(**values)  # type: ignore[arg-type]


def test_checkpoint_round_trip_is_bound_atomic_and_alias_free(tmp_path: Path) -> None:
    store = _checkpoint_store(tmp_path)
    state = {"private_search_state": [1, {"branch": 2}]}
    path = store.save(state, work_units=25)
    state["private_search_state"][1]["branch"] = 9  # type: ignore[index]

    loaded = store.load(path)
    assert loaded == {"private_search_state": (1, {"branch": 2})}
    with pytest.raises(TypeError):
        loaded["new"] = 1  # type: ignore[index]

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw == {
        "schema_version": 1,
        "solver_id": "solver_v1",
        "solver_revision": "clean-room-v1",
        "instance_digest": "a" * 64,
        "seed": 7,
        "work_units": 25,
        "state": {"private_search_state": [1, {"branch": 2}]},
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(tmp_path.glob("*.tmp-*"))


def test_checkpoint_mode_is_0600_even_under_maximally_restrictive_umask(
    tmp_path: Path,
) -> None:
    previous_umask = os.umask(0o777)
    try:
        path = _checkpoint_store(tmp_path).save({"branch": 1}, work_units=1)
    finally:
        os.umask(previous_umask)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_checkpoint_resume_transition_matches_uninterrupted_execution(
    tmp_path: Path,
) -> None:
    def advance(state, stop: int) -> dict[str, int]:
        next_index = state["next_index"]
        total = state["total"]
        while next_index < stop:
            total += next_index * next_index
            next_index += 1
        return {"next_index": next_index, "total": total}

    initial = {"next_index": 0, "total": 0}
    uninterrupted = advance(initial, 20)
    partial = advance(initial, 7)
    store = _checkpoint_store(tmp_path)
    path = store.save(partial, work_units=7)
    loaded = store.load(path)
    assert loaded is not None
    resumed = advance(loaded, 20)
    assert resumed == uninterrupted

    # A state loaded into the internal immutable representation remains a
    # supported checkpoint input even though arbitrary Mapping subclasses do not.
    store.save(loaded, work_units=7)


@pytest.mark.parametrize(
    "override",
    [
        {"solver_id": "other"},
        {"solver_revision": "other-revision"},
        {"instance_digest": "b" * 64},
        {"seed": 8},
    ],
)
def test_checkpoint_rejects_mismatched_binding(
    tmp_path: Path, override: dict[str, object]
) -> None:
    path = _checkpoint_store(tmp_path).save({"branch": 1}, work_units=5)
    with pytest.raises(SolverContractError, match="binding"):
        _checkpoint_store(tmp_path, **override).load(path)


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b'{"schema_version":1,"schema_version":1}',
        b'{"schema_version":NaN}',
        b'{"schema_version":1,"solver_id":"solver_v1"}',
    ],
)
def test_checkpoint_rejects_corrupt_payload(
    tmp_path: Path, payload: bytes
) -> None:
    path = tmp_path / "solver_v1.checkpoint.json"
    path.write_bytes(payload)
    with pytest.raises(SolverContractError, match="checkpoint"):
        _checkpoint_store(tmp_path).load(path)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":' + b"9" * 5_000 + b"}",
        b'{"state":' + b"[" * 2_000 + b"0" + b"]" * 2_000 + b"}",
    ],
    ids=("huge-integer", "deep-json"),
)
def test_checkpoint_normalizes_huge_integer_and_deep_json_errors(
    tmp_path: Path, raw: bytes
) -> None:
    path = tmp_path / "solver_v1.checkpoint.json"
    path.write_bytes(raw)
    with pytest.raises(SolverContractError, match="checkpoint"):
        _checkpoint_store(tmp_path).load(path)


def test_checkpoint_rejects_json_number_that_only_compares_equal_to_seed(
    tmp_path: Path,
) -> None:
    path = _checkpoint_store(tmp_path).save({"branch": 1}, work_units=2)
    raw = path.read_text(encoding="ascii").replace('"seed":7', '"seed":7.0')
    path.write_text(raw, encoding="ascii")
    with pytest.raises(SolverContractError, match="binding"):
        _checkpoint_store(tmp_path).load(path)


def test_checkpoint_rejects_out_of_tree_and_symlink_paths(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    store = _checkpoint_store(work)
    with pytest.raises(SolverContractError, match="inside work_dir"):
        store.save({"branch": 1}, work_units=1, path=tmp_path / "outside.json")

    target = work / "target.json"
    target.write_text("{}", encoding="ascii")
    symlink = work / "link.json"
    symlink.symlink_to(target)
    with pytest.raises(SolverContractError, match="symlink"):
        store.save({"branch": 1}, work_units=1, path=symlink)


def test_checkpoint_parent_swap_cannot_redirect_atomic_replace(
    monkeypatch, tmp_path: Path
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    displaced = tmp_path / "displaced-work"
    outside = tmp_path / "outside"
    outside.mkdir()
    store = _checkpoint_store(work)
    real_replace = solver_api.os.replace

    def swap_parent_then_replace(
        source,
        destination,
        *,
        src_dir_fd=None,
        dst_dir_fd=None,
    ):
        assert src_dir_fd is not None
        assert dst_dir_fd == src_dir_fd
        work.rename(displaced)
        work.symlink_to(outside, target_is_directory=True)
        return real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(solver_api.os, "replace", swap_parent_then_replace)
    with pytest.raises(SolverContractError, match="parent directory changed"):
        store.save({"branch": 1}, work_units=1)

    assert not (outside / "solver_v1.checkpoint.json").exists()
    assert (displaced / "solver_v1.checkpoint.json").is_file()


def test_checkpoint_leaf_replacement_after_atomic_replace_fails_closed(
    monkeypatch, tmp_path: Path
) -> None:
    store = _checkpoint_store(tmp_path)
    destination = store.default_path
    displaced = tmp_path / "displaced-checkpoint.json"
    real_replace = solver_api.os.replace
    replaced = False

    def replace_then_swap_leaf(
        source,
        target,
        *,
        src_dir_fd=None,
        dst_dir_fd=None,
    ):
        nonlocal replaced
        real_replace(
            source,
            target,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )
        if not replaced:
            replaced = True
            destination.rename(displaced)
            destination.write_text("{}\n", encoding="ascii")
            destination.chmod(0o600)

    monkeypatch.setattr(solver_api.os, "replace", replace_then_swap_leaf)
    with pytest.raises(SolverContractError, match="changed during write"):
        store.save({"branch": 1}, work_units=1)

    assert destination.read_text(encoding="ascii") == "{}\n"
    assert displaced.is_file()


def test_checkpoint_ancestor_symlink_swap_fails_complete_nofollow_check(
    monkeypatch, tmp_path: Path
) -> None:
    container = tmp_path / "container"
    work = container / "work"
    work.mkdir(parents=True)
    displaced = tmp_path / "displaced-container"
    store = _checkpoint_store(work)
    real_replace = solver_api.os.replace

    def swap_ancestor_then_replace(
        source,
        destination,
        *,
        src_dir_fd=None,
        dst_dir_fd=None,
    ):
        assert src_dir_fd is not None
        assert dst_dir_fd == src_dir_fd
        container.rename(displaced)
        container.symlink_to(displaced, target_is_directory=True)
        return real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(solver_api.os, "replace", swap_ancestor_then_replace)
    with pytest.raises(SolverContractError, match="parent directory changed"):
        store.save({"branch": 1}, work_units=1)
    assert (displaced / "work" / "solver_v1.checkpoint.json").is_file()


def test_checkpoint_rejects_work_regression(tmp_path: Path) -> None:
    store = _checkpoint_store(tmp_path)
    store.save({"branch": 1}, work_units=5)
    with pytest.raises(SolverContractError, match="work_units"):
        store.save({"branch": 2}, work_units=4)


def test_checkpoint_transaction_lock_prevents_deterministic_overwrite_race(
    monkeypatch, tmp_path: Path
) -> None:
    store = _checkpoint_store(tmp_path)
    store.save({"branch": 0}, work_units=0)
    high_at_replace = threading.Event()
    low_lock_attempt = threading.Event()
    real_replace = solver_api.os.replace
    real_flock = solver_api.fcntl.flock

    def coordinated_flock(descriptor, operation):
        if (
            threading.current_thread().name == "checkpoint-low"
            and operation == solver_api.fcntl.LOCK_EX
        ):
            low_lock_attempt.set()
        return real_flock(descriptor, operation)

    def coordinated_replace(
        source,
        destination,
        *,
        src_dir_fd=None,
        dst_dir_fd=None,
    ):
        if threading.current_thread().name == "checkpoint-high":
            high_at_replace.set()
            assert low_lock_attempt.wait(5)
        return real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(solver_api.fcntl, "flock", coordinated_flock)
    monkeypatch.setattr(solver_api.os, "replace", coordinated_replace)

    def save(state: dict[str, int], work_units: int) -> BaseException | None:
        try:
            store.save(state, work_units=work_units)
        except BaseException as exc:
            return exc
        return None

    results: list[BaseException | None] = []
    high = threading.Thread(
        name="checkpoint-high",
        target=lambda: results.append(save({"branch": 10}, 10)),
    )
    high.start()
    assert high_at_replace.wait(5)
    low = threading.Thread(
        name="checkpoint-low",
        target=lambda: results.append(save({"branch": 6}, 6)),
    )
    low.start()
    high.join(5)
    low.join(5)
    assert not high.is_alive() and not low.is_alive()
    assert sum(result is None for result in results) == 1
    failures = [result for result in results if result is not None]
    assert len(failures) == 1
    assert isinstance(failures[0], SolverContractError)
    assert "work_units regressed" in str(failures[0])
    assert store.load() == {"branch": 10}


def test_checkpoint_default_missing_is_none_but_explicit_missing_fails(
    tmp_path: Path,
) -> None:
    store = _checkpoint_store(tmp_path)
    assert store.load() is None
    with pytest.raises(SolverContractError, match="does not exist"):
        store.load(tmp_path / "missing.json")
