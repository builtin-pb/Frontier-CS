from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

import lwe_challenge.evaluator_core as evaluator_core
from lwe_challenge.schema import canonical_record_bytes, compute_instance_digest


def _write_production_catalog(
    public_dir: Path, *, task_dir: Path, count: int = 200
) -> Path:
    source = json.loads(
        (task_dir / "tests" / "fixtures" / "catalog_two_instances.json")
        .read_text(encoding="utf-8")
    )["instances"][0]
    records: list[bytes] = []
    for index in range(count):
        record = dict(source)
        record["instance_id"] = f"prod-{index:03d}"
        record["analysis_path"] = f"analysis/prod-{index:03d}.md"
        record["instance_digest"] = compute_instance_digest(record)
        records.append(canonical_record_bytes(record))
    catalog_bytes = b"\n".join(records) + b"\n"
    public_dir.mkdir(parents=True, exist_ok=True)
    catalog_path = public_dir / "catalog.jsonl"
    catalog_path.write_bytes(catalog_bytes)
    digest = hashlib.sha256(catalog_bytes).hexdigest()
    (public_dir / "catalog.sha256").write_text(
        f"{digest}  catalog.jsonl\n", encoding="ascii"
    )
    return catalog_path


def _load_with_override(
    *,
    task_dir: Path,
    task_module_loader,
    monkeypatch,
    catalog_path: Path,
    module_name: str,
):
    monkeypatch.setenv("FCS_STRUCTURED_LWE_CATALOG", str(catalog_path))
    return task_module_loader(task_dir / "evaluator.py", module_name)


def test_fcs_evaluator_returns_public_four_tuple(
    task_dir: Path, task_module_loader, monkeypatch
) -> None:
    monkeypatch.setenv(
        "FCS_STRUCTURED_LWE_CATALOG", str(task_dir / "catalog.synthetic.json")
    )
    module = task_module_loader(
        task_dir / "evaluator.py", "lwe_evaluator_synthetic"
    )

    result = module.evaluate(str(task_dir / "reference.json"))

    assert len(result) == 4
    score, unbounded, message, metrics = result
    assert score == unbounded == 0.0
    assert "traceback" not in message.lower()
    assert metrics["instance_count"] == 2


def test_production_catalog_rejects_a_sidecar_digest_mismatch(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    public_dir = tmp_path / "judge-public"
    _write_production_catalog(public_dir, task_dir=task_dir)
    (public_dir / "catalog.sha256").write_text(
        f"{'0' * 64}  catalog.jsonl\n", encoding="ascii"
    )
    monkeypatch.delenv("FCS_STRUCTURED_LWE_CATALOG", raising=False)
    monkeypatch.setenv("FRONTIER_PUBLIC_DIR", str(public_dir))
    module = task_module_loader(task_dir / "evaluator.py", "lwe_evaluator_bad_sidecar")

    with pytest.raises(ValueError, match="catalog.sha256"):
        module.prepare()


def test_production_catalog_requires_exactly_two_hundred_instances(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    public_dir = tmp_path / "judge-public"
    _write_production_catalog(public_dir, task_dir=task_dir, count=199)
    monkeypatch.delenv("FCS_STRUCTURED_LWE_CATALOG", raising=False)
    monkeypatch.setenv("FRONTIER_PUBLIC_DIR", str(public_dir))
    module = task_module_loader(task_dir / "evaluator.py", "lwe_evaluator_bad_count")

    with pytest.raises(ValueError, match="exactly 200"):
        module.prepare()


def test_catalog_cache_reuses_the_verified_path_and_digest(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    catalog_path = tmp_path / "override.json"
    shutil.copyfile(task_dir / "catalog.synthetic.json", catalog_path)
    monkeypatch.setenv("FCS_STRUCTURED_LWE_CATALOG", str(catalog_path))
    module = task_module_loader(task_dir / "evaluator.py", "lwe_evaluator_cache")

    first = module._catalog()
    second = module._catalog()

    assert first is second


def test_prepare_loads_a_valid_catalog_across_short_kernel_reads(
    task_dir: Path, task_module_loader, monkeypatch
) -> None:
    catalog_path = task_dir / "catalog.synthetic.json"
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=catalog_path,
        module_name="lwe_evaluator_short_catalog_reads",
    )
    real_read = module.os.read

    def short_read(fd: int, length: int) -> bytes:
        return real_read(fd, min(length, 7))

    monkeypatch.setattr(module.os, "read", short_read)

    assert module.prepare() == {
        "instance_count": 2,
        "catalog_id": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
    }


def test_cli_prints_message_to_stderr_and_scores_as_the_final_stdout_line(
    task_dir: Path,
) -> None:
    env = os.environ.copy()
    env["FCS_STRUCTURED_LWE_CATALOG"] = str(task_dir / "catalog.synthetic.json")

    completed = subprocess.run(
        [
            sys.executable,
            str(task_dir / "evaluator.py"),
            str(task_dir / "reference.json"),
        ],
        cwd=task_dir,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stdout == "0.000000000000 0.000000000000\n"
    assert completed.stderr == (
        "scored solved=0 submitted=0 invalid=0 duplicates=0 conflicts=0 unknown=0\n"
    )


def test_shell_wrapper_is_strict_and_defaults_to_the_harbor_solution_ledger(
    task_dir: Path,
) -> None:
    script = task_dir / "evaluate.sh"

    syntax = subprocess.run(
        ["bash", "-n", str(script)],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    text = script.read_text(encoding="utf-8")

    assert syntax.returncode == 0, syntax.stderr
    assert script.stat().st_mode & 0o111
    assert text.startswith("#!/usr/bin/env bash\nset -euo pipefail\n")
    assert (
        'SOLUTION="${1:-/work/execution_env/solution_env/solution.json}"' in text
    )
    assert 'exec "$PYTHON_BIN" "$SCRIPT_DIR/evaluator.py" "$SOLUTION"' in text
    assert "Python 3.11 or newer is required" in text


def test_shell_wrapper_evaluates_an_explicit_solution_path(task_dir: Path) -> None:
    env = os.environ.copy()
    env["FCS_STRUCTURED_LWE_CATALOG"] = str(task_dir / "catalog.synthetic.json")

    completed = subprocess.run(
        [
            "bash",
            str(task_dir / "evaluate.sh"),
            str(task_dir / "reference.json"),
        ],
        cwd=task_dir,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "0.000000000000 0.000000000000\n"
    assert completed.stderr == (
        "scored solved=0 submitted=0 invalid=0 duplicates=0 conflicts=0 unknown=0\n"
    )


def test_local_setup_installs_python_only_when_missing(
    task_dir: Path, tmp_path: Path
) -> None:
    script = task_dir / "set_up_env.sh"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "apt.log"
    fake_apt = fake_bin / "apt-get"
    fake_apt.write_text(
        '#!/bin/bash\nprintf \'%s\\n\' "$*" >> "$SETUP_LOG"\n',
        encoding="utf-8",
    )
    fake_apt.chmod(0o755)
    env = {"PATH": str(fake_bin), "SETUP_LOG": str(log)}

    syntax = subprocess.run(
        ["/bin/bash", "-n", str(script)],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    missing = subprocess.run(
        ["/bin/bash", str(script)],
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert syntax.returncode == 0, syntax.stderr
    assert script.stat().st_mode & 0o111
    assert missing.returncode == 0, missing.stderr
    assert log.read_text(encoding="utf-8").splitlines() == [
        "update -qq",
        "install -y -qq --no-install-recommends python3",
    ]

    fake_python = fake_bin / "python3"
    fake_python.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
    fake_python.chmod(0o755)
    present = subprocess.run(
        ["/bin/bash", str(script)],
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert present.returncode == 0, present.stderr
    assert log.read_text(encoding="utf-8").splitlines() == [
        "update -qq",
        "install -y -qq --no-install-recommends python3",
    ]


def test_missing_solution_file_returns_a_sanitized_zero_score(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=task_dir / "tests" / "fixtures" / "catalog_two_instances.json",
        module_name="lwe_evaluator_missing_solution",
    )

    score, unbounded, message, metrics = module.evaluate(
        str(tmp_path / "not-present.json")
    )

    assert score == unbounded == 0.0
    assert message == "submission_invalid code=submission_missing"
    assert metrics["instance_count"] == 2
    assert "not-present" not in repr((message, metrics))


def test_malformed_ledger_returns_a_sanitized_zero_score(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=task_dir / "tests" / "fixtures" / "catalog_two_instances.json",
        module_name="lwe_evaluator_malformed_solution",
    )
    solution_path = tmp_path / "PRIVATE-SOLUTION-PATH.json"
    solution_path.write_bytes(b'{"schema_version":1,"solutions":[PRIVATE-SECRET')

    score, unbounded, message, metrics = module.evaluate(str(solution_path))

    assert score == unbounded == 0.0
    assert message == "submission_invalid code=invalid_json"
    public = json.dumps({"message": message, "metrics": metrics}, sort_keys=True)
    assert "PRIVATE" not in public
    assert "traceback" not in public.lower()


def test_valid_partial_ledger_receives_partial_credit(
    task_dir: Path, task_module_loader, monkeypatch
) -> None:
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=task_dir / "tests" / "fixtures" / "catalog_two_instances.json",
        module_name="lwe_evaluator_partial_solution",
    )

    score, unbounded, message, metrics = module.evaluate(
        str(task_dir / "tests" / "fixtures" / "submission_one_valid.json")
    )

    assert score == 50.0
    assert unbounded == 1.0
    assert message.startswith("scored solved=1 ")
    assert metrics["solved_ids"] == ["toy-uniform"]


def test_plain_metrics_are_json_native_and_detached_from_the_core_result(
    task_dir: Path, task_module_loader, monkeypatch
) -> None:
    catalog_path = task_dir / "tests" / "fixtures" / "catalog_two_instances.json"
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=catalog_path,
        module_name="lwe_evaluator_plain_metrics",
    )
    core_result = module.evaluate_path(
        task_dir / "tests" / "fixtures" / "submission_one_valid.json",
        catalog=module.Catalog.load(catalog_path),
    )

    snapshot = module._plain_data(core_result.metrics)
    encoded = json.dumps(snapshot, allow_nan=False, sort_keys=True)
    assert isinstance(snapshot, dict)
    assert isinstance(snapshot["family_solved_counts"], dict)
    assert isinstance(snapshot["solved_ids"], list)
    assert isinstance(snapshot["invalid_examples"], list)
    assert "toy-uniform" in encoded

    snapshot["family_solved_counts"]["DS_BIN"] = 99
    snapshot["solved_ids"].append("fabricated")
    snapshot["invalid_examples"].append(["fabricated", "fabricated"])

    assert core_result.metrics["family_solved_counts"]["DS_BIN"] == 0
    assert core_result.metrics["solved_ids"] == ("toy-uniform",)
    assert core_result.metrics["invalid_examples"] == ()


def test_hard_octave_metrics_are_json_native_end_to_end(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    source = json.loads(
        (task_dir / "tests" / "fixtures" / "catalog_two_instances.json")
        .read_text(encoding="utf-8")
    )["instances"][0]
    record = dict(source)
    record["tier"] = "hard"
    record["cohort"] = "ladder"
    record["runtime_bin"] = "H2"
    record["octave"] = 2
    record["instance_digest"] = compute_instance_digest(record)
    catalog_path = tmp_path / "hard-catalog.json"
    catalog_path.write_text(
        json.dumps(
            {"schema_version": 1, "instances": [record]},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=catalog_path,
        module_name="lwe_evaluator_hard_octave_metrics",
    )

    _score, _unbounded, _message, metrics = module.evaluate(
        str(task_dir / "reference.json")
    )

    assert metrics["hard_octave_totals"] == {"2": 1}
    assert metrics["hard_octave_solved_counts"] == {"2": 0}
    json.dumps(metrics, allow_nan=False)


def test_public_result_never_contains_secrets_paths_residuals_or_tracebacks(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=task_dir / "tests" / "fixtures" / "catalog_two_instances.json",
        module_name="lwe_evaluator_redaction",
    )
    solution_path = tmp_path / "PRIVATE-SOLUTION-PATH.json"
    solution_path.write_text(
        '{"schema_version":1,"solutions":['
        '{"instance_id":"toy-uniform","secret":[8675309,0,0]}]}',
        encoding="utf-8",
    )

    score, unbounded, message, metrics = module.evaluate(str(solution_path))

    assert score == unbounded == 0.0
    public = json.dumps({"message": message, "metrics": metrics}, sort_keys=True)
    for forbidden in (
        "8675309",
        "PRIVATE-SOLUTION-PATH",
        "analysis/toy-uniform.md",
        "residual",
        "traceback",
        "max_abs_error",
        "l1_error",
        "l2_squared_error",
    ):
        assert forbidden.lower() not in public.lower()


def test_explicit_catalog_override_precedes_the_judge_public_directory(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("FRONTIER_PUBLIC_DIR", str(tmp_path / "missing-judge-public"))
    monkeypatch.setenv(
        "FCS_STRUCTURED_LWE_CATALOG", str(task_dir / "catalog.synthetic.json")
    )
    module = task_module_loader(
        task_dir / "evaluator.py", "lwe_evaluator_override_precedence"
    )

    prepared = module.prepare()

    assert prepared == {
        "instance_count": 2,
        "catalog_id": hashlib.sha256(
            (task_dir / "catalog.synthetic.json").read_bytes()
        ).hexdigest(),
    }


def test_explicit_override_imports_from_the_source_tree_before_judge_public(
    task_dir: Path, tmp_path: Path
) -> None:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["FCS_STRUCTURED_LWE_CATALOG"] = str(task_dir / "catalog.synthetic.json")
    env["FRONTIER_PUBLIC_DIR"] = str(tmp_path / "missing-judge-public")

    completed = subprocess.run(
        [
            sys.executable,
            str(task_dir / "evaluator.py"),
            str(task_dir / "reference.json"),
        ],
        cwd=task_dir,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == "0.000000000000 0.000000000000\n"


def test_judge_public_directory_precedes_the_source_tree_catalog(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    public_dir = tmp_path / "judge-public"
    catalog_path = _write_production_catalog(public_dir, task_dir=task_dir)
    monkeypatch.delenv("FCS_STRUCTURED_LWE_CATALOG", raising=False)
    monkeypatch.setenv("FRONTIER_PUBLIC_DIR", str(public_dir))
    module = task_module_loader(
        task_dir / "evaluator.py", "lwe_evaluator_judge_precedence"
    )

    prepared = module.prepare()

    assert prepared["instance_count"] == 200
    assert prepared["catalog_id"] == hashlib.sha256(
        catalog_path.read_bytes()
    ).hexdigest()


def test_source_checkout_uses_the_production_catalog_not_the_synthetic_fixture(
    task_dir: Path, task_module_loader, monkeypatch
) -> None:
    production_path = task_dir / "harbor" / "app" / "public" / "catalog.jsonl"
    synthetic_path = task_dir / "catalog.synthetic.json"
    monkeypatch.delenv("FCS_STRUCTURED_LWE_CATALOG", raising=False)
    monkeypatch.delenv("FRONTIER_PUBLIC_DIR", raising=False)
    module = task_module_loader(
        task_dir / "evaluator.py", "lwe_evaluator_source_production_catalog"
    )

    prepared = module.prepare()

    assert prepared == {
        "instance_count": 200,
        "catalog_id": hashlib.sha256(production_path.read_bytes()).hexdigest(),
    }
    assert prepared["catalog_id"] != hashlib.sha256(
        synthetic_path.read_bytes()
    ).hexdigest()


def test_source_checkout_falls_back_to_the_sibling_public_catalog(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    copied_task = tmp_path / "copied-task"
    copied_task.mkdir()
    shutil.copyfile(task_dir / "evaluator.py", copied_task / "evaluator.py")
    catalog_path = _write_production_catalog(
        copied_task / "harbor" / "app" / "public", task_dir=task_dir
    )
    monkeypatch.delenv("FCS_STRUCTURED_LWE_CATALOG", raising=False)
    monkeypatch.delenv("FRONTIER_PUBLIC_DIR", raising=False)
    module = task_module_loader(
        copied_task / "evaluator.py", "lwe_evaluator_source_fallback"
    )

    prepared = module.prepare()

    assert prepared["instance_count"] == 200
    assert prepared["catalog_id"] == hashlib.sha256(
        catalog_path.read_bytes()
    ).hexdigest()


def test_catalog_cache_isolated_by_resolved_path_and_current_digest(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    shutil.copyfile(task_dir / "catalog.synthetic.json", first_path)
    shutil.copyfile(task_dir / "catalog.synthetic.json", second_path)
    monkeypatch.setenv("FCS_STRUCTURED_LWE_CATALOG", str(first_path))
    module = task_module_loader(
        task_dir / "evaluator.py", "lwe_evaluator_cache_isolation"
    )

    first = module._catalog()
    monkeypatch.setenv("FCS_STRUCTURED_LWE_CATALOG", str(second_path))
    second = module._catalog()
    monkeypatch.setenv("FCS_STRUCTURED_LWE_CATALOG", str(first_path))
    first_again = module._catalog()
    first_path.write_bytes(first_path.read_bytes() + b"\n")
    changed = module._catalog()

    assert first is first_again
    assert first is not second
    assert changed is not first
    assert changed.catalog_id != first.catalog_id


def test_removing_the_override_reveals_the_current_judge_catalog(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    public_dir = tmp_path / "judge-public"
    _write_production_catalog(public_dir, task_dir=task_dir)
    monkeypatch.setenv("FRONTIER_PUBLIC_DIR", str(public_dir))
    monkeypatch.setenv(
        "FCS_STRUCTURED_LWE_CATALOG", str(task_dir / "catalog.synthetic.json")
    )
    module = task_module_loader(
        task_dir / "evaluator.py", "lwe_evaluator_override_removal"
    )
    assert module.prepare()["instance_count"] == 2

    monkeypatch.delenv("FCS_STRUCTURED_LWE_CATALOG")

    assert module.prepare()["instance_count"] == 200


def test_relative_and_absolute_overrides_share_the_resolved_cache_key(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    catalog_path = tmp_path / "override.json"
    shutil.copyfile(task_dir / "catalog.synthetic.json", catalog_path)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FCS_STRUCTURED_LWE_CATALOG", "override.json")
    module = task_module_loader(
        task_dir / "evaluator.py", "lwe_evaluator_resolved_cache"
    )
    relative = module._catalog()
    monkeypatch.setenv("FCS_STRUCTURED_LWE_CATALOG", str(catalog_path))

    absolute = module._catalog()

    assert relative is absolute


def test_production_sidecar_format_is_exact_not_merely_parseable(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    public_dir = tmp_path / "judge-public"
    catalog_path = _write_production_catalog(public_dir, task_dir=task_dir)
    digest = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
    monkeypatch.delenv("FCS_STRUCTURED_LWE_CATALOG", raising=False)
    monkeypatch.setenv("FRONTIER_PUBLIC_DIR", str(public_dir))
    module = task_module_loader(
        task_dir / "evaluator.py", "lwe_evaluator_sidecar_format"
    )
    invalid_sidecars = (
        f"{digest} catalog.jsonl\n",
        f"{digest}  catalog.jsonl",
        f"{digest.upper()}  catalog.jsonl\n",
        f"{digest}  other.jsonl\n",
        f"{digest}  catalog.jsonl\n\n",
    )

    for sidecar in invalid_sidecars:
        (public_dir / "catalog.sha256").write_text(sidecar, encoding="ascii")
        with pytest.raises(ValueError, match="catalog.sha256"):
            module.prepare()

    (public_dir / "catalog.sha256").write_text(
        f"{digest}  catalog.jsonl\n", encoding="ascii"
    )
    assert module.prepare()["instance_count"] == 200


def test_production_catalog_requires_its_sibling_sidecar(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    public_dir = tmp_path / "judge-public"
    _write_production_catalog(public_dir, task_dir=task_dir)
    (public_dir / "catalog.sha256").unlink()
    monkeypatch.delenv("FCS_STRUCTURED_LWE_CATALOG", raising=False)
    monkeypatch.setenv("FRONTIER_PUBLIC_DIR", str(public_dir))
    module = task_module_loader(
        task_dir / "evaluator.py", "lwe_evaluator_missing_sidecar"
    )

    with pytest.raises(FileNotFoundError):
        module.prepare()


def test_prepare_propagates_catalog_loading_failures(
    task_dir: Path, task_module_loader, monkeypatch, tmp_path: Path
) -> None:
    catalog_path = tmp_path / "override.json"
    catalog_path.write_text("{}", encoding="utf-8")
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=catalog_path,
        module_name="lwe_evaluator_prepare_failure",
    )

    def fail_load(_path):
        raise RuntimeError("PRIVATE-INFRASTRUCTURE-DETAIL")

    monkeypatch.setattr(module.Catalog, "load", fail_load)

    with pytest.raises(RuntimeError, match="PRIVATE-INFRASTRUCTURE-DETAIL"):
        module.prepare()


def test_unexpected_matrix_failure_propagates_as_infrastructure_failure(
    task_dir: Path, task_module_loader, monkeypatch
) -> None:
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=task_dir / "tests" / "fixtures" / "catalog_two_instances.json",
        module_name="lwe_evaluator_matrix_failure",
    )

    def fail_matrix(*_args, **_kwargs):
        raise RuntimeError("PRIVATE-MATRIX-DETAIL")

    monkeypatch.setattr(evaluator_core, "validate_secret", fail_matrix)

    with pytest.raises(RuntimeError, match="PRIVATE-MATRIX-DETAIL"):
        module.evaluate(
            str(task_dir / "tests" / "fixtures" / "submission_one_valid.json")
        )


def test_plain_data_rejects_nonfinite_float_leaves(
    task_dir: Path, task_module_loader, monkeypatch
) -> None:
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=task_dir / "catalog.synthetic.json",
        module_name="lwe_evaluator_nonfinite_metrics",
    )

    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(TypeError, match="finite"):
            module._plain_data({"value": value})


def test_plain_data_rejects_non_json_container_shapes_and_mapping_keys(
    task_dir: Path, task_module_loader, monkeypatch
) -> None:
    module = _load_with_override(
        task_dir=task_dir,
        task_module_loader=task_module_loader,
        monkeypatch=monkeypatch,
        catalog_path=task_dir / "catalog.synthetic.json",
        module_name="lwe_evaluator_non_json_metrics",
    )

    with pytest.raises(TypeError, match="string keys"):
        module._plain_data({1: "value"})
    for value in (["mutable-list"], {"set-value"}, b"bytes"):
        with pytest.raises(TypeError, match="non-JSON"):
            module._plain_data(value)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFOs")
def test_catalog_preverification_rejects_a_fifo_without_blocking(
    task_dir: Path, tmp_path: Path
) -> None:
    catalog_path = tmp_path / "catalog.json"
    os.mkfifo(catalog_path)
    env = os.environ.copy()
    env["FCS_STRUCTURED_LWE_CATALOG"] = str(catalog_path)

    completed = subprocess.run(
        [
            sys.executable,
            str(task_dir / "evaluator.py"),
            str(task_dir / "reference.json"),
        ],
        cwd=task_dir,
        env=env,
        text=True,
        capture_output=True,
        timeout=2,
        check=False,
    )

    assert completed.returncode != 0
    assert completed.stdout == ""


def test_cli_reports_infrastructure_failure_without_a_score_or_traceback(
    task_dir: Path, tmp_path: Path
) -> None:
    env = os.environ.copy()
    env.pop("FCS_STRUCTURED_LWE_CATALOG", None)
    env["FRONTIER_PUBLIC_DIR"] = str(tmp_path / "PRIVATE-MISSING-PUBLIC")
    env["PYTHONPATH"] = str(task_dir / "harbor" / "app" / "public")

    completed = subprocess.run(
        [
            sys.executable,
            str(task_dir / "evaluator.py"),
            str(task_dir / "reference.json"),
        ],
        cwd=task_dir,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "infrastructure_error\n"


def test_cli_sanitizes_public_package_import_failure(
    task_dir: Path, tmp_path: Path
) -> None:
    evaluator_path = tmp_path / "evaluator.py"
    shutil.copyfile(task_dir / "evaluator.py", evaluator_path)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("FCS_STRUCTURED_LWE_CATALOG", None)
    env["FRONTIER_PUBLIC_DIR"] = str(tmp_path / "missing-public")

    completed = subprocess.run(
        [sys.executable, str(evaluator_path), str(tmp_path / "solution.json")],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "infrastructure_error\n"


def test_cli_sanitizes_public_directory_resolution_failure(
    task_dir: Path, tmp_path: Path
) -> None:
    evaluator_path = tmp_path / "evaluator.py"
    shutil.copyfile(task_dir / "evaluator.py", evaluator_path)
    public_loop = tmp_path / "public-loop"
    public_loop.symlink_to(public_loop.name)
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("FCS_STRUCTURED_LWE_CATALOG", None)
    env["FRONTIER_PUBLIC_DIR"] = str(public_loop)

    completed = subprocess.run(
        [sys.executable, str(evaluator_path), str(tmp_path / "solution.json")],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "infrastructure_error\n"


@pytest.mark.parametrize(
    ("solution_name", "solution_bytes", "expected_code"),
    (
        ("PRIVATE-MISSING.json", None, "submission_missing"),
        ("PRIVATE-MALFORMED.json", b"PRIVATE-SECRET-[", "invalid_json"),
    ),
)
def test_cli_sanitizes_expected_submission_failures(
    task_dir: Path,
    tmp_path: Path,
    solution_name: str,
    solution_bytes: bytes | None,
    expected_code: str,
) -> None:
    solution_path = tmp_path / solution_name
    if solution_bytes is not None:
        solution_path.write_bytes(solution_bytes)
    env = os.environ.copy()
    env["FCS_STRUCTURED_LWE_CATALOG"] = str(
        task_dir / "tests" / "fixtures" / "catalog_two_instances.json"
    )

    completed = subprocess.run(
        [sys.executable, str(task_dir / "evaluator.py"), str(solution_path)],
        cwd=task_dir,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stdout == "0.000000000000 0.000000000000\n"
    assert completed.stderr == f"submission_invalid code={expected_code}\n"
    assert "PRIVATE" not in completed.stdout + completed.stderr


def test_cli_prints_partial_credit_for_a_valid_ledger(task_dir: Path) -> None:
    env = os.environ.copy()
    env["FCS_STRUCTURED_LWE_CATALOG"] = str(
        task_dir / "tests" / "fixtures" / "catalog_two_instances.json"
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(task_dir / "evaluator.py"),
            str(task_dir / "tests" / "fixtures" / "submission_one_valid.json"),
        ],
        cwd=task_dir,
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stdout == "50.000000000000 1.000000000000\n"
    assert completed.stderr.startswith("scored solved=1 submitted=1 ")
