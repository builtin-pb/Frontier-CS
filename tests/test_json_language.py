from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from frontier_cs.config import get_language_config, get_problem_extension
from frontier_cs.runner.base import EvaluationResult
from frontier_cs.runner.research_docker import ResearchDockerRunner


REPO_ROOT = Path(__file__).resolve().parents[1]


def _find_reference_solution(track: str, problem_id: str) -> Path | None:
    script_path = REPO_ROOT / "scripts" / "validate_problems.py"
    spec = importlib.util.spec_from_file_location("validate_problems", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.find_reference_solution(track, problem_id)


def _write_json_problem(problem_dir: Path) -> None:
    problem_dir.mkdir(parents=True)
    problem_dir.joinpath("config.yaml").write_text(
        """\
tag: optimization
runtime:
  language: json
  timeout_seconds: 300
  pip_packages:
    - numpy==2.1.3
  judge_pip_packages:
    - jsonschema==4.23.0
  docker:
    image: ubuntu:24.04
submission:
  kind: file
  path: /app/solution.json
""",
        encoding="utf-8",
    )
    problem_dir.joinpath("reference.json").write_text(
        '{"schema_version": 1, "solutions": []}\n',
        encoding="utf-8",
    )


def test_json_language_config_exposes_json_extension(tmp_path: Path) -> None:
    problem_dir = tmp_path / "json_problem"
    _write_json_problem(problem_dir)

    language = get_language_config(problem_dir)

    assert language.name == "json"
    assert language.extension == "json"
    assert language.code_block_tag == "json"
    assert get_problem_extension(problem_dir) == "json"


@pytest.mark.parametrize(
    "problem_id",
    ["bboplace_direct_ispd2005", "bboplace_direct_iccad2015"],
)
def test_existing_bbo_json_reference_is_discoverable(
    monkeypatch: pytest.MonkeyPatch,
    problem_id: str,
) -> None:
    monkeypatch.chdir(REPO_ROOT)

    reference = _find_reference_solution("2.0", problem_id)

    assert reference == Path(f"2.0/problems/{problem_id}/reference.json")


def test_docker_runner_materializes_json_before_evaluation_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    problems_dir = tmp_path / "2.0" / "problems"
    problem_dir = problems_dir / "json_problem"
    _write_json_problem(problem_dir)
    runner = ResearchDockerRunner(
        base_dir=tmp_path,
        problems_dir=problems_dir,
        datasets_dir=tmp_path / "datasets",
    )
    observed: dict[str, str] = {}

    def capture_boundary(
        problem_id: str,
        received_problem_dir: Path,
        solution_path: Path,
    ) -> EvaluationResult:
        observed["problem_id"] = problem_id
        observed["problem_dir"] = str(received_problem_dir)
        observed["suffix"] = solution_path.suffix
        observed["payload"] = solution_path.read_text(encoding="utf-8")
        return EvaluationResult(problem_id=problem_id, score=0.0)

    monkeypatch.setattr(runner, "_run_evaluation", capture_boundary)
    payload = '{"schema_version": 1, "solutions": []}'

    result = runner.evaluate("json_problem", payload)

    assert result.success
    assert observed == {
        "problem_id": "json_problem",
        "problem_dir": str(problem_dir),
        "suffix": ".json",
        "payload": payload,
    }
