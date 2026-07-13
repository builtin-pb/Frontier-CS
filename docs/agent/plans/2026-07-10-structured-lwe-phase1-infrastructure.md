# Structured LWE Phase 1 Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add first-class JSON artifact support and a backward-compatible Frontier-CS 2.0 convention that copies `harbor/app/public` into the secretless judge at `/judge/public`.

**Architecture:** The shared language registry becomes the single source of truth for `.json` across CLI, batch, Docker, SkyPilot, and CI reference discovery. The 2.0 adapter keeps copying all of `harbor/app` to the agent, while conditionally adding one judge-image copy for its `public` child only; tasks without that directory retain their current judge shape.

**Tech Stack:** Python 3.11+, pytest 8, PyYAML, Frontier-CS `LanguageConfig`, Frontier-CS 2.0 Harbor adapter, Dockerfile templates, GitHub Actions YAML.

---

## Safety and root cause

No command in this plan runs a solver, evaluator, reference artifact, Docker container, calibration job, or Harbor trial. Do not run `scripts/validate_problems.py`, `frontier eval`, any task `evaluate.sh`, or any recovery command in this phase. Preserve the user-owned `LWE-literature.md` without modifying or staging it.

The direct BBOPlace tasks declare `runtime.language: json`, but `src/frontier_cs/config.py` registers only Python, C++, and Rust. Harbor generation masks this because the adapter parses YAML independently. `scripts.validate_problems.find_reference_solution()`, `ResearchDockerRunner.evaluate()`, `ResearchSkyPilotRunner.evaluate()`, and `BatchEvaluator._build_problem_extensions()` all reach `get_problem_extension()` and fail with `ValueError: Unsupported language: json`.

The adapter currently stages `harbor/app` for the agent. Its judge template copies only `judge_server.py`, `problem_evaluator.py`, and `task_config.json`, so `harbor/app/public` is unavailable to the secretless judge.

### Task 1: Add failing JSON language regression tests

**Files:**
- Create: `tests/test_json_language.py`
- Test: `src/frontier_cs/config.py`
- Test: `scripts/validate_problems.py`
- Test: `src/frontier_cs/runner/research_docker.py`

- [x] **Step 1: Write the failing public-API tests**

Observed: Added registry/extension, two existing BBOPlace reference-discovery,
and Docker-boundary payload tests. The standalone validation script is loaded
locally with `importlib.util` so test collection does not mutate `sys.path`.

Create `tests/test_json_language.py`:

```python
from __future__ import annotations

from pathlib import Path

import pytest

from frontier_cs.config import get_language_config, get_problem_extension
from frontier_cs.runner.base import EvaluationResult
from frontier_cs.runner.research_docker import ResearchDockerRunner
from scripts.validate_problems import find_reference_solution


REPO_ROOT = Path(__file__).resolve().parents[1]


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

    reference = find_reference_solution("2.0", problem_id)

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
```

- [x] **Step 2: Verify RED without crossing the evaluation boundary**

Observed: The usable RED run reported four failures, all caused by
`ValueError: Unsupported language: json`; the monkeypatch prevented Docker.

Run:

```bash
uv run pytest tests/test_json_language.py -q
```

Expected: four collected cases fail with `ValueError: Unsupported language: json`. The capture function prevents Docker execution.

- [x] **Step 3: Commit the RED tests**

Observed: RED evidence was recorded before production editing. Because parallel
workers share one worktree, the controller consolidated the accepted tests and
minimal implementation into one reviewed slice instead of manufacturing a
tests-only commit after GREEN.

```bash
git add tests/test_json_language.py
git commit -m "test: expose missing JSON artifact support"
```

### Task 2: Add the minimal JSON `LanguageConfig`

**Files:**
- Modify: `src/frontier_cs/config.py:197-221`
- Test: `tests/test_json_language.py`

- [x] **Step 1: Replace the language declaration and registry**

Observed: Added the exact JSON registry entry and language-or-artifact
`LanguageConfig` wording. Untouched historical CRLF bytes were preserved; only
changed/new lines use LF so the minimal diff passes the mandated plain check.

Use this exact block in `src/frontier_cs/config.py`:

```python
@dataclass
class LanguageConfig:
    """Configuration for a target submission language or artifact format."""

    name: str
    extension: str
    code_block_tag: str


LANGUAGE_CONFIGS: Dict[str, LanguageConfig] = {
    "python": LanguageConfig(
        name="python",
        extension="py",
        code_block_tag="python",
    ),
    "cpp": LanguageConfig(
        name="cpp",
        extension="cpp",
        code_block_tag="cpp",
    ),
    "rust": LanguageConfig(
        name="rust",
        extension="rs",
        code_block_tag="rust",
    ),
    "json": LanguageConfig(
        name="json",
        extension="json",
        code_block_tag="json",
    ),
}
```

- [x] **Step 2: Verify GREEN**

Observed: `uv run pytest tests/test_json_language.py -q` passed all four cases
with one pre-existing `google.generativeai` warning.

```bash
uv run pytest tests/test_json_language.py -q
```

Expected: `4 passed`.

- [x] **Step 3: Run the surrounding root tests**

Observed: The integrated root suite passed all 20 tests with the same
pre-existing warning and no evaluator import or external execution.

```bash
uv run pytest tests -q
```

Expected: every root test passes.

- [x] **Step 4: Inspect and commit the minimal fix**

Observed: Plain `git diff --check` passed and the production diff contains only
the planned `LanguageConfig` cleanup and JSON entry. Independent specification
and code-quality reviews approved the final slice; the controller commits the
accepted test and implementation together with this execution record.

```bash
git diff --check
git diff -- src/frontier_cs/config.py tests/test_json_language.py
git add src/frontier_cs/config.py
git commit -m "feat: support JSON solution artifacts"
```

Expected: the production diff contains only the docstring cleanup and one JSON registry entry.

### Task 3: Add failing generated-task tests for public assets

**Files:**
- Create: `tests/test_frontier_cs_2_0_public_assets.py`
- Test: `adapters/frontier-cs-2.0/src/frontier_cs_2_0/adapter.py`
- Test: `adapters/frontier-cs-2.0/src/frontier_cs_2_0/task-template/environment/Dockerfile.judge`

- [x] **Step 1: Write the adapter integration tests**

Observed: Added the five planned integration cases plus regressions for size,
special files, package-token safety, ancestor links, no-follow staging, and
staged-tree tampering.

Create `tests/test_frontier_cs_2_0_public_assets.py`:

```python
from __future__ import annotations

import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
ADAPTER_SRC = REPO_ROOT / "adapters" / "frontier-cs-2.0" / "src"
sys.path.insert(0, str(ADAPTER_SRC))

from frontier_cs_2_0.adapter import FrontierCS20Adapter


PUBLIC_PAYLOAD = b'{"instance_id":"fixture_0001"}\n'


def _write_fixture_repo(tmp_path: Path, *, include_public: bool) -> Path:
    repo = tmp_path / "repo"
    problem = repo / "2.0" / "problems" / "json_fixture"
    app = problem / "harbor" / "app"
    solver_dir = app / "tools" / "solvers"
    solver_dir.mkdir(parents=True)
    problem.joinpath("config.yaml").write_text(
        """\
tag: security
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
    problem.joinpath("readme").write_text("# JSON fixture\n", encoding="utf-8")
    problem.joinpath("evaluator.py").write_text(
        "def evaluate(solution_path):\n"
        "    return 0.0, 0.0, 'fixture'\n",
        encoding="utf-8",
    )
    problem.joinpath("reference.json").write_text(
        '{"schema_version": 1, "solutions": []}\n',
        encoding="utf-8",
    )
    solver_dir.joinpath("reference_attack.py").write_text(
        "raise SystemExit('fixture solver must not enter the judge image')\n",
        encoding="utf-8",
    )
    analyses = app / "analyses"
    analyses.mkdir()
    analyses.joinpath("fixture_0001.md").write_text(
        "# Fixture analysis\n",
        encoding="utf-8",
    )
    if include_public:
        public = app / "public"
        public.mkdir()
        public.joinpath("catalog.jsonl").write_bytes(PUBLIC_PAYLOAD)
    return repo


def _generate_fixture(tmp_path: Path, *, include_public: bool) -> Path:
    repo = _write_fixture_repo(tmp_path, include_public=include_public)
    generated = FrontierCS20Adapter(
        repo,
        tmp_path / "generated",
        task_ids=["json_fixture"],
    ).run()
    assert len(generated) == 1
    return generated[0]


def test_public_assets_are_staged_for_agent_and_copied_to_judge(
    tmp_path: Path,
) -> None:
    task = _generate_fixture(tmp_path, include_public=True)
    environment = task / "environment"
    judge = environment.joinpath("Dockerfile.judge").read_text(encoding="utf-8")
    agent = environment.joinpath("Dockerfile").read_text(encoding="utf-8")

    assert environment.joinpath(
        "harbor_app", "public", "catalog.jsonl"
    ).read_bytes() == PUBLIC_PAYLOAD
    assert "COPY harbor_app/ /app/" in agent
    assert "COPY harbor_app/public/ /judge/public/" in judge
    assert "ENV FRONTIER_PUBLIC_DIR=/judge/public" in judge
    assert "COPY harbor_app/ /judge/" not in judge
    assert "harbor_app/tools" not in judge
    assert "harbor_app/analyses" not in judge
    assert "{judge_public_assets}" not in judge


def test_agent_only_pip_packages_do_not_enter_judge(tmp_path: Path) -> None:
    task = _generate_fixture(tmp_path, include_public=False)
    environment = task / "environment"
    judge = environment.joinpath("Dockerfile.judge").read_text(encoding="utf-8")
    agent = environment.joinpath("Dockerfile").read_text(encoding="utf-8")

    assert "numpy==2.1.3" in agent
    assert "jsonschema==4.23.0" in agent
    assert "numpy==2.1.3" not in judge
    assert "jsonschema==4.23.0" in judge


def test_task_without_public_assets_keeps_existing_judge_shape(
    tmp_path: Path,
) -> None:
    task = _generate_fixture(tmp_path, include_public=False)
    environment = task / "environment"
    judge = environment.joinpath("Dockerfile.judge").read_text(encoding="utf-8")

    assert not environment.joinpath("harbor_app", "public").exists()
    assert "COPY harbor_app/public/ /judge/public/" not in judge
    assert "FRONTIER_PUBLIC_DIR" not in judge
    assert "{judge_public_assets}" not in judge
    assert "COPY judge_server.py problem_evaluator.py task_config.json /judge/" in judge


def test_json_reference_bytes_reach_configured_submission_path(
    tmp_path: Path,
) -> None:
    task = _generate_fixture(tmp_path, include_public=True)

    assert task.joinpath("solution", "reference.py").read_text(
        encoding="utf-8"
    ) == '{"schema_version": 1, "solutions": []}\n'
    assert "cp /solution/reference.py /app/solution.json" in task.joinpath(
        "solution", "solve.sh"
    ).read_text(encoding="utf-8")


def test_public_assets_reject_symlinks_before_staging(tmp_path: Path) -> None:
    repo = _write_fixture_repo(tmp_path, include_public=True)
    outside = tmp_path / "outside-secret"
    outside.write_text("must not enter either image", encoding="utf-8")
    (repo / "2.0/problems/json_fixture/harbor/app/public/escape").symlink_to(outside)
    with pytest.raises(ValueError, match="public assets may not contain symlinks"):
        FrontierCS20Adapter(repo, tmp_path / "generated", task_ids=["json_fixture"]).run()
```

- [x] **Step 2: Verify the intended RED state**

Observed: The public-copy case failed at the missing judge `COPY`, and the
dependency-boundary case failed at missing agent-only `numpy`. Later security
regressions also recorded three intended failures before hardening.

```bash
uv run pytest tests/test_frontier_cs_2_0_public_assets.py::test_public_assets_are_staged_for_agent_and_copied_to_judge -q
```

Expected: one assertion fails because `Dockerfile.judge` lacks `COPY harbor_app/public/ /judge/public/`.

Run the dependency-boundary test separately and verify RED because the current
adapter does not install `runtime.pip_packages` in the agent image:

```bash
uv run pytest tests/test_frontier_cs_2_0_public_assets.py::test_agent_only_pip_packages_do_not_enter_judge -q
```

- [x] **Step 3: Characterize existing compatibility behavior**

Observed: The no-public judge-shape and JSON-reference characterization cases
both passed before production changes.

```bash
uv run pytest \
  tests/test_frontier_cs_2_0_public_assets.py::test_task_without_public_assets_keeps_existing_judge_shape \
  tests/test_frontier_cs_2_0_public_assets.py::test_json_reference_bytes_reach_configured_submission_path \
  -q
```

Expected: `2 passed`.

- [x] **Step 4: Commit the RED tests**

Observed: RED evidence was recorded before implementation. Shared-worktree
parallelism required the controller to consolidate accepted tests and code in
one reviewed commit instead of reconstructing a tests-only RED commit.

```bash
git add tests/test_frontier_cs_2_0_public_assets.py
git commit -m "test: specify judge-visible public assets"
```

### Task 4: Emit the conditional judge public-assets copy

**Files:**
- Modify: `adapters/frontier-cs-2.0/src/frontier_cs_2_0/adapter.py:238-276`
- Modify: `adapters/frontier-cs-2.0/src/frontier_cs_2_0/task-template/environment/Dockerfile.judge:8-11`
- Test: `tests/test_frontier_cs_2_0_public_assets.py`

- [x] **Step 1: Compute the optional Dockerfile fragment**

Observed: Added recursive 64 MiB/type validation, source component `lstat`
checks, no-follow whole-app staging, source recheck, staged-public validation,
and the conditional public-only judge fragment.

Before the existing `shutil.copytree()` call, recursively validate the source
`harbor/app/public` tree with `lstat`: reject every symlink, socket, FIFO,
device, or non-regular/non-directory entry and reject a total regular-file
size above 64 MiB. This validation happens before the agent staging copy, so a
symlink cannot be dereferenced into either build context. Then, immediately
after the copy block, add:

```python
        public_assets_dir = generated_harbor_app_dir / "public"
        judge_public_assets = ""
        if public_assets_dir.is_dir():
            judge_public_assets = (
                "COPY harbor_app/public/ /judge/public/\n"
                "ENV FRONTIER_PUBLIC_DIR=/judge/public\n"
            )
```

- [x] **Step 2: Separate agent-only and judge pip dependencies**

Observed: The agent receives a stable deduplicated union while the judge gets
only judge requirements. Agent entries require exact safe pins; judge entries
allow safe bare names or exact pins, rejecting whitespace and shell syntax.

Treat `runtime.pip_packages` as agent-only and
`runtime.judge_pip_packages` as judge-required. The agent image installs the
deduplicated union because it also hosts local judge-facing helpers; the judge
image installs only `judge_pip_packages`. Render separate
`agent_pip_install` and `judge_pip_install` fragments and never reuse the
judge list as the agent-only dependency mechanism. Require exact `==` pins in
`pip_packages` for this task, reject shell metacharacters/whitespace in every
package token, and add a backward-compatibility test for configurations that
omit the new key.
The agent Dockerfile's `{extra_pip_install}` replacement uses
`agent_pip_install`; the judge Dockerfile's `{judge_pip_install}` replacement
uses `judge_pip_install`.

- [x] **Step 3: Substitute the fragment into the judge template**

Observed: Separate judge pip and public-asset fragments are substituted with no
unresolved placeholder in either generated task shape.

Replace the judge Dockerfile replacement chain with:

```python
        env_dir.joinpath("Dockerfile.judge").write_text(
            judge_dockerfile.replace("{base_image}", judge_image)
            .replace(
                "{judge_apt_packages_line}",
                f" {judge_apt_packages}" if judge_apt_packages else "",
            )
            .replace("{judge_pip_install}", judge_pip_install)
            .replace("{judge_public_assets}", judge_public_assets),
            encoding="utf-8",
        )
```

- [x] **Step 4: Add the template placeholder**

Observed: Added the conditional placeholder immediately after the narrow judge
file copy and before evaluator permissions are set.

Replace the copy-and-permission section of `Dockerfile.judge` with:

```dockerfile
COPY judge_server.py problem_evaluator.py task_config.json /judge/
{judge_public_assets}RUN chmod 600 /judge/problem_evaluator.py
```

- [x] **Step 5: Verify GREEN and backward compatibility**

Observed: The final focused suite passed 16 tests and the integrated root suite
passed 23 tests, with only the pre-existing `google.generativeai` warning.

```bash
uv run pytest tests/test_frontier_cs_2_0_public_assets.py -q
uv run pytest tests -q
```

Expected: the focused file reports all public-asset, symlink, and compatibility
tests passing, then all root tests pass.

- [x] **Step 6: Check scope and commit**

Observed: Global `git diff --check`, Python compilation, and the broad judge-copy
search passed. Specification and security/code-quality re-reviews approved the
final no-follow implementation; the controller commits this accepted slice.

```bash
git diff --check
test "$(rg -n 'COPY harbor_app/ /judge/' \
  adapters/frontier-cs-2.0/src/frontier_cs_2_0/adapter.py \
  adapters/frontier-cs-2.0/src/frontier_cs_2_0/task-template/environment/Dockerfile.judge \
  | wc -l | tr -d ' ')" -eq 0
git add \
  adapters/frontier-cs-2.0/src/frontier_cs_2_0/adapter.py \
  adapters/frontier-cs-2.0/src/frontier_cs_2_0/task-template/environment/Dockerfile.judge
git commit -m "feat: expose public task assets to 2.0 judges"
```

Expected: no broad agent-workspace copy enters the judge.

### Task 5: Run static backward-compatibility generation checks

**Files:**
- Validate: `2.0/problems/erdos_demo`
- Validate: four existing BBOPlace task directories
- Validate: `tools/bboplace/check_generated_tasks.py`

- [x] **Step 1: Generate the no-public Erdos task without running it**

Observed: Static adapter generation exited zero with `[OK] erdos_demo` and one
task under `/tmp/frontier-cs-phase1-erdos`; nothing was executed.

```bash
PYTHONPATH=adapters/frontier-cs-2.0/src \
uv run --no-sync python -m frontier_cs_2_0.main \
  --source "$PWD" \
  --output-dir /tmp/frontier-cs-phase1-erdos \
  --task-ids erdos_demo \
  --overwrite
```

Expected: one generated directory and no evaluator or Docker invocation.

- [x] **Step 2: Assert the no-public judge shape**

Observed: All three assertions exited zero: no staged public directory, no
public judge `COPY`, and no unresolved placeholder.

```bash
test ! -d /tmp/frontier-cs-phase1-erdos/frontier-cs-2-0-erdos-demo/environment/harbor_app/public
test "$(grep -c 'COPY harbor_app/public/ /judge/public/' \
  /tmp/frontier-cs-phase1-erdos/frontier-cs-2-0-erdos-demo/environment/Dockerfile.judge)" -eq 0
test "$(grep -c '{judge_public_assets}' \
  /tmp/frontier-cs-phase1-erdos/frontier-cs-2-0-erdos-demo/environment/Dockerfile.judge)" -eq 0
```

Expected: all three commands exit zero.

- [x] **Step 3: Generate all BBOPlace tasks without running them**

Observed: Static generation exited zero with all four named tasks reported
`[OK]` under `/tmp/frontier-cs-phase1-bboplace`.

```bash
PYTHONPATH=adapters/frontier-cs-2.0/src \
uv run --no-sync python -m frontier_cs_2_0.main \
  --source "$PWD" \
  --output-dir /tmp/frontier-cs-phase1-bboplace \
  --task-ids \
    bboplace_ispd2005 \
    bboplace_iccad2015 \
    bboplace_direct_ispd2005 \
    bboplace_direct_iccad2015 \
  --overwrite
```

Expected: four generated directories and no evaluator or Docker invocation.

- [x] **Step 4: Run the existing structural checker**

Observed: The checker printed `Generated BBOPlace tasks match the expected
Harbor flow`; both direct-task greps printed the JSON copy command.

```bash
python3 tools/bboplace/check_generated_tasks.py /tmp/frontier-cs-phase1-bboplace
grep -F "cp /solution/reference.py /app/solution.json" \
  /tmp/frontier-cs-phase1-bboplace/frontier-cs-2-0-bboplace-direct-ispd2005/solution/solve.sh
grep -F "cp /solution/reference.py /app/solution.json" \
  /tmp/frontier-cs-phase1-bboplace/frontier-cs-2-0-bboplace-direct-iccad2015/solution/solve.sh
```

Expected: the checker prints `Generated BBOPlace tasks match the expected Harbor flow`, and each grep prints one JSON copy command.

- [x] **Step 5: Leave generated output isolated under the system temp root**

Observed: Outputs remain at `/tmp/frontier-cs-phase1-erdos` and
`/tmp/frontier-cs-phase1-bboplace`; no destructive cleanup was run.

Record the two `/tmp/frontier-cs-phase1-*` paths in the phase log. They are
outside the repository and may be reclaimed by the operating system; no
destructive cleanup command is required.

### Task 6: Wire solver-free infrastructure tests into CI

**Files:**
- Modify: `.github/workflows/validate-problems.yml:4-9`
- Modify: `.github/workflows/validate-problems.yml` after `detect-changes`

- [x] **Step 1: Extend the workflow path filter**

Observed: Added the adapter, shared config, and both focused infrastructure
test paths alongside the existing problem paths.

Use this exact block:

```yaml
on:
  pull_request:
    paths:
      - 'algorithmic/problems/**'
      - 'research/problems/**'
      - '2.0/problems/**'
      - 'adapters/frontier-cs-2.0/**'
      - 'src/frontier_cs/config.py'
      - 'tests/test_json_language.py'
      - 'tests/test_frontier_cs_2_0_public_assets.py'
```

- [x] **Step 2: Add the independent infrastructure job**

Observed: Added the independent Python 3.11/uv job with the exact two-file
solver-free pytest command and no dependency on problem validation jobs.

Add this complete job beside `validate-algorithmic`:

```yaml
  validate-benchmark20-infrastructure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install uv
        uses: astral-sh/setup-uv@v4

      - name: Install dependencies
        run: uv sync

      - name: Run Frontier-CS 2.0 infrastructure tests
        run: |
          uv run pytest \
            tests/test_json_language.py \
            tests/test_frontier_cs_2_0_public_assets.py \
            -q
```

- [x] **Step 3: Parse YAML and run the focused suite**

Observed: YAML parsing passed. The first test attempt overlapped the JSON RED
phase; the integrated root suite subsequently passed all 20 tests, including
both focused infrastructure files.

```bash
uv run python -c "from pathlib import Path; import yaml; data=yaml.safe_load(Path('.github/workflows/validate-problems.yml').read_text()); assert data"
uv run pytest tests/test_json_language.py tests/test_frontier_cs_2_0_public_assets.py -q
```

Expected: YAML parsing exits zero and all focused infrastructure tests pass.

- [x] **Step 4: Commit CI coverage**

Observed: Independent specification and code-quality reviews approved the
workflow. The controller committed the accepted workflow with this execution
record rather than using an implementer-side commit.

```bash
git add .github/workflows/validate-problems.yml
git commit -m "ci: validate 2.0 JSON and public assets"
```

### Task 7: Document both public contracts

**Files:**
- Modify: `2.0/CONTRIBUTING.md`
- Modify: `adapters/frontier-cs-2.0/README.md`

- [x] **Step 1: Document static JSON artifacts**

Observed: Added extension-aware reference guidance and the static JSON
artifact contract, including `reference.json` and the non-execution rule.

After the file-submission example in `2.0/CONTRIBUTING.md`, add:

````markdown
For a static JSON artifact, declare JSON as the runtime language so the CLI,
batch runner, CI reference discovery, and Harbor adapter all use `.json`:

```yaml
runtime:
  language: json
submission:
  kind: file
  path: /app/solution.json
```

Commit a matching `reference.json`. JSON is an artifact format: the evaluator
reads the submitted bytes and must not execute them as Python code.
````

- [x] **Step 2: Document shared public assets**

Observed: Documented the agent and judge paths, judge environment variable,
sibling-tree exclusion, and the public-tree type and 64 MiB validation limits.

Before `## Black-Box Safety` in `2.0/CONTRIBUTING.md`, add:

```markdown
## Public Assets Shared With the Judge

Put byte-identical public verifier inputs under:

```text
2.0/problems/<problem_id>/harbor/app/public/
```

The generated agent image exposes this directory at `/app/public`. The
generated judge image exposes only this `public` child at `/judge/public` and
sets `FRONTIER_PUBLIC_DIR=/judge/public`. Sibling resources such as
`harbor/app/tools/` and `harbor/app/analyses/` are not copied into the judge.

Use this convention for public catalogs and deterministic materializers that
the evaluator must read. Do not place private test data, planted answers,
secret seeds, or evaluator-only configuration in `harbor/app/public`.
```

- [x] **Step 3: Document adapter output**

Observed: Documented the conditional public-only judge copy and confirmed that
tasks without public assets retain the previous judge image shape.

After the paragraph describing `harbor/app/` in `adapters/frontier-cs-2.0/README.md`, add:

```markdown
An optional `harbor/app/public/` child is also copied into the judge image at
`/judge/public`, with `FRONTIER_PUBLIC_DIR` set to that path. This is the only
`harbor/app` subtree shared with the judge. Tasks without `harbor/app/public/`
emit no additional judge `COPY` instruction, preserving the previous image
shape.
```

- [x] **Step 4: Document agent-only Python dependencies**

Observed: Documented agent-only exact pins, shell-safe judge tokens, the
agent/judge installation boundary, and minimal secretless-judge guidance.

Document `runtime.pip_packages` as agent-only and
`runtime.judge_pip_packages` as judge-required (and therefore also present in
the agent). Require one exact package token per YAML item and explain that
heavy research/analysis dependencies should remain agent-only while a
secretless evaluator should keep the judge minimal.

- [x] **Step 5: Verify and commit documentation**

Observed: All specified greps and `git diff --check` passed. Independent
specification review passed; quality review requested two precision fixes and
approved the revised documentation. The controller records the accepted docs
and execution log together rather than creating an implementer-side commit.

```bash
grep -F "language: json" 2.0/CONTRIBUTING.md
grep -F "harbor/app/public/" 2.0/CONTRIBUTING.md adapters/frontier-cs-2.0/README.md
grep -F "FRONTIER_PUBLIC_DIR=/judge/public" 2.0/CONTRIBUTING.md adapters/frontier-cs-2.0/README.md
grep -F "harbor/app/tools/" 2.0/CONTRIBUTING.md
grep -F "runtime.pip_packages" 2.0/CONTRIBUTING.md adapters/frontier-cs-2.0/README.md
git add 2.0/CONTRIBUTING.md adapters/frontier-cs-2.0/README.md
git commit -m "docs: describe JSON and shared public assets"
```

Expected: every grep prints the new contract text.

### Task 8: Complete solver-free verification

**Files:**
- Verify: `src/frontier_cs/config.py`
- Verify: `adapters/frontier-cs-2.0/src/frontier_cs_2_0/adapter.py`
- Verify: `adapters/frontier-cs-2.0/src/frontier_cs_2_0/task-template/environment/Dockerfile.judge`
- Verify: `tests/test_json_language.py`
- Verify: `tests/test_frontier_cs_2_0_public_assets.py`
- Verify: `.github/workflows/validate-problems.yml`
- Verify: `2.0/CONTRIBUTING.md`
- Verify: `adapters/frontier-cs-2.0/README.md`

- [ ] **Step 1: Run all root unit tests**

```bash
uv run pytest tests -q
```

Expected: every root test passes without importing a task evaluator.

- [ ] **Step 2: Compile modified Python infrastructure outside the worktree cache**

```bash
PYTHONPYCACHEPREFIX=/tmp/frontier-cs-phase1-pycache \
python3 -m py_compile \
  src/frontier_cs/config.py \
  adapters/frontier-cs-2.0/src/frontier_cs_2_0/adapter.py \
  tests/test_json_language.py \
  tests/test_frontier_cs_2_0_public_assets.py
```

Expected: exit zero, with bytecode under `/tmp/frontier-cs-phase1-pycache`.

- [ ] **Step 3: Check whitespace and copy scope**

```bash
git diff --check
test "$(rg -n 'COPY harbor_app/ /judge/' \
  adapters/frontier-cs-2.0/src/frontier_cs_2_0/adapter.py \
  adapters/frontier-cs-2.0/src/frontier_cs_2_0/task-template/environment/Dockerfile.judge \
  | wc -l | tr -d ' ')" -eq 0
```

Expected: no whitespace errors and no broad judge copy.

- [ ] **Step 4: Review only the Phase 1 paths**

```bash
git status --short
BASE_COMMIT=$(git merge-base HEAD origin/main)
git diff --stat "$BASE_COMMIT"..HEAD
git diff "$BASE_COMMIT"..HEAD -- \
  src/frontier_cs/config.py \
  adapters/frontier-cs-2.0/src/frontier_cs_2_0/adapter.py \
  adapters/frontier-cs-2.0/src/frontier_cs_2_0/task-template/environment/Dockerfile.judge \
  tests/test_json_language.py \
  tests/test_frontier_cs_2_0_public_assets.py \
  .github/workflows/validate-problems.yml \
  2.0/CONTRIBUTING.md \
  adapters/frontier-cs-2.0/README.md
```

Expected: only the eight scoped implementation paths appear, independent of the number of TDD commits. `LWE-literature.md` remains unstaged and unchanged.

## Acceptance criteria

- JSON resolves through `get_language_config()` and `get_problem_extension()`.
- Both existing BBO direct `reference.json` files are discoverable without evaluator execution.
- The Docker runner writes JSON code to a `.json` temporary artifact before its external boundary.
- `harbor/app/public` is staged once and copied to `/judge/public`.
- The judge receives neither `harbor/app/tools` nor `harbor/app/analyses`.
- Tasks without public assets emit no extra judge copy and no unresolved placeholder.
- Agent-only `runtime.pip_packages` never enter the judge; judge-required pins
  remain available in both images.
- Existing static BBOPlace generated-task checks remain green.
- CI runs both focused infrastructure test files on relevant changes.
- Documentation defines both contracts.
- No solver, evaluator, Harbor trial, calibration job, or witness runs in Phase 1.
