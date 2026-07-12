# Structured LWE Phase 3 Solvers and Calibration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the gated clean-room exact-recovery solver portfolio, attack and reduction audits, uniqueness machinery, calibrated runtime models, 60/140 ladder assignment, and witness-leak controls for `lwe_structured_recovery`.

**Architecture:** Phase 3 imports only the Phase 2 public facade
`2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_instance.py`. The
facade supplies `Catalog.load(path)`, public `Instance` properties including
`b` and all matrix/secret/error distribution parameters, streamed/block/full
row access, `Instance.matvec(secret)`, and
`Instance.validate_secret(secret)`. Solvers share one typed protocol and
registry; offline analysis tools produce schema-validated estimates, audits,
calibration logs, models, and ladder placements without placing witnesses in
committed artifacts.

**Tech Stack:** Python 3.11+, NumPy, SciPy, fpylll/fplll, psutil, canonical JSON, pytest, SHA-256, and the pinned Lattice Estimator.

---

## Preconditions and non-negotiable invariants

- Read `docs/agent/specs/2026-07-10-structured-lwe-recovery-design.md` and the master plan before implementation.
- Do not import `harbor/app/public/lwe_challenge/` internals; use only `lwe_instance.py`.
- Do not edit the user-owned root `LWE-literature.md`.
- Do not start a solver, recovery smoke test, calibration run, or production solution attempt before `2026-07-10T23:00:00+08:00`.
- The family set is exactly `DS_BIN`, `DS_TER`, `DS_SMALL`, `SA_Q`, `SA_SMALL`, `DA_BIN`, `DA_TER`, `MIX_Q_SPARSE`, `MIX_SMALL_SPARSE`, and `MIX_DENSE_SMALL`.
- Each family has 20 final instances: six measured paper cases and fourteen modeled cases. Mixed families are first-class scored families, not a separate experimental category.
- Only exact-search attacks influence admission or runtime placement. Decision and refutation estimates are retained as non-qualifying leads.
- Phase 4 owns production records and prose. Phase 3 creates machinery, schemas, synthetic fixtures, and smoke artifacts only.

## File map

Create these focused units:

```text
2.0/problems/lwe_structured_recovery/
  harbor/app/tools/solvers/
    __init__.py
    execution_gate.py
    api.py
    registry.json
    registry.py
    cli.py
    primal_bdd.py
    sparse_secret.py
    small_secret_hybrid.py
    sparse_matrix.py
    mixed_recovery.py
    bounded_error.py
    requirements.lock
    requirements.lock.json
  analysis_tools/
    __init__.py
    docker/Dockerfile
    estimate_types.py
    attack_estimates.py
    lattice_estimator.py
    reduction_audits.py
    reduction_assumptions.json
    uniqueness.py
    calibration_types.py
    calibration_runner.py
    runtime_model.py
    ladder.py
    leak_audit.py
  calibration/schemas/
    attack-estimate.schema.json
    reduction-audit.schema.json
    calibration-run.schema.json
    runtime-model.schema.json
    ladder.schema.json
  calibration/lattice-estimator.lock.json
  tests/
    conftest.py                    extend Phase-2 fixture/import plumbing
    test_execution_gate.py
    test_solver_registry.py
    test_solver_api.py
    test_sparse_secret_solver.py
    test_sparse_matrix_solver.py
    test_mixed_and_error_solvers.py
    test_primal_bdd.py
    test_attack_estimates.py
    test_reduction_audits.py
    test_uniqueness.py
    test_calibration_runner.py
    test_runtime_model.py
    test_ladder.py
    test_leak_audit.py
```

## Safe command policy

Commands labeled **STATIC** do not recover an LWE secret and may run before the gate. Commands labeled **GATED** must run only after the durable gate-crossing procedure in the master plan. Never replace a gated expected result with an unexecuted claim; record it as `SKIPPED (execution gate)` until permitted.

### Task 1: Enforce the solver execution gate

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/execution_gate.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_execution_gate.py`

- [ ] **Step 1: Write the failing clock-injection tests**

```python
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from tools.solvers.execution_gate import ExecutionBlocked, require_solver_gate


HKT = ZoneInfo("Asia/Hong_Kong")


def test_gate_rejects_one_second_early() -> None:
    with pytest.raises(ExecutionBlocked, match=r"2026-07-10T23:00:00\+08:00"):
        require_solver_gate(datetime(2026, 7, 10, 22, 59, 59, tzinfo=HKT))


def test_gate_accepts_exact_boundary() -> None:
    assert require_solver_gate(datetime(2026, 7, 10, 23, 0, 0, tzinfo=HKT)).isoformat() == "2026-07-10T23:00:00+08:00"


def test_gate_rejects_naive_clock() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        require_solver_gate(datetime(2026, 7, 10, 23, 0, 0))
```

- [ ] **Step 2: Run the STATIC test and observe the expected failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_execution_gate.py`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'tools.solvers.execution_gate'`.

- [ ] **Step 3: Add the gate implementation**

```python
from datetime import datetime
from zoneinfo import ZoneInfo


HKT = ZoneInfo("Asia/Hong_Kong")
NOT_BEFORE = datetime(2026, 7, 10, 23, 0, 0, tzinfo=HKT)


class ExecutionBlocked(RuntimeError):
    pass


def require_solver_gate(now: datetime | None = None) -> datetime:
    observed = now if now is not None else datetime.now(HKT)
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise ValueError("solver gate clock must be timezone-aware")
    observed_hkt = observed.astimezone(HKT)
    if observed_hkt < NOT_BEFORE:
        raise ExecutionBlocked(
            "solver execution is disabled until 2026-07-10T23:00:00+08:00"
        )
    return observed_hkt
```

- [ ] **Step 4: Run the STATIC test and verify all three cases pass**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_execution_gate.py`

Expected: `3 passed` and no solver invocation.

- [ ] **Step 5: Commit the gate slice**

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/execution_gate.py 2.0/problems/lwe_structured_recovery/tests/test_execution_gate.py
git commit -m "feat(lwe): enforce solver execution gate"
```

### Task 2: Define the exact-search protocol and scrubbed result boundary

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/__init__.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/api.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_solver_api.py`

- [ ] **Step 1: Write failing tests for result validation and scrubbing**

```python
import pytest

from tools.solvers.api import (
    GatedExactSolver,
    SolveRequest,
    SolveResult,
    SolveStatus,
    scrub_result,
)


def test_success_requires_valid_secret() -> None:
    result = SolveResult.success((0, 1, 0), elapsed_seconds=1.25, work_units=17)
    assert result.status is SolveStatus.SUCCESS
    assert result.secret == (0, 1, 0)


def test_scrubbed_result_has_no_secret() -> None:
    result = SolveResult.success((0, 1, 0), elapsed_seconds=1.25, work_units=17)
    public = scrub_result(result)
    assert "secret" not in public
    assert public == {
        "status": "success", "elapsed_seconds": 1.25, "work_units": 17,
        "peak_rss_bytes": 0, "checkpoint_count": 0, "detail": {},
    }


def test_base_wrapper_checks_gate_before_solver_body(monkeypatch, tmp_path) -> None:
    entered = False

    class Dummy(GatedExactSolver):
        solver_id = "dummy"

        def _solve(self, instance, request):
            nonlocal entered
            entered = True
            raise AssertionError("body must not run")

    monkeypatch.setattr("tools.solvers.api.require_solver_gate", lambda: (_ for _ in ()).throw(RuntimeError("gate")))
    with pytest.raises(RuntimeError, match="gate"):
        Dummy().solve(None, SolveRequest(1, 1.0, tmp_path))
    assert not entered
```

- [ ] **Step 2: Run the STATIC test and observe the expected import failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_solver_api.py`

Expected: FAIL with `ModuleNotFoundError: No module named 'tools.solvers.api'`.

- [ ] **Step 3: Add the protocol types and one-way scrubber**

```python
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Mapping, Protocol, final

from .execution_gate import require_solver_gate


class SolveStatus(StrEnum):
    SUCCESS = "success"
    EXHAUSTED = "exhausted"
    CENSORED = "censored"
    ERROR = "error"


@dataclass(frozen=True)
class SolveRequest:
    seed: int
    max_seconds: float
    work_dir: Path
    single_worker: bool = True
    exclude_secret: tuple[int, ...] | None = None
    parameters: Mapping[str, object] = field(default_factory=dict)
    resume_checkpoint: Path | None = None
    checkpoint_every_work_units: int = 10_000


@dataclass(frozen=True)
class SolveResult:
    status: SolveStatus
    secret: tuple[int, ...] | None
    elapsed_seconds: float
    work_units: int
    peak_rss_bytes: int = 0
    checkpoint_count: int = 0
    detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def success(cls, secret: tuple[int, ...], elapsed_seconds: float, work_units: int) -> "SolveResult":
        return cls(SolveStatus.SUCCESS, secret, elapsed_seconds, work_units)


class ExactSolver(Protocol):
    solver_id: str

    def solve(self, instance: Any, request: SolveRequest) -> SolveResult:
        pass


class GatedExactSolver:
    solver_id: str

    @final
    def solve(self, instance: Any, request: SolveRequest) -> SolveResult:
        require_solver_gate()
        return self._solve(instance, request)

    def _solve(self, instance: Any, request: SolveRequest) -> SolveResult:
        raise NotImplementedError


def scrub_result(result: SolveResult) -> dict[str, Any]:
    forbidden = {"secret", "witness", "candidate", "vector", "residual"}
    if forbidden.intersection(result.detail):
        raise ValueError("solver detail contains private witness material")
    return {
        "status": result.status.value,
        "elapsed_seconds": result.elapsed_seconds,
        "work_units": result.work_units,
        "peak_rss_bytes": result.peak_rss_bytes,
        "checkpoint_count": result.checkpoint_count,
        "detail": dict(result.detail),
    }
```

All concrete solvers implement `_solve` and must not override `solve`;
registry validation rejects a class with `"solve" in cls.__dict__`. Add
`ProgressEvent` and `CheckpointStore` in the same module. Progress is
secret-free JSONL containing solver/instance IDs, elapsed time, work units,
phase, peak RSS, and checkpoint count. Checkpoints live only under the request
work directory, bind solver revision/instance digest/seed, use atomic writes,
and may contain resumable private search state; release/leak audits therefore
forbid checkpoint files from committed task artifacts. Tests cover resume
equivalence, corrupt/mismatched checkpoint rejection, monotone progress, and
peak-memory reporting.

- [ ] **Step 4: Run the STATIC API tests**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_solver_api.py`

Expected: all API, gate-wrapper, progress, and checkpoint tests pass.

- [ ] **Step 5: Commit the protocol slice**

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/__init__.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/api.py 2.0/problems/lwe_structured_recovery/tests/test_solver_api.py
git commit -m "feat(lwe): define exact solver protocol"
```

### Task 3: Add the clean-room solver registry and ten-family coverage gate

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/registry.json`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/registry.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/sources.json`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_solver_registry.py`
- Modify: `2.0/problems/lwe_structured_recovery/tests/conftest.py`

- [ ] **Step 1: Write the complete registry record**

```json
{
  "schema_version": 1,
  "solvers": [
    {"id":"primal_bdd","entrypoint":"tools.solvers.primal_bdd:PrimalBDD","applicability":"tools.solvers.primal_bdd:applicability","task":"exact_search","randomized":false,"families":["DS_BIN","DS_TER","DS_SMALL","SA_Q","SA_SMALL","DA_BIN","DA_TER","MIX_Q_SPARSE","MIX_SMALL_SPARSE","MIX_DENSE_SMALL"],"citations":["lindner-peikert-2011","albrecht-goepfert-virdia-wunderer-2017"]},
    {"id":"sparse_secret_enum","entrypoint":"tools.solvers.sparse_secret:SparseSecretEnumerator","applicability":"tools.solvers.sparse_secret:enumerator_applicability","task":"exact_search","randomized":false,"families":["DS_BIN","DS_TER","MIX_Q_SPARSE","MIX_SMALL_SPARSE","MIX_DENSE_SMALL"],"citations":["son-cheon-2019"]},
    {"id":"sparse_secret_mitm","entrypoint":"tools.solvers.sparse_secret:SparseSecretMitM","applicability":"tools.solvers.sparse_secret:mitm_applicability","task":"exact_search","randomized":false,"families":["DS_BIN","DS_TER","MIX_DENSE_SMALL"],"citations":["espitau-joux-kharchenko-2020"]},
    {"id":"small_secret_hybrid","entrypoint":"tools.solvers.small_secret_hybrid:SmallSecretHybrid","applicability":"tools.solvers.small_secret_hybrid:applicability","task":"exact_search","randomized":true,"families":["DS_SMALL","MIX_DENSE_SMALL"],"citations":["espitau-joux-kharchenko-2020","bi-lu-luo-wang-zhang-2021"]},
    {"id":"repeated_support","entrypoint":"tools.solvers.sparse_matrix:RepeatedSupportRecovery","applicability":"tools.solvers.sparse_matrix:repeated_support_applicability","task":"exact_search","randomized":false,"families":["SA_Q","SA_SMALL","MIX_Q_SPARSE","MIX_SMALL_SPARSE"],"citations":["jain-lin-saha-2024"]},
    {"id":"graph_peeling","entrypoint":"tools.solvers.sparse_matrix:GraphPeelingRecovery","applicability":"tools.solvers.sparse_matrix:graph_peeling_applicability","task":"exact_search","randomized":false,"families":["SA_SMALL","MIX_SMALL_SPARSE"],"citations":["jain-lin-saha-2024"]},
    {"id":"dense_minor","entrypoint":"tools.solvers.sparse_matrix:DenseMinorRecovery","applicability":"tools.solvers.sparse_matrix:dense_minor_applicability","task":"exact_search","randomized":true,"families":["SA_Q","SA_SMALL","MIX_Q_SPARSE","MIX_SMALL_SPARSE"],"citations":["jain-lin-saha-2024"]},
    {"id":"mixed_filter_greedy","entrypoint":"tools.solvers.mixed_recovery:MixedFilterGreedy","applicability":"tools.solvers.mixed_recovery:applicability","task":"exact_search","randomized":true,"families":["MIX_Q_SPARSE","MIX_SMALL_SPARSE","MIX_DENSE_SMALL"],"citations":["chi-cho-kim-lee-2026"]},
    {"id":"bounded_error","entrypoint":"tools.solvers.bounded_error:CleanSubsetRecovery","applicability":"tools.solvers.bounded_error:applicability","task":"exact_search","randomized":true,"families":["DS_BIN","DS_TER","DS_SMALL","DA_BIN","DA_TER","MIX_DENSE_SMALL"],"citations":["arora-ge-2011","steiner-2024"]}
  ]
}
```

- [ ] **Step 2: Write the failing coverage test**

```python
from pathlib import Path

from tools.solvers.registry import load_registry, load_sources


FAMILIES = {"DS_BIN", "DS_TER", "DS_SMALL", "SA_Q", "SA_SMALL", "DA_BIN", "DA_TER", "MIX_Q_SPARSE", "MIX_SMALL_SPARSE", "MIX_DENSE_SMALL"}


def test_registry_covers_every_approved_family_with_exact_search() -> None:
    registry = load_registry(Path("2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/registry.json"))
    covered = {family for solver in registry for family in solver.families if solver.task == "exact_search"}
    assert covered == FAMILIES
    assert all(solver.citations for solver in registry)
    sources = load_sources(Path("2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/sources.json"))
    assert {citation for solver in registry for citation in solver.citations} <= set(sources)
```

- [ ] **Step 3: Run the STATIC test and observe the expected import failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_solver_registry.py`

Expected: FAIL with `ModuleNotFoundError: No module named 'tools.solvers.registry'`.

- [ ] **Step 4: Implement strict registry loading**

```python
import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SolverRecord:
    solver_id: str
    entrypoint: str
    applicability: str
    task: str
    randomized: bool
    families: tuple[str, ...]
    citations: tuple[str, ...]


def load_registry(path: Path) -> tuple[SolverRecord, ...]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != 1:
        raise ValueError("unsupported solver registry schema")
    records = tuple(
        SolverRecord(
            item["id"], item["entrypoint"], item["applicability"],
            item["task"], bool(item["randomized"]),
            tuple(item["families"]), tuple(item["citations"]),
        )
        for item in raw["solvers"]
    )
    ids = [record.solver_id for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate solver id")
    if any(record.task != "exact_search" for record in records):
        raise ValueError("qualifying registry contains a non-search solver")
    return records
```

Validate both `module:object` fields syntactically in this slice. After Tasks
4–6 create the modules, Task 14 uses `importlib` to resolve them.
`instantiate_solver` then requires a `GatedExactSolver`, matching `solver_id`,
and a concrete `_solve`; the applicability function returns `(bool,
stable_reason, public_parameters)` without running recovery. `sources.json` is strict and
contains, for every citation ID, primary URL, exact section/theorem/algorithm
locator, search/decision/refutation classification, implementation mapping,
clean-room status, copied-code flag (always false here), and paper/software
license notes. Registry loading fails on an unresolved/non-search citation or
an entrypoint/applicability mismatch.

- [ ] **Step 5: Add owned synthetic solver fixtures and recovery markers**

Extend the Phase 2 task-local `conftest.py` with lazy fixtures generated only
through the Phase 2 synthetic generator: `binary_fixture`,
`repeated_support_fixture`, `graph_peeling_fixture`, `dense_minor_fixture`,
`mixed_fixture`, `sparse_error_fixture`, `primal_fixture`, `unique_fixture`,
and `multiple_witness_fixture`. Each uses the unmistakable synthetic domain,
tiny public parameters, and returns a public `lwe_instance.Instance`; no test
imports a hidden witness. Add lazy solver fixtures after their modules exist.

Register a `recovery` pytest marker. Before the fixed gate, collection marks
every recovery test skipped from a timezone-aware clock while the common
solver wrapper independently blocks direct calls. Add a registry test that
monkeypatches `api.require_solver_gate` to raise a sentinel, invokes every
instantiated solver on a non-solving dummy, and proves no concrete `_solve`
body was entered.

- [ ] **Step 6: Run the STATIC registry test**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_solver_registry.py`

Expected: registry/source/schema validation passes for every declared entry,
including `graph_peeling`; Task 14 later proves all declarations resolve.

- [ ] **Step 7: Commit the registry slice**

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/registry.json 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/registry.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/sources.json 2.0/problems/lwe_structured_recovery/tests/conftest.py 2.0/problems/lwe_structured_recovery/tests/test_solver_registry.py
git commit -m "feat(lwe): register clean-room recovery portfolio"
```

### Task 4: Implement sparse-secret exact recovery

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/sparse_secret.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_sparse_secret_solver.py`

- [ ] **Step 1: Write a GATED synthetic exact-weight recovery test**

```python
from pathlib import Path

from tools.solvers.api import SolveRequest, SolveStatus
from tools.solvers.sparse_secret import SparseSecretEnumerator


def test_enumerator_recovers_exact_weight_secret(binary_fixture) -> None:
    result = SparseSecretEnumerator().solve(binary_fixture, SolveRequest(7, 10.0, Path("build/lwe-test")))
    assert result.status is SolveStatus.SUCCESS
    assert binary_fixture.validate_secret(result.secret).ok
```

- [ ] **Step 2: After the gate, run the GATED test and observe the expected import failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_sparse_secret_solver.py`

Expected after 23:00 HKT: FAIL with `ModuleNotFoundError: No module named 'tools.solvers.sparse_secret'`. Before the gate: record `SKIPPED (execution gate)`.

- [ ] **Step 3: Implement lexicographic support/alphabet enumeration with early row rejection**

```python
from itertools import combinations, product
from time import monotonic

from .api import GatedExactSolver, SolveRequest, SolveResult, SolveStatus


class SparseSecretEnumerator(GatedExactSolver):
    solver_id = "sparse_secret_enum"

    def _solve(self, instance, request: SolveRequest) -> SolveResult:
        started = monotonic()
        if instance.secret_distribution_kind != "exact_weight_alphabet":
            return SolveResult(SolveStatus.ERROR, None, 0.0, 0, {"code": "not_exact_weight"})
        weight = int(instance.secret_weight)
        values = tuple(int(v) for v in instance.secret_alphabet if v != 0)
        tested = 0
        for support in combinations(range(instance.n), weight):
            for assignment in product(values, repeat=weight):
                if monotonic() - started >= request.max_seconds:
                    return SolveResult(SolveStatus.CENSORED, None, monotonic() - started, tested)
                candidate = [0] * instance.n
                for index, value in zip(support, assignment, strict=True):
                    candidate[index] = value
                tested += 1
                frozen = tuple(candidate)
                if request.exclude_secret == frozen:
                    continue
                if instance.validate_secret(frozen).ok:
                    return SolveResult.success(frozen, monotonic() - started, tested)
        return SolveResult(SolveStatus.EXHAUSTED, None, monotonic() - started, tested)
```

- [ ] **Step 4: Add a meet-in-the-middle class that indexes exact partial syndromes on a declared zero-error row subset**

Add gated `SparseSecretMitM` in the same file. It must not assume or receive
error locations. A per-instance analysis may select only public row indices
and a bucket width derived from the public residual bounds. Split support and
alphabet assignments into two halves, compute partial syndromes on those rows,
and index the left half in centered-residual buckets of width
`2*error_max_abs+1`. Probe every neighboring bucket consistent with all public
L-infinity/L1/L2/error-weight predicates, reconstruct complete secrets, and
call `instance.validate_secret(...).ok`. The implementation records collision
counts and memory. Return `EXHAUSTED` only after a finite exact traversal whose
checkpoint certificate records every support/assignment range; otherwise
return `CENSORED`.

- [ ] **Step 5: Run the GATED test after the gate**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_sparse_secret_solver.py`

Expected: PASS and the returned candidate passes `Instance.validate_secret`.

- [ ] **Step 6: Commit the sparse-secret slice**

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/sparse_secret.py 2.0/problems/lwe_structured_recovery/tests/test_sparse_secret_solver.py
git commit -m "feat(lwe): add sparse secret recovery solvers"
```

### Task 5: Implement sparse-matrix and mixed exact recovery

Every class in this task subclasses `GatedExactSolver` and implements only
`_solve`; direct recovery cannot bypass the common gate/progress/checkpoint
wrapper.

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/sparse_matrix.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/mixed_recovery.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_sparse_matrix_solver.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_mixed_and_error_solvers.py`

- [ ] **Step 1: Write GATED tests for repeated-support, dense-minor, and mixed filtering**

```python
from pathlib import Path

from tools.solvers.api import SolveRequest, SolveStatus
from tools.solvers.mixed_recovery import MixedFilterGreedy
from tools.solvers.sparse_matrix import (
    DenseMinorRecovery,
    GraphPeelingRecovery,
    RepeatedSupportRecovery,
)


def request() -> SolveRequest:
    return SolveRequest(11, 20.0, Path("build/lwe-test"))


def test_repeated_support_recovers(repeated_support_fixture) -> None:
    result = RepeatedSupportRecovery().solve(repeated_support_fixture, request())
    assert result.status is SolveStatus.SUCCESS
    assert repeated_support_fixture.validate_secret(result.secret).ok


def test_dense_minor_recovers(dense_minor_fixture) -> None:
    result = DenseMinorRecovery().solve(dense_minor_fixture, request())
    assert result.status is SolveStatus.SUCCESS
    assert dense_minor_fixture.validate_secret(result.secret).ok


def test_graph_peeling_recovers(graph_peeling_fixture) -> None:
    result = GraphPeelingRecovery().solve(graph_peeling_fixture, request())
    assert result.status is SolveStatus.SUCCESS
    assert graph_peeling_fixture.validate_secret(result.secret).ok


def test_mixed_filter_recovers(mixed_fixture) -> None:
    result = MixedFilterGreedy().solve(mixed_fixture, request())
    assert result.status is SolveStatus.SUCCESS
    assert mixed_fixture.validate_secret(result.secret).ok
```

- [ ] **Step 2: After the gate, run the GATED tests and observe missing-module failures**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_sparse_matrix_solver.py 2.0/problems/lwe_structured_recovery/tests/test_mixed_and_error_solvers.py`

Expected after 23:00 HKT: FAIL during import. Before the gate: record `SKIPPED (execution gate)`.

- [ ] **Step 3: Implement repeated-support recovery**

Group rows by `(support, coefficients)`, enumerate the (q^{|support|}) local assignments only when the declared local budget permits it, score centered residuals against the public predicate, merge consistent local assignments, and validate the completed vector. Conflicting assignments return `ERROR`; finite complete local enumeration with no witness returns `EXHAUSTED`.

- [ ] **Step 4: Implement graph-peeling recovery**

Build the public row/variable bipartite graph. For every current degree-one
row, enumerate only values allowed by the public secret predicate and retain
values whose centered residual is compatible with the public error predicate.
Intersect/vote across all leaves incident to a variable; commit only a unique
value, subtract it from neighboring public equations, and peel. When peeling
stalls, enumerate the explicitly bounded residual component or return
`CENSORED`; never guess a planted error location. Validate the complete vector
globally. Add exact success, ambiguous-leaf, contradiction, and stalled-graph
tests for `GraphPeelingRecovery`.

- [ ] **Step 5: Implement dense-minor recovery**

Use the seeded RNG to choose a coordinate subset of declared size `r`; select exactly the rows whose support is contained in that subset; require at least `r + 1` selected rows and full modular column rank; pass the induced instance to the registered local exact solver; merge recovered coordinates; repeat until all coordinates are assigned; validate globally before success.

The induced problem is a solver-internal immutable array view built from public
rows, public `b`, and adjusted residual bounds. It is not added to the Phase 2
facade and never claims that a restricted subproblem has the same error
distribution without deriving the adjusted predicate explicitly.

- [ ] **Step 6: Implement mixed row-filtering and greedy coordinate recovery**

Score each coordinate by the change in accepted residual count caused by each
allowed secret value, commit only a unique best value separated by the explicit
`request.parameters["greedy_margin"]`, rematerialize residuals after every
commitment, and fall back to bounded support enumeration for unresolved
coordinates. Never classify a decision-only correlation as success; call
`Instance.validate_secret` on the full vector and require `.ok`.

- [ ] **Step 7: Run the GATED sparse/mixed tests after the gate**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_sparse_matrix_solver.py 2.0/problems/lwe_structured_recovery/tests/test_mixed_and_error_solvers.py`

Expected: all repeated-support, graph-peeling, dense-minor, and mixed tests pass.

- [ ] **Step 8: Commit the sparse/mixed slice**

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/sparse_matrix.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/mixed_recovery.py 2.0/problems/lwe_structured_recovery/tests/test_sparse_matrix_solver.py 2.0/problems/lwe_structured_recovery/tests/test_mixed_and_error_solvers.py
git commit -m "feat(lwe): add sparse matrix and mixed recovery"
```

### Task 6: Add bounded-error and generic primal fallback solvers

Every class in this task subclasses `GatedExactSolver` and implements only
`_solve`; nested solvers are invoked through the registry dispatcher so gate,
progress, memory, and checkpoint rules remain active.

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/bounded_error.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/primal_bdd.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/small_secret_hybrid.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/requirements.lock`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/requirements.lock.json`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_primal_bdd.py`

- [ ] **Step 1: Pin solver-only dependencies**

```text
numpy==2.1.3
scipy==1.14.1
fpylll==0.6.4
cysignals==1.12.3
psutil==6.1.0
```

Add a static dependency-contract test that loads task `config.yaml` and
requires `runtime.pip_packages` to equal these five exact pins in canonical
order, while both judge package lists exclude them. Generate a lock metadata
file at `requirements.lock.json` with package hashes, source URLs,
Python/platform tags, and licenses; the
Phase 4 image build verifies installed versions and records the resulting
environment digest. The separate Sage/Lattice-Estimator container has its own
lock and is not conflated with this Harbor-agent lock.

- [ ] **Step 2: Write GATED tests for clean-subset and primal recovery**

```python
from pathlib import Path

from tools.solvers.api import SolveRequest, SolveStatus
from tools.solvers.bounded_error import CleanSubsetRecovery
from tools.solvers.primal_bdd import PrimalBDD


def test_clean_subset_recovers(sparse_error_fixture) -> None:
    result = CleanSubsetRecovery().solve(sparse_error_fixture, SolveRequest(3, 20.0, Path("build/lwe-test")))
    assert result.status is SolveStatus.SUCCESS
    assert sparse_error_fixture.validate_secret(result.secret).ok


def test_primal_bdd_recovers(primal_fixture) -> None:
    result = PrimalBDD().solve(primal_fixture, SolveRequest(5, 30.0, Path("build/lwe-test")))
    assert result.status is SolveStatus.SUCCESS
    assert primal_fixture.validate_secret(result.secret).ok
```

- [ ] **Step 3: After the gate, run the GATED tests and observe missing-module failures**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_primal_bdd.py`

Expected after 23:00 HKT: FAIL during import. Before the gate: record `SKIPPED (execution gate)`.

- [ ] **Step 4: Implement clean-subset recovery**

Sample `n` distinct rows with the request RNG, solve the square system modulo prime `q`, validate the candidate on all rows, and repeat until the time cap. Record every sampled subset as one work unit. Return `CENSORED`, not `EXHAUSTED`, when the randomized budget ends.

- [ ] **Step 5: Implement systematic Construction-A primal BDD**

Select `n` independent rows (A_0), compute (C=A_1A_0^{-1}\bmod q), build the square basis

```text
[ I_n      C^T ]
[  0   q I_(m-n) ]
```

in the corresponding row permutation, run single-thread BKZ followed by nearest-plane/CVP against the permuted `b`, recover `s=A_0^{-1}y_0 mod q`, convert to the public representatives, and validate. Composite-modulus or rank-deficient inputs return an explicit non-applicable error rather than an estimate masquerading as a solution.

- [ ] **Step 6: Implement small-secret hybrid as guessed coordinates plus PrimalBDD**

Enumerate the declared guessed coordinate block and values, subtract each contribution from `b`, invoke `PrimalBDD` on the remaining columns, merge, and validate. Count every outer guess and propagate censoring.

Construct the reduced matrix/vector as an internal array-backed problem and
route nested primal calls through the registered gated dispatcher. Do not
require a public subinstance constructor or expose planted information.

- [ ] **Step 7: Run the GATED tests after the gate**

Run: `OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 pytest -q 2.0/problems/lwe_structured_recovery/tests/test_primal_bdd.py`

Expected: `2 passed`; process inspection shows one worker.

- [ ] **Step 8: Commit the generic solver slice**

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/bounded_error.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/primal_bdd.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/small_secret_hybrid.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/requirements.lock 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/requirements.lock.json 2.0/problems/lwe_structured_recovery/tests/test_primal_bdd.py
git commit -m "feat(lwe): add bounded error and primal recovery"
```

### Task 7: Build attack-estimate schemas and applicability calculations

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/__init__.py`
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/estimate_types.py`
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/attack_estimates.py`
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/lattice_estimator.py`
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/docker/Dockerfile`
- Create: `2.0/problems/lwe_structured_recovery/calibration/lattice-estimator.lock.json`
- Create: `2.0/problems/lwe_structured_recovery/calibration/schemas/attack-estimate.schema.json`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_attack_estimates.py`

- [ ] **Step 1: Write the estimate schema**

Require `instance_id`, `solver_id`, `task` equal to `exact_search`, `applicable`, `work`, `memory_bytes`, `samples_required`, `source_ids`, `assumptions`, and `confidence`; disallow additional properties.

- [ ] **Step 2: Write failing STATIC formula tests**

```python
from math import comb

from analysis_tools.attack_estimates import dense_minor_rows, sparse_secret_candidates


def test_sparse_secret_candidate_count() -> None:
    assert sparse_secret_candidates(20, 3, 2) == comb(20, 3) * 8


def test_dense_minor_expected_rows() -> None:
    assert dense_minor_rows(n=10, m=90, k=2, r=5) == 20.0
```

- [ ] **Step 3: Run the STATIC tests and observe the expected import failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_attack_estimates.py`

Expected: FAIL with `ModuleNotFoundError: No module named 'analysis_tools.attack_estimates'`.

- [ ] **Step 4: Implement exact combinatorial formulas**

```python
from math import comb


def sparse_secret_candidates(n: int, weight: int, nonzero_alphabet: int) -> int:
    return comb(n, weight) * nonzero_alphabet**weight


def dense_minor_rows(n: int, m: int, k: int, r: int) -> float:
    if not 0 <= k <= r <= n:
        raise ValueError("require 0 <= k <= r <= n")
    return m * comb(r, k) / comb(n, k)


def algebraic_monomials(n: int, error_alphabet_size: int) -> int:
    return comb(n + error_alphabet_size, error_alphabet_size)
```

- [ ] **Step 5: Add `estimate_all(instance, registry)`**

Emit estimates for enumeration, MITM, hybrid, repeated support, dense minor, graph peeling, bounded error, mixed filtering, and calibrated generic primal. Mark unsupported attacks `applicable: false` with a concrete reason. Preserve decision/refutation leads in a separate `non_qualifying_leads` array that ladder code never reads.

- [ ] **Step 6: Pin and wrap the Lattice Estimator generic-search baseline**

Record the official upstream repository URL, immutable commit SHA, retrieval
date, license, and environment hash in `lattice-estimator.lock.json`; do not
copy code from the non-commercial Meta benchmarking repository. The wrapper
maps `(n,m,q)` and supported secret/error distributions into the pinned
Estimator API and retains only primal exact-recovery/BDD-style results as
qualifying generic upper bounds. Dual, distinguishing, and refutation outputs
go only to `non_qualifying_leads`.

For restricted or sparse public matrices, run the same parameters under the
ordinary dense-uniform `A` model when no justified interaction-specific
mapping exists, label it `normal_lwe_fallback`, and state that it is an
estimate rather than a reduction. Preserve the Estimator's operation count,
memory estimate, algorithm parameters, and raw versioned output; translate
operations to seconds only through the separately calibrated generic-primal
model. A missing/failed Estimator call is fail-closed for corpus admission, not
silently replaced by a guessed number.

Build a separate digest-pinned Sage analysis image from
`analysis_tools/docker/Dockerfile`. Install the locked official Estimator
commit, verify its checked-out commit and dependency hashes during the build,
and record all package licenses. Sage and the Estimator stay out of the Harbor
judge. The Harbor agent image instead receives the task config's
APT-installed NumPy/SciPy/fpylll/fplll/psutil stack. Phase 4 must build both
images, import every dependency, instantiate the complete registry, and record
the resulting version manifest before corpus admission.

Add fixture-driven tests for distribution mapping, commit-lock validation,
normal-LWE fallback on all mixed families, operation-count preservation,
decision-output exclusion, and raw-output schema. The tests may use recorded
tiny Estimator output; invoking the external Estimator itself waits until the
solver gate has opened.

- [ ] **Step 7: Run the STATIC tests**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_attack_estimates.py`

Expected: PASS, including JSON Schema validation of one applicable and one non-applicable estimate.

- [ ] **Step 8: Commit the estimator slice**

```bash
git add 2.0/problems/lwe_structured_recovery/analysis_tools 2.0/problems/lwe_structured_recovery/calibration/lattice-estimator.lock.json 2.0/problems/lwe_structured_recovery/calibration/schemas/attack-estimate.schema.json 2.0/problems/lwe_structured_recovery/tests/test_attack_estimates.py
git commit -m "feat(lwe): add exact attack estimators"
```

### Task 8: Implement reduction admission audits

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/reduction_audits.py`
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/reduction_assumptions.json`
- Create: `2.0/problems/lwe_structured_recovery/calibration/schemas/reduction-input.schema.json`
- Create: `2.0/problems/lwe_structured_recovery/calibration/schemas/reduction-audit.schema.json`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_reduction_audits.py`

- [ ] **Step 1: Add explicit assumption profiles**

```json
{
  "schema_version": 1,
  "entropy_slack_bits": 40,
  "negligible_bound_bits": 40,
  "base_profiles": {
    "ordinary_lwe_search_ceiling": {
      "source": "pinned-lattice-estimator-plus-primal-calibration",
      "max_core_hours": 1024,
      "required_status": "reviewed_upper_bound"
    }
  },
  "sources": {
    "BD20": "https://eprint.iacr.org/2020/119",
    "BBTV24": "https://arxiv.org/abs/2411.12512",
    "BLMR13": "https://crypto.stanford.edu/~dabo/papers/homprf.pdf",
    "MIC18": "https://theoryofcomputing.org/articles/v014a013/",
    "GVV22": "https://arxiv.org/abs/2204.02550"
  }
}
```

Define a strict per-candidate reduction-input record rather than reading
unstated values from `Instance`. It contains the instance digest; theorem ID;
all theorem variables with units; exact/at-most distribution flags; selected
ordinary-LWE base profile and dimension; base `q,m,alpha`/noise convention;
`gamma`, `sigma1`, mapped/final noise; sample transformation; security slack;
factorization/unit assumptions; and source locator. Each field is either a
finite number/explicit enum or `unknown`; `unknown` can never pass admission.
The record is separately reviewed and later bound by the per-instance release
manifest.

- [ ] **Step 2: Write failing STATIC entropy and applicability tests**

```python
from math import comb, log2

from analysis_tools.reduction_audits import exact_weight_entropy, is_mixed_family


def test_exact_weight_entropy_bits() -> None:
    assert exact_weight_entropy(32, 4, 2) == log2(comb(32, 4)) + 4


def test_mixed_families_are_first_class_but_reductions_do_not_auto_compose() -> None:
    assert is_mixed_family("MIX_Q_SPARSE")
    assert is_mixed_family("MIX_SMALL_SPARSE")
    assert is_mixed_family("MIX_DENSE_SMALL")
```

- [ ] **Step 3: Run the STATIC test and observe the expected import failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_reduction_audits.py`

Expected: FAIL with `ModuleNotFoundError: No module named 'analysis_tools.reduction_audits'`.

- [ ] **Step 4: Implement exact entropy and radius calculations**

```python
from math import comb, log2, sqrt


MIXED = {"MIX_Q_SPARSE", "MIX_SMALL_SPARSE", "MIX_DENSE_SMALL"}


def exact_weight_entropy(n: int, weight: int, nonzero_alphabet: int) -> float:
    return log2(comb(n, weight)) + weight * log2(nonzero_alphabet)


def exact_weight_radius(weight: int, max_abs_value: int) -> float:
    return sqrt(weight) * max_abs_value


def is_mixed_family(family: str) -> bool:
    return family in MIXED
```

- [ ] **Step 5: Implement theorem-specific audit records**

For secret-only records compute the Brakerski-Döttling general and ball-bounded
sufficient-hardness margins using the per-instance selected base dimension,
`gamma`, `sigma1`, final noise, sample count, and 40-bit slack. Also apply the
Micciancio binary-secret and Gupte-Vafa-Vaikuntanathan sparse-ternary mappings
whenever their exact hypotheses match. For `SA_Q` and `SA_SMALL`, record
exact/at-most support, support uniformity, coefficient-unit status, secret
uniformity, modulus/noise hypotheses, sample preservation, `(k/sqrt(n))`,
mapped dense dimension, and every BBT-V parameter relation. For `DA_BIN`,
record `ceil(log2(q))`, target dimension expansion, and
`n_base*(2^ceil(log2(q))-q)/q` against the 40-bit negligible bound. A
single-structure candidate receives `rejects_candidate` whenever any checked
reduction maps it to an assumed-hard ordinary-LWE regime; a merely applicable
reduction is not treated as a harmless diagnostic. Mixed families retain all
single-structure records but set `known_composition: false`; do not compose
them, label the family experimental, or remove it from admission.

- [ ] **Step 6: Make admission fail closed**

Use statuses `passes_gate`, `rejects_candidate`, and `requires_human_review`. Unknown theorem inputs and asymptotic-only judgments produce `requires_human_review`, never `passes_gate`. Emit numeric margins and source IDs in every result.

- [ ] **Step 7: Run the STATIC tests**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_reduction_audits.py`

Expected: PASS for theorem-specific golden calculations, missing-input
fail-closed behavior, one secret-only rejection, one matrix-only rejection,
one BLMR rejection/pass-boundary pair, and all three mixed families retained
with non-composition diagnostics.

- [ ] **Step 8: Commit the reduction-audit slice**

```bash
git add 2.0/problems/lwe_structured_recovery/analysis_tools/reduction_audits.py 2.0/problems/lwe_structured_recovery/analysis_tools/reduction_assumptions.json 2.0/problems/lwe_structured_recovery/calibration/schemas/reduction-input.schema.json 2.0/problems/lwe_structured_recovery/calibration/schemas/reduction-audit.schema.json 2.0/problems/lwe_structured_recovery/tests/test_reduction_audits.py
git commit -m "feat(lwe): add reduction admission audits"
```

### Task 9: Add rank, kernel, and alternative-witness checks

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/uniqueness.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_uniqueness.py`

- [ ] **Step 1: Write failing STATIC rank tests and a GATED second-witness test**

```python
from analysis_tools.uniqueness import (
    UniquenessStatus,
    assess_uniqueness,
    kernel_profile_mod_composite,
    rank_mod_prime,
)


def test_rank_mod_prime() -> None:
    assert rank_mod_prime([[1, 2], [2, 4], [0, 1]], 5) == 2


def test_composite_kernel_profile_matches_exhaustive_toy() -> None:
    profile = kernel_profile_mod_composite([[2, 0], [0, 3]], 6, {2: 1, 3: 1})
    assert profile.kernel_cardinality == 6


def test_exhaustive_domain_can_prove_unique(unique_fixture, sparse_secret_solver) -> None:
    result = assess_uniqueness(unique_fixture, sparse_secret_solver)
    assert result.status is UniquenessStatus.PROVEN_UNIQUE
    assert result.accepted_count == 1
```

- [ ] **Step 2: Run only the STATIC rank test and observe the expected import failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_uniqueness.py -k rank_mod_prime`

Expected: FAIL during import.

- [ ] **Step 3: Implement modular Gaussian elimination**

Normalize pivots with `pow(pivot, -1, q)`, eliminate every other row modulo
prime `q`, and return the pivot count. For a deliberately selected composite
`q`, require its reviewed prime-power factorization and compute an integer
Smith normal form of the public matrix with an independent implementation
cross-check. Record every invariant factor, rank modulo each prime factor, and
the exact kernel cardinality over `Z_q` (`q^(n-r)` times the product of
`gcd(d_i,q)` for nonzero Smith factors). Never reuse field-rank terminology
for a composite ring. Tests cover prime powers, square-free composites,
non-unit pivots, CRT consistency, and agreement with exhaustive tiny kernels;
unknown/incomplete factorization blocks admission.

- [ ] **Step 4: Implement the public-safe uniqueness result**

```python
from dataclasses import dataclass
from enum import StrEnum


class UniquenessStatus(StrEnum):
    PROVEN_UNIQUE = "proven_unique"
    KNOWN_MULTIPLE = "known_multiple"
    NO_SECOND_WITNESS_FOUND = "no_second_witness_found"


@dataclass(frozen=True)
class UniquenessResult:
    status: UniquenessStatus
    accepted_count: int | None
    search_complete: bool
    rank: int
    kernel_dimension: int
    method: str
    domain_digest: str
    exhaustive_certificate_digest: str | None
```

- [ ] **Step 5: Implement exhaustive and bounded alternative search**

Implement `assess_uniqueness(instance, exhaustive_solver)` as a dedicated API.
It dispatches the finite-domain solver once to obtain an accepted first witness
and again with `exclude_secret`, but accepts `EXHAUSTED` as a proof only when
the solver emits an auditable domain certificate: canonical domain digest,
candidate count, disjoint completed ranges, checkpoint chain, and no censored
range. Report `PROVEN_UNIQUE` only for a complete certificate,
`KNOWN_MULTIPLE` on a second accepted witness, and otherwise
`NO_SECOND_WITNESS_FOUND`. A separate generation-boundary entrypoint may take
the planted witness through the private pipe to avoid solving for the first
witness on hard cases; it emits only the same scrubbed status/certificate
metadata. Never serialize either witness.

- [ ] **Step 6: Run the STATIC rank test**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_uniqueness.py -k rank_mod_prime`

Expected: PASS.

- [ ] **Step 7: After the gate, run the GATED uniqueness test**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_uniqueness.py`

Expected: all tests pass; before the gate record the recovery test as skipped.

- [ ] **Step 8: Commit the uniqueness slice**

```bash
git add 2.0/problems/lwe_structured_recovery/analysis_tools/uniqueness.py 2.0/problems/lwe_structured_recovery/tests/test_uniqueness.py
git commit -m "feat(lwe): audit rank and alternative witnesses"
```

### Task 10: Build calibration run capture and witness scrubbing

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/calibration_types.py`
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/calibration_runner.py`
- Create: `2.0/problems/lwe_structured_recovery/calibration/schemas/calibration-run.schema.json`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_calibration_runner.py`

- [ ] **Step 1: Define the scrubbed run schema**

Require `run_id`, `instance_id`, `instance_digest`, `solver_id`,
`solver_revision`, `solver_seed`, `started_at_hkt`, `wall_seconds`,
`cpu_seconds`, `peak_rss_bytes`, `worker_count` equal to 1, `status`,
`output_sha256`, `output_disposition` equal to
`deleted_after_validation`, `command`, `environment`, and `cold_run`; forbid
`secret`, `witness`, and seed fields for production generation. The environment
record includes machine/CPU/OS/compiler/tool versions, AC-power and low-power
mode, thermal-pressure state before/after, process QoS, native thread count,
BLAS/OpenMP variables, timing clocks, and cold-process/cache policy.

- [ ] **Step 2: Write failing STATIC tests using a non-solver child command**

```python
from pathlib import Path

from analysis_tools.calibration_runner import scrub_command


def test_scrub_command_removes_private_output_path() -> None:
    command = ["python", "solver.py", "--private-output", "/tmp/witness.json", "--seed", "9"]
    assert scrub_command(command) == ["python", "solver.py", "--private-output", "[redacted]", "--seed", "9"]


def test_log_text_never_contains_secret_key(tmp_path: Path) -> None:
    path = tmp_path / "run.json"
    path.write_text('{"status":"success"}', encoding="utf-8")
    assert '"secret"' not in path.read_text(encoding="utf-8")
```

- [ ] **Step 3: Run the STATIC tests and observe the expected import failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_calibration_runner.py`

Expected: FAIL with `ModuleNotFoundError: No module named 'analysis_tools.calibration_runner'`.

- [ ] **Step 4: Implement `scrub_command` and atomic JSON writes**

Replace only the value following `--private-output`; preserve the solver seed for reproducibility. Write to a sibling `.tmp`, call `flush()` and `os.fsync()`, then `os.replace()`.

- [ ] **Step 5: Implement the gated single-worker runner**

Call `require_solver_gate()` before process creation; set `OMP_NUM_THREADS=1`, `OPENBLAS_NUM_THREADS=1`, `MKL_NUM_THREADS=1`, `VECLIB_MAXIMUM_THREADS=1`, and `NUMEXPR_NUM_THREADS=1`; sample child RSS with psutil; include parsing, preprocessing, checkpoint I/O, and validation in wall time; hash canonical solver output only after `Instance.validate_secret` succeeds; delete plaintext output in a `finally` block; serialize only the schema-approved run record.

On the Apple M5 reference host, launch the worker through a tiny native harness
that requests `QOS_CLASS_USER_INTERACTIVE`, records the effective QoS, and
keeps exactly one computational thread. macOS offers no hard public P-core
affinity guarantee, so do not claim one: record scheduler/core-class telemetry
available on the host, reject background/E-core-class or thermal-pressure
runs, and publish this limitation. Require AC power, low-power mode off, a
fixed warm-up policy, a fresh process per cold run, and rerun a set whose QoS,
thermal state, tool revision, or thread telemetry differs.

- [ ] **Step 6: Add cold-run and randomized-run orchestration**

Require three cold runs for deterministic solvers and ten independent seeds for randomized solvers. Preserve censored failures. Reject a run set whose environment or solver revision differs within the set.

- [ ] **Step 7: Run the STATIC scrubber tests**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_calibration_runner.py -k 'scrub_command or log_text'`

Expected: PASS without starting a solver.

- [ ] **Step 8: After the gate, run one GATED synthetic calibration smoke**

Run: `python 2.0/problems/lwe_structured_recovery/analysis_tools/calibration_runner.py --catalog 2.0/problems/lwe_structured_recovery/catalog.synthetic.json --instance toy-uniform --solver sparse_secret_enum --runs 3 --threads 1 --output build/lwe-calibration`

Expected: three schema-valid scrubbed records, accepted output hashes, deleted private outputs, and the first permitted timestamp recorded per the master plan.

- [ ] **Step 9: Commit the calibration-runner slice**

```bash
git add 2.0/problems/lwe_structured_recovery/analysis_tools/calibration_types.py 2.0/problems/lwe_structured_recovery/analysis_tools/calibration_runner.py 2.0/problems/lwe_structured_recovery/calibration/schemas/calibration-run.schema.json 2.0/problems/lwe_structured_recovery/tests/test_calibration_runner.py
git commit -m "feat(lwe): capture scrubbed single-core calibrations"
```

### Task 11: Fit runtime models and minimum-over-attacks predictions

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/runtime_model.py`
- Create: `2.0/problems/lwe_structured_recovery/calibration/schemas/runtime-model.schema.json`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_runtime_model.py`

- [ ] **Step 1: Write failing STATIC model tests**

```python
from analysis_tools.runtime_model import fit_log_linear, joint_minimum_prediction


def test_fit_log_linear_recovers_scaling() -> None:
    model = fit_log_linear([1.0, 2.0, 4.0], [2.0, 8.0, 32.0], [False, False, False])
    assert abs(model.slope - 2.0) < 1e-8


def test_minimum_uses_only_exact_applicable_attacks() -> None:
    predictions = [
        {"solver_id":"primal_bdd","task":"exact_search","applicable":True,"draws":[9.0,10.0,11.0]},
        {"solver_id":"spectral","task":"decision","applicable":True,"draws":[1.0,1.0,1.0]},
        {"solver_id":"dense_minor","task":"exact_search","applicable":True,"draws":[4.0,5.0,6.0]}
    ]
    summary = joint_minimum_prediction(predictions)
    assert summary["primary_solver_id"] == "dense_minor"
    assert summary["minimum_draws"] == [4.0, 5.0, 6.0]
```

- [ ] **Step 2: Run the STATIC tests and observe the expected import failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_runtime_model.py`

Expected: FAIL during import.

- [ ] **Step 3: Implement robust log-work/log-time fitting**

Fit `log2(seconds)=intercept+slope*log2(work)` with a robust survival-aware
likelihood (Huberized residuals for observed runs and right-censor likelihood
terms for censored runs), rather than substituting censor limits as observed
times. Store training run IDs, regime key, anchor range/count, residual median
absolute deviation, held-out log-error quantiles, calibration coverage, and
maximum extrapolation ratio. Golden tests cover exact scaling and synthetic
right-censored recovery.

- [ ] **Step 4: Implement deterministic and randomized summaries**

Deterministic summaries expose min/median/max of three cold runs. Randomized
summaries use Kaplan-Meier/right-censored survival estimates for `T50` and
`T90` plus a fixed-seed bootstrap 90% interval over ten or more runs. If the
survival curve never crosses a requested percentile, report that percentile
as a lower bound/undefined and reject easy-bin admission; never treat a censor
limit as a completed runtime.

- [ ] **Step 5: Implement fastest credible exact-attack selection**

Filter to `task == "exact_search"`, `applicable is True`, memory at most
16 GiB, and a model whose regime key matches without crossing a phase
transition. For each instance, propagate fitted-parameter, run-to-run, and
randomized-success draws through all attacks and compute the distribution of
the minimum exact-recovery time. Use paired/shared calibration draws when
available; otherwise publish both independence and worst-correlation
sensitivity bounds and use the conservative bound for admission. The selected
primary attack is the one most often attaining that simulated minimum, not
merely the smallest individual median. Publish every alternative and its
exclusion reason; decision/refutation records never enter the draw set.

- [ ] **Step 6: Run the STATIC model tests**

Before a model is eligible for a hard slot, require within the exact regime:
at least six anchors (at least four uncensored), at least two held-out points,
an observed work span of at least 8x, held-out median absolute log2 error at
most 1 bit, held-out 90th-percentile absolute error at most 2 bits, no detected
phase transition, extrapolation no farther than 256x beyond the observed work
range, and a predicted 90% interval with multiplicative width at most 32x.
Interpolation must remain inside the observed work range. Failing any limit is
`requires_more_calibration`, not a waivable warning. Add one boundary test per
predicate.

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_runtime_model.py`

Expected: PASS for exact scaling, censor handling, bootstrap reproducibility, and decision-attack exclusion.

- [ ] **Step 7: Commit the runtime-model slice**

```bash
git add 2.0/problems/lwe_structured_recovery/analysis_tools/runtime_model.py 2.0/problems/lwe_structured_recovery/calibration/schemas/runtime-model.schema.json 2.0/problems/lwe_structured_recovery/tests/test_runtime_model.py
git commit -m "feat(lwe): fit calibrated runtime models"
```

### Task 12: Assign and verify the 60/140 logarithmic ladders

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/ladder.py`
- Create: `2.0/problems/lwe_structured_recovery/calibration/schemas/ladder.schema.json`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_ladder.py`

- [ ] **Step 1: Write failing STATIC balance tests**

```python
from collections import Counter

from analysis_tools.ladder import FAMILY_CODES, hard_octave, hard_target_hours


def test_approved_family_set_is_exact() -> None:
    assert FAMILY_CODES == ("DS_BIN", "DS_TER", "DS_SMALL", "SA_Q", "SA_SMALL", "DA_BIN", "DA_TER", "MIX_Q_SPARSE", "MIX_SMALL_SPARSE", "MIX_DENSE_SMALL")


def test_cyclic_hard_assignment_has_fourteen_per_family_and_octave() -> None:
    placements = [(family, hard_octave(family_index, local_index)) for family_index, family in enumerate(FAMILY_CODES) for local_index in range(14)]
    assert Counter(family for family, _ in placements) == {family: 14 for family in FAMILY_CODES}
    assert Counter(octave for _, octave in placements) == {octave: 14 for octave in range(10)}


def test_hard_targets_are_inside_octave() -> None:
    assert all(2**k <= hard_target_hours(k, j) < 2**(k + 1) for k in range(10) for j in range(14))
```

- [ ] **Step 2: Run the STATIC tests and observe the expected import failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_ladder.py`

Expected: FAIL during import.

- [ ] **Step 3: Implement the exact approved formulas**

```python
FAMILY_CODES = ("DS_BIN", "DS_TER", "DS_SMALL", "SA_Q", "SA_SMALL", "DA_BIN", "DA_TER", "MIX_Q_SPARSE", "MIX_SMALL_SPARSE", "MIX_DENSE_SMALL")
EASY_BOUNDS_SECONDS = ((1, 4), (4, 16), (16, 64), (64, 256), (256, 1024), (1024, 3600))


def hard_octave(family_index: int, local_index: int) -> int:
    if not 0 <= family_index < 10 or not 0 <= local_index < 14:
        raise ValueError("hard assignment index out of range")
    return (family_index + local_index) % 10


def hard_target_hours(octave: int, position: int) -> float:
    return 2 ** (octave + (position + 0.5) / 14)


def easy_target_seconds(family_index: int, easy_bin: int) -> float:
    low, high = EASY_BOUNDS_SECONDS[easy_bin]
    fraction = ((family_index + easy_bin) % 10 + 0.5) / 10
    return low * (high / low) ** fraction
```

- [ ] **Step 4: Implement easy admission**

Require exactly one instance per family in each `E0` through `E5`. Deterministic attacks need three cold successful runs all inside the bin. Randomized attacks need at least ten seeds, `T50` inside the bin, and empirical `T90 < 3600`. Every easy record needs a paper citation and accepted exact witness attestation.

- [ ] **Step 5: Implement hard admission**

Require exactly fourteen modeled cases per family and exactly fourteen cases
per `H0` through `H9`. Assign octaves with `hard_octave`; require the
censor-aware conservative joint-minimum median in `[2^k,2^(k+1))` hours and
all Task 11 anchor/holdout/extrapolation/interval gates. Retain the full joint
distribution, sensitivity bounds, interval, confidence, interpolation class,
model ID, and all alternative exact attacks. Do not alter score by difficulty.

- [ ] **Step 6: Add fail-closed corpus diagnostics**

Reject any set that is not exactly 200 records, 20 per family, 60 measured and 140 modeled, ten per easy bin, fourteen per hard octave, or that includes a family outside `FAMILY_CODES`.

- [ ] **Step 7: Run the STATIC ladder tests**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_ladder.py`

Expected: PASS for exact counts, targets, easy admission, hard admission, and malformed-corpus rejection.

- [ ] **Step 8: Commit the ladder slice**

```bash
git add 2.0/problems/lwe_structured_recovery/analysis_tools/ladder.py 2.0/problems/lwe_structured_recovery/calibration/schemas/ladder.schema.json 2.0/problems/lwe_structured_recovery/tests/test_ladder.py
git commit -m "feat(lwe): assign balanced runtime ladders"
```

### Task 13: Add release-time witness and seed leak audits

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/analysis_tools/leak_audit.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_leak_audit.py`

- [ ] **Step 1: Write failing STATIC leak tests**

```python
from pathlib import Path

from analysis_tools.leak_audit import audit_release_tree


def test_rejects_secret_seed(tmp_path: Path) -> None:
    (tmp_path / "bad.json").write_text('{"secret_seed":"abcd"}', encoding="utf-8")
    assert audit_release_tree(tmp_path) == ["bad.json: forbidden key secret_seed"]


def test_allows_submission_schema_source(tmp_path: Path) -> None:
    (tmp_path / "readme").write_text('{"solutions":[{"instance_id":"lwe_0001","secret":[0]}]}', encoding="utf-8")
    assert audit_release_tree(tmp_path) == []
```

- [ ] **Step 2: Run the STATIC tests and observe the expected import failure**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_leak_audit.py`

Expected: FAIL during import.

- [ ] **Step 3: Implement structural JSON/JSONL inspection**

Inspect the production catalog, scrubbed generation receipts, calibration
summaries, scrubbed logs, models, and review records. Reject keys
`secret_seed`, `error_seed`, `private_seed_sha256`, `secret_sha256`,
`error_sha256`, `planted_secret`, `planted_error`, `private_entropy`, `answer`,
and `witness`. The catalog's public `secret` predicate and `error` predicate
are required and explicitly allowed; reject only keys/values that contain a
planted or submitted vector. In non-catalog JSON, allow `secret` solely in
documentation, tests, solver source, and submission examples.

- [ ] **Step 4: Add file and Git-index checks**

Reject filenames matching `solution*.json`, `witness*`, `secret*`, or
`*.private.json` under the production task except the two documented canonical
empty ledgers: task-root `reference.json` and
`harbor/app/solution.json`. Parse both strictly and require exactly
`{"schema_version":1,"solutions":[]}`; no other exception is allowed. Verify
that no private generation attestation exists on disk
and every calibration private-output path is absent. Scan tracked production
data for private-value keys and unexpected 64-hex fields; allow only the
schema-enumerated public digests, seeds, commits, and scoped output hashes.

- [ ] **Step 5: Add canonical output-hash policy**

Allow `output_sha256` only in scrubbed calibration logs with `output_disposition == "deleted_after_validation"`. Reject an output hash in catalog records, analyses, review files, models, and generation receipts.

- [ ] **Step 6: Run the STATIC leak tests**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_leak_audit.py`

Expected: PASS for forbidden JSON keys, forbidden files, allowed documentation examples, and calibration-hash scoping.

- [ ] **Step 7: Commit the leak-audit slice**

```bash
git add 2.0/problems/lwe_structured_recovery/analysis_tools/leak_audit.py 2.0/problems/lwe_structured_recovery/tests/test_leak_audit.py
git commit -m "security(lwe): audit release artifacts for witnesses"
```

### Task 14: Add the gated solver CLI and run the Phase 3 verification matrix

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/cli.py`
- Modify: `2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/__init__.py`

- [ ] **Step 1: Implement CLI argument parsing without starting a solver**

Support concrete arguments `--catalog`, `--instance`, `--solver`, `--seed`,
`--max-seconds`, `--work-dir`, mutually exclusive `--private-output` or
`--ledger`, and `--threads`. Require `--threads 1`; load through
`Catalog.load`; resolve the registered exact solver; call the common gated
`solve`; validate success; atomically write the candidate only to
`--private-output` for the calibration runner or merge it through the Phase 2
ledger helper in agent mode. In ledger mode, print the updated solved count and
the exact immediate-submit reminder without printing the secret.

- [ ] **Step 2: Verify the pre-gate failure path without invoking the CLI**

Before 23:00 HKT, exercise only the injected-clock unit test from Task 1 and
assert the exact message
`solver execution is disabled until 2026-07-10T23:00:00+08:00`. Do not invoke
the solver CLI at all before the user's gate. After the gate, do not falsify
the clock to recreate an early path.

- [ ] **Step 3: Run all STATIC Phase 3 tests**

First extend `test_solver_registry.py` now that Tasks 4–6 exist: resolve and
instantiate every entrypoint and applicability function, require
`GatedExactSolver`, matching IDs, concrete `_solve`, no `solve` override, one
synthetic fixture mapping, and a nonempty stable applicability reason for both
applicable and inapplicable fixtures. This imports code but does not execute a
recovery.

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_execution_gate.py 2.0/problems/lwe_structured_recovery/tests/test_solver_api.py 2.0/problems/lwe_structured_recovery/tests/test_solver_registry.py 2.0/problems/lwe_structured_recovery/tests/test_attack_estimates.py 2.0/problems/lwe_structured_recovery/tests/test_reduction_audits.py 2.0/problems/lwe_structured_recovery/tests/test_runtime_model.py 2.0/problems/lwe_structured_recovery/tests/test_ladder.py 2.0/problems/lwe_structured_recovery/tests/test_leak_audit.py`

Expected: all STATIC tests pass and no recovery solver starts.

- [ ] **Step 4: Cross the gate using the master-plan procedure**

Run: `date '+%Y-%m-%dT%H:%M:%S%z'`

Expected: no earlier than `2026-07-10T23:00:00+0800`. Create `2.0/problems/lwe_structured_recovery/calibration/FIRST_SOLVER_RUN.md` with that observed timestamp, machine identifier, branch revision, and first gated command before executing it.

- [ ] **Step 5: Run all GATED synthetic recovery tests**

Run: `OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 VECLIB_MAXIMUM_THREADS=1 pytest -q 2.0/problems/lwe_structured_recovery/tests/test_sparse_secret_solver.py 2.0/problems/lwe_structured_recovery/tests/test_sparse_matrix_solver.py 2.0/problems/lwe_structured_recovery/tests/test_mixed_and_error_solvers.py 2.0/problems/lwe_structured_recovery/tests/test_primal_bdd.py 2.0/problems/lwe_structured_recovery/tests/test_uniqueness.py 2.0/problems/lwe_structured_recovery/tests/test_calibration_runner.py`

Expected: all tests pass; every recovered synthetic candidate is accepted through `Instance.validate_secret`; calibration plaintext outputs are deleted.

- [ ] **Step 6: Run the complete Phase 3 suite and leak audit**

Run: `pytest -q 2.0/problems/lwe_structured_recovery/tests/test_execution_gate.py 2.0/problems/lwe_structured_recovery/tests/test_solver_api.py 2.0/problems/lwe_structured_recovery/tests/test_solver_registry.py 2.0/problems/lwe_structured_recovery/tests/test_sparse_secret_solver.py 2.0/problems/lwe_structured_recovery/tests/test_sparse_matrix_solver.py 2.0/problems/lwe_structured_recovery/tests/test_mixed_and_error_solvers.py 2.0/problems/lwe_structured_recovery/tests/test_primal_bdd.py 2.0/problems/lwe_structured_recovery/tests/test_attack_estimates.py 2.0/problems/lwe_structured_recovery/tests/test_reduction_audits.py 2.0/problems/lwe_structured_recovery/tests/test_uniqueness.py 2.0/problems/lwe_structured_recovery/tests/test_calibration_runner.py 2.0/problems/lwe_structured_recovery/tests/test_runtime_model.py 2.0/problems/lwe_structured_recovery/tests/test_ladder.py 2.0/problems/lwe_structured_recovery/tests/test_leak_audit.py`

Expected: all Phase 3 tests pass.

Run: `python 2.0/problems/lwe_structured_recovery/analysis_tools/leak_audit.py --root 2.0/problems/lwe_structured_recovery`

Expected: `release leak audit: clean`.

- [ ] **Step 7: Run the required self-review checks**

Confirm every spec requirement in this phase maps to a task; search this plan
and implementation for `TBD`, `TODO`, `NotImplementedError`, and unresolved
bracket markers; compare type names across solver, estimator, audit, model, and
ladder modules; verify mixed families are never removed or labeled
experimental; verify decision/refutation records cannot enter
`joint_minimum_prediction`.

- [ ] **Step 8: Commit the CLI and verified Phase 3 state**

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/cli.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/solvers/__init__.py 2.0/problems/lwe_structured_recovery/calibration/FIRST_SOLVER_RUN.md
git commit -m "feat(lwe): complete solver calibration machinery"
```

## Phase 3 completion evidence

Before handing off to Phase 4, record:

- the exact passing STATIC and GATED commands;
- the first permitted solver timestamp and revision;
- solver registry coverage for all ten approved families;
- one accepted synthetic recovery per solver class;
- schema-validation results for estimates, audits, runs, models, and ladder records;
- a secret-only reduction rejection, a matrix-only reduction rejection, a BLMR diagnostic, and mixed-family non-composition diagnostics;
- rank and alternative-witness outcomes for synthetic unique and multiple-witness fixtures;
- deterministic and randomized calibration summaries with censoring retained;
- exact 60/140 and per-bin balance on a synthetic 200-record assignment; and
- a clean release leak audit.

Phase 4 may then populate production specifications, public instances, scrubbed runs, models, 200 authored analyses, and 400 independent reviews using these interfaces.
