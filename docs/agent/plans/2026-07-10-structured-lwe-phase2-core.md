# Structured LWE Phase 2 Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the data-only, secretless core of the `lwe_structured_recovery` Frontier-CS 2.0 task: strict public instance schemas, deterministic SHAKE matrix generation, exact witness verification, duplicate-safe cumulative submissions, synthetic fixtures, and the FCS evaluator facade.

**Architecture:** The stable solver-facing API is the single module `harbor/app/public/lwe_instance.py`; it delegates to small modules under `harbor/app/public/lwe_challenge/`. The evaluator parses an untrusted JSON ledger, reconstructs public matrices from committed SHAKE seeds, and accepts any secret satisfying the published secret and residual predicates; it never loads or compares a planted secret. Production instances and long-running attacks are outside this phase; all tests use tiny synthetic instances.

**Tech Stack:** Python 3.11 standard library (`dataclasses`, `hashlib`, `json`, `pathlib`, `secrets`), pytest, Bash, a standalone C11/FIPS-202 matrix oracle, the final task's apt-installed NumPy/SciPy/fpylll/fplll solver dependencies, and the Frontier-CS 2.0 evaluator tuple contract. The Phase 2 evaluator and judge path themselves remain standard-library-only.

---

## Execution gate

Do not start a reference attack, recovery solver, calibration run, or
production-instance solution attempt before **2026-07-10 23:00 HKT
(Asia/Hong_Kong)**. Code authoring, compilation, schema tests, public matrix
materialization, synthetic generation, evaluator tests, and ledger tests may
run before the gate because they do not attempt recovery. This phase contains
no cryptanalytic solver.

## File map and dependency direction

```text
2.0/problems/lwe_structured_recovery/
  config.yaml                         FCS resource/submission metadata
  readme                              agent-facing task and ledger contract
  evaluate.sh                         local Frontier-CS wrapper
  evaluator.py                        FCS prepare()/evaluate() facade only
  reference.json                      empty valid cumulative ledger
  catalog.synthetic.json              tiny public smoke catalog only
  harbor/app/
    solution.json                     editable cumulative ledger starter
    add_solution.py                   thin ledger CLI
    public/
      lwe_instance.py                 stable Phase-3 solver facade
      lwe_challenge/
        __init__.py
        strict_json.py                bounded duplicate-key-safe JSON decoding
        schema.py                     immutable schema objects and catalog loading
        shake.py                      deterministic domain-separated byte stream
        matrix.py                     row iteration, materialization, modular matvec
        verification.py               secret/error predicates and witness verdicts
        submission.py                 untrusted ledger parsing and duplicate policy
        evaluator_core.py             equal-count scoring over verified witnesses
        ledger.py                     canonical cumulative ledger read/merge/write
        generator.py                  synthetic/production in-memory generation core
    tools/audit/
      matrix_ref.c                    independent C11 SHAKE/matrix oracle
  tests/
    conftest.py
    fixtures/
      catalog_two_instances.json
      submission_one_valid.json
    test_strict_json.py
    test_schema.py
    test_shake_matrix.py
    test_verification.py
    test_submission.py
    test_evaluator_core.py
    test_ledger.py
    test_generator.py
    test_public_facade.py
    test_fcs_wrapper.py
tests/test_lwe_structured_recovery_registration.py  root-level discovery/config regression
```

Dependency order is strict and acyclic:

```text
strict_json -> schema
shake + schema -> matrix
schema + matrix -> verification
strict_json + schema -> submission
schema + submission + verification -> evaluator_core
strict_json + submission -> ledger
schema + matrix + verification -> generator
all public modules -> lwe_instance facade -> evaluator.py / add_solution.py
```

No Phase-3 solver may import `lwe_challenge.*`; it must import only `lwe_instance.py`.

## Fixed public contracts

```python
# harbor/app/public/lwe_instance.py
class Catalog:
    catalog_id: str
    @property
    def instances(self) -> tuple["Instance", ...]:
        return self._instances

class Instance:
    instance_id: str
    n: int
    m: int
    q: int
    b: tuple[int, ...]
    family: str
    tier: str
    cohort: str
    runtime_bin: str
    octave: int | None
    matrix_kind: str
    matrix_seed_hex: str
    matrix_expansion_domain: str
    matrix_alphabet: tuple[int, ...]
    matrix_row_weight: int | None
    secret_distribution_kind: str
    secret_predicate_kind: str
    secret_alphabet: tuple[int, ...]
    secret_weight: int | None
    secret_eta: int | None
    secret_min_nonzero: int
    secret_max_nonzero: int
    error_distribution_kind: str
    error_sigma: float | None
    error_eta: int | None
    error_bound: int
    error_weight: int | None
    error_max_abs: int
    error_max_l1: int | None
    error_max_l2_squared: int | None
    error_max_nonzero: int | None
    analysis_path: str
    generator_version: str
    calibration_status: str
    calibration_model_id: str
    predicted_runtime_seconds: float
    measured_runtime_seconds: float | None
    instance_digest: str
```

The exact facade methods are `Catalog.load(path: str | Path) -> Catalog`,
`Catalog.get(instance_id: str) -> Instance`, `Instance.iter_rows() ->
Iterator[tuple[int, ...]]`, `Instance.materialize_row_block(start: int, stop:
int) -> tuple[tuple[int, ...], ...]`, `Instance.materialize_rows() ->
tuple[tuple[int, ...], ...]`, `Instance.matvec(secret: Sequence[int]) ->
tuple[int, ...]`, and `Instance.validate_secret(secret: Sequence[int]) ->
WitnessVerdict`. Task 10 supplies their complete delegation behavior. `_instances`
and every wrapped schema object remain private; the listed primitive properties
are the complete supported Phase 3 surface.

Submission JSON is cumulative and has exactly this shape:

```json
{"schema_version":1,"solutions":[{"instance_id":"toy-001","secret":[0,1,0]}]}
```

Duplicate JSON object keys are fatal. Repeating an instance ID, whether with
an identical or different vector, invalidates that ID and scores it zero while
other unique records remain eligible; `conflicted_ids` distinguishes the
different-vector case for diagnostics. Unknown IDs and malformed records score
nothing and are reported by public error codes. Official score is exactly
`100 * solved / catalog_size`; `score_unbounded` is the raw solved-instance
count, and difficulty metadata is diagnostic only.

### Task 1: Register the JSON task scaffold

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/config.yaml`
- Create: `2.0/problems/lwe_structured_recovery/reference.json`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/solution.json`
- Create: `2.0/problems/lwe_structured_recovery/tests/conftest.py`
- Create: `tests/test_lwe_structured_recovery_registration.py`

- [x] **Step 1: Add task-local import/fixture plumbing and write the failing JSON-language registration test**

  Observed: Added the task-local lazy fixtures and safe path-based module loader, plus the root JSON-registration test. The implementation and both independent reviewers confirmed the imports remain lazy and the loader removes a partially initialized module if execution fails.

In task-local `conftest.py`, prepend the task root, `harbor/app`, and
`harbor/app/public` to `sys.path`. Provide lazy `task_dir`, `catalog_path`,
`catalog`, and `valid_submission_bytes` fixtures; imports of not-yet-created
task modules occur inside fixture functions so early TDD collection still
works. Also define `load_task_module(path: Path, module_name: str)` with
`importlib.util.spec_from_file_location`, check both the spec and loader, insert
the module into `sys.modules` before `exec_module`, and return it. The
expose it through a `task_module_loader` fixture; tests never import
`conftest.py` or rely on an undefined `load_module` name. Phase 4's root-level
`tests/lwe_structured_recovery/lwe_test_support.py` is a separate helper for
root tests and does not replace this task-local function.

```python
from pathlib import Path

from frontier_cs.config import get_problem_extension


def test_lwe_structured_recovery_uses_json_reference() -> None:
    root = Path(__file__).parents[1]
    task = root / "2.0/problems/lwe_structured_recovery"
    assert get_problem_extension(task) == "json"
    assert (task / "reference.json").read_text(encoding="utf-8") == (
        '{"schema_version":1,"solutions":[]}\n'
    )
```

- [x] **Step 2: Run the focused test and verify RED**

  Observed: The literal command first hit the sandboxed default uv cache. Re-running with `UV_CACHE_DIR=/tmp/frontier-cs-uv-cache` produced the intended behavioral failure, `assert 'py' == 'json'` (`1 failed`).

Run: `uv run pytest tests/test_lwe_structured_recovery_registration.py -q`

Expected: FAIL because the task files do not exist. Phase 1 already supplies
the JSON registry entry.

- [x] **Step 3: Create the JSON task metadata and empty ledgers**

  Observed: Created the exact pinned agent runtime configuration without judge dependency fields, and byte-checked both empty ledgers as the required single canonical line with a final LF.

Create `config.yaml` exactly as:

```yaml
tag: security
runtime:
  language: json
  timeout_seconds: 10800
  environment: "Public structured-LWE instances; Python 3.11 helper library; CPU only"
  apt_packages:
    - build-essential
    - ca-certificates
    - fplll-tools
    - git
    - libgmp-dev
    - libmpfr-dev
    - pkg-config
    - python3-dev
  pip_packages:
    - numpy==2.1.3
    - scipy==1.14.1
    - fpylll==0.6.4
    - cysignals==1.12.3
    - psutil==6.1.0
  docker:
    image: ubuntu:24.04
environment:
  cpus: 8
  memory_mb: 32768
  storage_mb: 32768
  build_timeout_seconds: 1800
submission:
  kind: file
  path: /app/solution.json
  max_queue_size: 3
```

These native APT prerequisites and exact `pip_packages` are intentional
agent-only dependencies for Phase 3 solvers, even though the Phase 2 core uses
only the standard library. Their versions exactly match Phase 3's
`requirements.lock`; Phase 3's dependency-contract test parses both and rejects drift. Do not
add them to `runtime.judge_apt_packages` or
`runtime.judge_pip_packages`: the judge image needs only the template's
`python3` and `ca-certificates`, preserving the secretless/minimal boundary.
Phase 3's separate pinned Lattice Estimator image remains outside this task
runtime.

Create both JSON ledgers with one line:

```json
{"schema_version":1,"solutions":[]}
```

- [x] **Step 4: Run the focused test and verify GREEN**

  Observed: The focused registration test passed (`1 passed`); the surrounding root suite passed (`38 passed`) with only the pre-existing `google.generativeai` deprecation warning.

Run: `uv run pytest tests/test_lwe_structured_recovery_registration.py -q`

Expected: `1 passed`.

- [x] **Step 5: Commit the scaffold**

  Observed: The slice passed independent specification and code-quality review with no findings and was accepted under the planned `feat(2.0): scaffold structured LWE JSON task` commit boundary.

```bash
git add tests/test_lwe_structured_recovery_registration.py 2.0/problems/lwe_structured_recovery/config.yaml 2.0/problems/lwe_structured_recovery/reference.json 2.0/problems/lwe_structured_recovery/harbor/app/solution.json 2.0/problems/lwe_structured_recovery/tests/conftest.py
git commit -m "feat(2.0): scaffold structured LWE JSON task"
```

### Task 2: Implement bounded duplicate-safe JSON decoding

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/__init__.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/strict_json.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_strict_json.py`

- [x] **Step 1: Write one failing behavior test**

  Observed: Added the nested duplicate-key behavior test through the public `loads_object` API.

```python
import pytest

from lwe_challenge.strict_json import JsonContractError, loads_object


def test_nested_duplicate_key_is_rejected() -> None:
    with pytest.raises(JsonContractError, match="duplicate JSON key: instance_id"):
        loads_object(b'{"x":{"instance_id":"a","instance_id":"b"}}', max_bytes=100)
```

- [x] **Step 2: Run the test and verify RED**

  Observed: The focused test failed at collection with the intended `ModuleNotFoundError` because `lwe_challenge` did not yet exist.

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_strict_json.py -q`

Expected: collection ERROR with `ModuleNotFoundError: No module named 'lwe_challenge'`.

- [x] **Step 3: Implement the complete strict JSON API**

  Observed: Implemented the bounded decoder and then hardened its decode boundary after quality review: finite-looking exponent overflow is rejected, while decoder recursion and Python integer-digit-limit failures are normalized without masking hook-raised `JsonContractError` values.

```python
# strict_json.py
from __future__ import annotations

import json
from typing import Any


class JsonContractError(ValueError):
    """The input violates a bounded, unambiguous JSON contract."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise JsonContractError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _constant(value: str) -> None:
    raise JsonContractError(f"non-finite JSON number: {value}")


def _check_shape(value: Any, *, max_depth: int, max_nodes: int) -> None:
    nodes = 0

    def visit(node: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > max_nodes:
            raise JsonContractError(f"JSON exceeds {max_nodes} nodes")
        if depth > max_depth:
            raise JsonContractError(f"JSON exceeds depth {max_depth}")
        if isinstance(node, dict):
            for key, child in node.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        elif isinstance(node, list):
            for child in node:
                visit(child, depth + 1)

    visit(value, 0)


def loads_object(
    data: bytes,
    *,
    max_bytes: int,
    max_depth: int = 8,
    max_nodes: int = 10_000,
) -> dict[str, Any]:
    if len(data) > max_bytes:
        raise JsonContractError(f"JSON exceeds {max_bytes} bytes")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JsonContractError("invalid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise JsonContractError("top-level JSON value must be an object")
    _check_shape(value, max_depth=max_depth, max_nodes=max_nodes)
    return value
```

- [x] **Step 4: Add one RED→GREEN cycle each for byte limit, NaN, malformed UTF-8, non-object input, excessive nesting, and excessive node count**

  Observed: The six planned boundary tests were added individually and were immediately green against the complete implementation. Review-driven regressions for positive/negative exponent overflow, decoder recursion, and overlong integers each reproduced the missing behavior before their fixes; a finite-float preservation test also passes.

Add six separate tests calling `loads_object`; run the focused file after
adding each test, observe the intended failure, then make only the smallest
correction if the implementation does not pass it.

- [x] **Step 5: Run the module tests and commit**

  Observed: The original hardened suite passed (`12 passed`) before Task 3 seam review added two Unicode-surrogate regressions. The final strict-JSON suite passes (`14 passed`); independent specification and code-quality review approved the decoder boundary.

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_strict_json.py -q`

Expected: `7 passed` (the duplicate-key test plus the six bounded-decoder
tests named in Step 4).

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge 2.0/problems/lwe_structured_recovery/tests/test_strict_json.py
git commit -m "feat(structured-lwe): reject ambiguous JSON"
```

### Task 3: Define and load the strict catalog schema

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/schema.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/fixtures/catalog_two_instances.json`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_schema.py`

- [x] **Step 1: Write the failing minimal-catalog test**

  Observed: Added the public `Catalog.load` fixture test and observed the intended import failure before `schema.py` existed.

```python
from pathlib import Path

from lwe_challenge.schema import Catalog


def test_catalog_loads_dimensions_and_public_predicates() -> None:
    path = Path(__file__).parent / "fixtures/catalog_two_instances.json"
    catalog = Catalog.load(path)
    toy = catalog.get("toy-uniform")
    assert (toy.n, toy.m, toy.q) == (3, 4, 17)
    assert toy.secret.alphabet == (-1, 0, 1)
    assert toy.error.max_abs == 1
```

- [x] **Step 2: Run and verify RED**

  Observed: The first focused run failed with `ModuleNotFoundError: lwe_challenge.schema`, establishing the missing schema behavior.

Expected: FAIL importing `lwe_challenge.schema.Catalog`.

- [x] **Step 3: Add immutable schema types with exact signatures**

  Observed: Implemented the frozen/slotted schema and strict JSON/JSONL loaders. Parallel review added bounded-input hardening for numeric conversion, centered-binomial `eta`, Unicode surrogates, safe ASCII IDs, nonempty catalogs, operational dimensions, catalog-wide work, and regular-file reads; all fixes received regression tests and re-review.

```python
@dataclass(frozen=True, slots=True)
class MatrixSpec:
    kind: Literal["uniform", "small_alphabet", "sparse_uniform", "sparse_small_alphabet"]
    seed_hex: str
    expansion_domain: str
    alphabet: tuple[int, ...] = ()
    row_weight: int | None = None

@dataclass(frozen=True, slots=True)
class SecretDistributionSpec:
    kind: Literal[
        "uniform_mod_q",
        "iid_alphabet",
        "exact_weight_alphabet",
        "centered_binomial",
    ]
    alphabet: tuple[int, ...]
    weight: int | None
    eta: int | None

@dataclass(frozen=True, slots=True)
class SecretPredicateSpec:
    kind: Literal["alphabet", "mod_q"]
    alphabet: tuple[int, ...]
    min_nonzero: int
    max_nonzero: int

@dataclass(frozen=True, slots=True)
class ErrorPredicateSpec:
    max_abs: int
    max_l1: int | None
    max_l2_squared: int | None
    max_nonzero: int | None

@dataclass(frozen=True, slots=True)
class ErrorDistributionSpec:
    kind: Literal[
        "truncated_discrete_gaussian",
        "centered_binomial",
        "bounded_uniform",
        "sparse_bounded",
    ]
    sigma: float | None
    eta: int | None
    bound: int
    weight: int | None

@dataclass(frozen=True, slots=True)
class InstanceSpec:
    schema_version: int
    instance_id: str
    n: int
    m: int
    q: int
    matrix: MatrixSpec
    b: tuple[int, ...]
    secret_distribution: SecretDistributionSpec
    secret: SecretPredicateSpec
    error_distribution: ErrorDistributionSpec
    error: ErrorPredicateSpec
    family: Literal[
        "DS_BIN", "DS_TER", "DS_SMALL", "SA_Q", "SA_SMALL",
        "DA_BIN", "DA_TER", "MIX_Q_SPARSE", "MIX_SMALL_SPARSE",
        "MIX_DENSE_SMALL",
    ]
    tier: Literal["easy", "hard", "synthetic"]
    cohort: Literal["paper", "ladder", "synthetic"]
    octave: int | None
    runtime_bin: str
    analysis_path: str
    generator_version: str
    calibration_status: Literal[
        "unmeasured", "measured", "interpolated", "extrapolated"
    ]
    calibration_model_id: str
    predicted_runtime_seconds: float
    measured_runtime_seconds: float | None
    instance_digest: str

@dataclass(frozen=True, slots=True)
class Catalog:
    schema_version: int
    catalog_id: str
    instances: tuple[InstanceSpec, ...]
```

Implement exact functions `Catalog.load(path: str | Path) -> Catalog`,
`Catalog.get(instance_id: str) -> InstanceSpec`,
`canonical_record_bytes(record: Mapping[str, object]) -> bytes`, and
`compute_instance_digest(record: Mapping[str, object]) -> str`. `Catalog.get`
uses an immutable ID index and raises `KeyError(instance_id)` for a miss.

`Catalog.load` must use `loads_object`, reject unknown keys at every nesting
level, require schema version `1`, require unique IDs, reject booleans wherever
an integer or float is required, require instance IDs to match
`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, and enforce `1 <= n <= 4096`, `1 <= m <=
65536`, `3 <= q <= 2**32 - 1`, `n*m <= 2**26`, `len(b) == m`, `0 <= b_i <
q`, 32-byte lowercase hexadecimal matrix seeds, expansion
domain `FCS-STRUCTURED-LWE-MATRIX-v1`, valid sparse row weights, and sorted
unique alphabets with no two values congruent modulo `q`. Small alphabets use
the unique centered representatives (so `-1` is valid); `uniform` and
`sparse_uniform` have empty alphabets, dense kinds have no row weight, sparse
kinds have `1 <= row_weight <= n`, and `sparse_small_alphabet` excludes zero.

Secret coherence is exact:

- `uniform_mod_q` has empty distribution/predicate alphabets, predicate kind
  `mod_q`, no weight/eta, and bounds `0 <= min_nonzero <= max_nonzero <= n`;
- `iid_alphabet` has a nonempty distribution alphabet equal to the predicate
  alphabet, predicate kind `alphabet`, and no weight/eta;
- `exact_weight_alphabet` has a sorted nonempty distribution alphabet that
  excludes zero, predicate alphabet equal to that alphabet plus zero,
  `weight == min_nonzero == max_nonzero`, and no eta; and
- `centered_binomial` has `eta >= 1`, no weight, distribution and predicate
  alphabet exactly `range(-eta, eta + 1)`, and predicate kind `alphabet`.

Error coherence is likewise exact: `bound >= 0`; Gaussian requires finite
positive `sigma` and no eta/weight; centered binomial requires `eta >= 1`,
`bound == eta`, and no sigma/weight; bounded uniform has no sigma/eta/weight;
sparse bounded has `bound >= 1`, `1 <= weight <= m`, and no sigma/eta. Require
`error.max_abs >= bound`, nonnegative optional L1/L2/nonzero bounds, and
`error.max_nonzero >= distribution.weight` for sparse bounded errors. All
finite runtime fields are nonnegative.

Enforce one approved family code and the exact metadata map
`easy -> (paper, E0..E5, octave=None)`, `hard -> (ladder, H0..H9,
octave=int(runtime_bin[1:]))`, and `synthetic -> (synthetic, synthetic,
octave=None)`. `unmeasured` is allowed for synthetic fixtures and one-record
production staging; Phase 4's release gate, not this reusable loader, requires
final easy records to be measured and hard records to be interpolated or
extrapolated. Require a normalized relative analysis path with no `..`, a
nonempty generator version, and a 64-character lowercase hexadecimal instance
digest. Calibration fields are coherent: `unmeasured` has empty model ID,
zero predicted time, and no measured time; `measured` has a nonempty model/run
ID and finite positive measured time; `interpolated`/`extrapolated` have a
nonempty model ID, finite positive prediction, and no measured time.

Canonical record bytes are UTF-8
`json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
allow_nan=False).encode("utf-8")`. The digest input is the whole canonical
record after deleting exactly `instance_digest`, `analysis_path`,
`calibration_status`, `calibration_model_id`, `predicted_runtime_seconds`, and
`measured_runtime_seconds`; all identity, family/ladder, dimension, matrix,
`b`, secret-distribution/predicate, error-distribution/predicate, schema, and
generator-version fields remain bound. Schema validation and generation share
this function; the Phase 4 release auditor independently recomputes it.

Read the catalog once through a nonblocking file descriptor, require a regular
file, and bound the read itself to 64 MiB plus one sentinel byte. Reject Unicode
surrogate code points before canonical UTF-8 encoding. Across either catalog
format, require at least one record and at most 200, and require aggregate
`sum(n*m) <= 2**28`; these operational bounds are provisional and Phase 4 must
review them before admitting production parameter specs.

When the suffix is `.jsonl`, require LF line endings, a final newline, no blank lines, one strict object per
line, each line byte-equal to `canonical_record_bytes(record)`, and strictly
increasing instance IDs. Derive `catalog_id` from SHA-256 of the exact complete
file and reject duplicate IDs across lines. A one-record canonical JSONL is
valid so Phase 4 can load each staging record before admission. This is the
production/staging format. The `.json` form has exactly the two top-level keys
`schema_version` and `instances` for synthetic tests; it has the same
bounded-read, record-count, and aggregate-work limits, derives rather than embeds `catalog_id`, and rejects
any other top-level key.

- [x] **Step 4: Add the concrete two-instance fixture**

  Observed: Added the checked two-instance synthetic fixture with distinct seeds and independently recomputed digests.

Use `toy-uniform` with `(n,m,q)=(3,4,17)` and `toy-sparse` with `(4,3,19)`. Give each a distinct 64-hex-character seed, inline `b`, explicit predicates, and cohort `synthetic`; set `octave` to `null`.

- [x] **Step 5: Add separate failing tests for unknown nested fields, duplicate IDs, wrong `b` length, invalid sparse weight, secret-distribution/predicate mismatch, canonical full-field secrets, error-distribution/predicate mismatch, tier/cohort/bin/octave mismatch, digest mismatch, canonical one-record JSONL loading, noncanonical JSONL bytes, and JSONL record/byte limits**

  Observed: Completed all thirteen planned behavior items. Review-driven cases now also cover every distribution/calibration branch, huge numeric inputs, allocation-free `eta` validation, Unicode and path hazards, exact and over resource bounds, aggregate JSONL work, nonempty catalogs, and nonregular-file rejection; named invalid records refresh their digests so validation-order assumptions do not mask the intended invariant.

Use `tmp_path` to write each malformed catalog. Run each new test before changing `schema.py`, confirm its assertion fails for the named validation, then implement that validation.

- [x] **Step 6: Run and commit**

  Observed: Final focused results are `14 passed` for strict JSON and `13 passed` for schema (`27 passed` combined), plus the root registration test. Two parallel spec audits, 266 original adversarial probes, 319 seam probes, and final quality checks approved the slice. The independently computed Task 4 SHAKE prefix was also corrected in this plan before matrix implementation.

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_schema.py -q`

Expected: `13 passed` (the loading test plus the twelve validations named in
Step 5).

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/schema.py 2.0/problems/lwe_structured_recovery/tests/fixtures/catalog_two_instances.json 2.0/problems/lwe_structured_recovery/tests/test_schema.py
git commit -m "feat(structured-lwe): add strict public catalog schema"
```

### Task 4: Implement SHAKE streams and matrix reconstruction

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/shake.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/matrix.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/audit/matrix_ref.c`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_shake_matrix.py`

- [x] **Step 1: Write a failing golden-vector test for SHAKE byte order**

  Observed: The standalone `hashlib` computation corrected the draft prefix to `27027578f05e9bd4933317218e161c7e`; the missing-module test then established RED.

```python
from lwe_challenge.shake import ShakeStream


def test_shake_stream_has_stable_first_block() -> None:
    stream = ShakeStream(domain=b"FCS-STRUCTURED-LWE-TEST-v1", seed=bytes(32))
    assert stream.read(16).hex() == "27027578f05e9bd4933317218e161c7e"
```

Before implementation, compute and review this golden value once with a
standalone
`hashlib.shake_256(domain + b"\0" + seed + (0).to_bytes(8,"little")).digest(64)`
command; replace the literal if that independently reviewed command differs,
and commit the reviewed literal with the implementation. This is a primitive
test-vector computation, not a recovery attempt, so it is permitted before the
execution gate.

- [x] **Step 2: Verify RED, then implement `ShakeStream` and unbiased `randbelow`**

  Observed: Implemented exact buffered block construction and unbiased little-endian rejection sampling, including zero/invalid boundary coverage and permanent `UINT32_MAX` parity.

Implement exact methods `ShakeStream.__init__(*, domain: bytes, seed: bytes)
-> None`, `ShakeStream.read(count: int) -> bytes`, and
`ShakeStream.randbelow(upper: int) -> int`. Require a 32-byte seed and a
nonempty domain. Generate block `i` as `SHAKE256(domain || 0x00 || seed ||
LE64(i)).digest(64)` and buffer unused bytes. For `randbelow`, let `width =
max(1, ceil(bit_length(upper - 1)/8))` and `limit = floor(256**width / upper) *
upper`; read a little-endian `width`-byte integer until it is below `limit`,
then return it modulo `upper`. Reject `upper <= 0`; unconditioned modular
reduction is forbidden.

- [x] **Step 3: Write the failing dense-row and matvec tests**

  Observed: Added public-API row and streamed matvec tests before the matrix module existed, then satisfied them without full-matrix materialization.

```python
from lwe_challenge.matrix import iter_rows, matvec_mod
from lwe_challenge.schema import Catalog


def test_streamed_matvec_matches_materialized_oracle(catalog: Catalog) -> None:
    inst = catalog.get("toy-uniform")
    rows = tuple(iter_rows(inst))
    secret = (1, 0, -1)
    oracle = tuple(sum(a * s for a, s in zip(row, secret)) % inst.q for row in rows)
    assert matvec_mod(inst, secret) == oracle
```

- [x] **Step 4: Implement the matrix API**

  Observed: Implemented exact length-framed domains, row separation, all four matrix structures, row blocks, and validated modular matvec under the schema bounds.

Implement exact functions `iter_rows(instance: InstanceSpec) ->
Iterator[tuple[int, ...]]`, `materialize_row_block(instance: InstanceSpec,
start: int, stop: int) -> tuple[tuple[int, ...], ...]`,
`materialize_rows(instance: InstanceSpec) -> tuple[tuple[int, ...], ...]`, and
`matvec_mod(instance: InstanceSpec, secret: Sequence[int]) -> tuple[int, ...]`.

Encode every matrix stream domain exactly as `LE32(len(domain_utf8)) ||
domain_utf8 || LE32(len(instance_id_ascii)) || instance_id_ascii ||
LE64(row_index) || tag`, where tag is `0x01` for dense coefficients, `0x02`
for sparse support, or `0x03` for sparse coefficients. Pass those bytes as the
`ShakeStream.domain`, with the public 32-byte matrix seed as
`ShakeStream.seed`; its internal block separator/counter is therefore applied
once and only once. Never concatenate ambiguous variable-length fields and
never reuse a stream between support and coefficient sampling. Uniform entries
use `randbelow(q)`.
Small-alphabet entries index uniformly into `alphabet`. Sparse rows choose
`row_weight` distinct columns by rejection, sort their positions, fill all
others with zero, and choose nonzero coefficients from `[1,q)` or the declared
nonzero alphabet.

`materialize_row_block` validates `0 <= start <= stop <= m` and streams only
the requested rows; `materialize_rows` is exactly the block `[0,m)`.

- [x] **Step 5: Add vertical RED→GREEN tests for all four matrix kinds**

  Observed: Retained reviewed Python golden rows and behavior coverage for dimensions, alphabets, sparse weights, repeatability, row separation, invalid inputs, and saturated sparse support.

Each test asserts dimensions, coefficient domain, exact row weight where applicable, repeatability, and differing rows under row-domain separation. Add and satisfy one kind at a time.

- [x] **Step 6: Add the independent native materializer and cross-check**

  Observed: Added an independently coded C11/FIPS-202 oracle with strict CLI validation. Python/native checks cover every kind, at least three rows, rejection-heavy moduli/alphabet sizes, multi-row ranges, `UINT32_MAX`, full sparse support, malformed CLI, and public-only argv. Review added 30-second compile and 10-second execution timeouts to prevent hung tests.

Write a standalone C11 row/range materializer that contains an independently
coded FIPS-202 SHAKE-256/Keccak permutation with an MIT/CC0-compatible
provenance comment. Its complete CLI is `matrix_ref --seed HEX64 --domain TEXT
--instance-id ASCII --n N --q Q --kind KIND [--alphabet CSV] [--row-weight K]
--start START --stop STOP`. `uniform` and `sparse_uniform` reject `--alphabet`;
both small-alphabet kinds require it. Both sparse kinds require `--row-weight`;
both dense kinds reject it. `0 <= START <= STOP <= m` is checked by the caller because `m` is
not otherwise needed. The program independently implements the exact LE32/LE64
domain tuple, block construction, rejection sampler, and support sampler, then
emits one whitespace-separated signed-integer row plus LF for every index in
`[START,STOP)`. It must not call Python, receive a secret/error, or share
generated tables/code with `shake.py` or `matrix.py`. The range interface lets
Phase 4 feed public native rows to its private checker through one subprocess
without exposing private values in argv or files.

Compile it in the test with
`cc -std=c11 -O2 -Wall -Wextra -Werror`, then compare native and Python rows
for every matrix kind, at least three row indices, rejection-heavy non-power-
failure, not a skip. Include one multi-row range test and one malformed-CLI
test, and retain reviewed Python/native golden rows for all four kinds.

- [x] **Step 7: Run and commit**

  Observed: Final focused suite passed (`48 passed`); strict compilation, ASan/UBSan probes, full spec review, and code-quality re-review passed with no remaining findings. The slice was accepted under the planned `feat(structured-lwe): materialize SHAKE matrices` boundary.

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_shake_matrix.py -q`

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/shake.py 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/matrix.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/audit/matrix_ref.c 2.0/problems/lwe_structured_recovery/tests/test_shake_matrix.py
git commit -m "feat(structured-lwe): materialize SHAKE matrices"
```

### Task 5: Verify any valid small secret without a planted secret

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/verification.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_verification.py`

- [x] **Step 1: Write failing centered-modulus boundary tests**

  Observed: Added the negative-even-tie behavior first and observed the intended missing-module failure.

```python
from lwe_challenge.verification import centered_mod


def test_centered_mod_uses_negative_even_tie() -> None:
    assert tuple(centered_mod(x, 8) for x in range(8)) == (0, 1, 2, 3, -4, -3, -2, -1)
```

- [x] **Step 2: Verify RED and implement exact integer predicates**

  Observed: Implemented frozen aggregate verdicts, strict secret shape/predicate checks, centered residuals, and deterministic integer-only norm bounds with stable codes.

```python
@dataclass(frozen=True, slots=True)
class WitnessVerdict:
    ok: bool
    code: str
    max_abs_error: int | None
    l1_error: int | None
    l2_squared_error: int | None
```

Implement exact functions `centered_mod(value: int, q: int) -> int`,
`validate_secret_shape(instance: InstanceSpec, secret: Sequence[int]) -> str |
None`, `residual(instance: InstanceSpec, secret: Sequence[int]) -> tuple[int,
...]`, and `validate_secret(instance: InstanceSpec, secret: Sequence[int]) ->
WitnessVerdict`.

Reject booleans, non-integers, and wrong lengths. For an `alphabet` predicate,
reject values outside the declared alphabet; for `mod_q`, require canonical
representatives `0 <= s_i < q`. Enforce the inclusive secret nonzero-count
bounds. Compute `e_i = centered_mod(b_i - (A*s)_i, q)` and enforce `max_abs`,
optional L1, optional squared-L2, and optional error nonzero-count bounds using
integers only. Return stable public codes such as `ok`, `wrong_length`,
`secret_alphabet`, `secret_mod_q`, `secret_weight`, `error_linf`, `error_l1`,
`error_l2`, and `error_weight`. The library verdict may report aggregate norms
because they are computable from public data; the official evaluator must not
return those candidate-specific values in its message or metrics.

- [x] **Step 3: Add a synthetic valid witness test that derives `b` from public `A,s,e`**

  Observed: Real SHAKE matrix tests derive `b` from public values and prove two distinct secrets are accepted when each satisfies the published predicates; no identity comparison exists.

Construct the fixture in the test, verify the chosen secret, then verify that a different planted-independent secret is also accepted when it satisfies the same public predicates. This proves the checker does not compare identities.

- [x] **Step 4: Add one RED→GREEN test per rejection code**

  Observed: Added behavior coverage for all shape, alphabet/modulus, nonzero-count, and error-norm/weight rejection codes, canonical full-field secrets, immutability, and leakage boundaries.

Keep each test to one observable code and use real matrix reconstruction rather
than mocks. Include canonical full-field secret acceptance and error-weight
rejection.

- [x] **Step 5: Run and commit**

  Observed: Focused verification passed (`31 passed`), with `90 passed` across verification, matrix, and schema. Independent spec and quality reviews approved the slice with no Critical or Important findings.

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_verification.py -q`

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/verification.py 2.0/problems/lwe_structured_recovery/tests/test_verification.py
git commit -m "feat(structured-lwe): verify public LWE predicates"
```

### Task 6: Parse untrusted cumulative submissions without duplicate inflation

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/submission.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_submission.py`

- [x] **Step 1: Write the failing conflicting-duplicate test**

  Observed: Added the conflicting-duplicate behavior first and observed the intended missing-module failure.

```python
from lwe_challenge.submission import parse_submission


def test_conflicting_duplicate_invalidates_only_that_id(catalog) -> None:
    data = b'{"schema_version":1,"solutions":[' \
           b'{"instance_id":"toy-uniform","secret":[1,0,-1]},' \
           b'{"instance_id":"toy-uniform","secret":[0,0,0]},' \
           b'{"instance_id":"toy-sparse","secret":[0,0,0,0]}]}'
    parsed = parse_submission(data, catalog=catalog)
    assert set(parsed.records) == {"toy-sparse"}
    assert parsed.conflicted_ids == ("toy-uniform",)
```

- [x] **Step 2: Verify RED and implement the parser contract**

  Observed: Implemented immutable parsed records, strict whole-ledger bounds, stable decoded-contract codes, duplicate poisoning across malformed/unknown occurrences, and deterministic duplicate/conflict/unknown metadata.

```python
@dataclass(frozen=True, slots=True)
class SubmissionRejection:
    instance_id: str | None
    code: str


@dataclass(frozen=True, slots=True)
class ParsedSubmission:
    records: Mapping[str, tuple[int, ...]]
    duplicate_ids: tuple[str, ...]
    conflicted_ids: tuple[str, ...]
    unknown_ids: tuple[str, ...]
    rejections: tuple[SubmissionRejection, ...]
    invalid_records: int
```

Implement `parse_submission(data: bytes, *, catalog: Catalog, max_bytes: int =
2_000_000, max_records: int = 200) -> ParsedSubmission`.

Require exactly top-level keys `schema_version` and `solutions`, version `1`,
a list of at most 200 records, exact record keys `instance_id` and `secret`,
ASCII IDs of at most 64 characters, integer arrays, no booleans, and absolute
integer magnitude at most `2**63 - 1`. Any repeated ID is removed without
erasing unrelated valid IDs; different vectors also mark the ID as conflicted.
Every record with a syntactically valid ID participates in duplicate detection
even if its secret field is malformed, so an invalid duplicate cannot preserve
the first copy. `SubmissionRejection` carries only the ID and a stable public
code—never a submitted value. Duplicate JSON object keys, unsupported schema,
wrong top-level shape, excessive file/record/depth/node limits, and malformed
UTF-8/JSON are whole-ledger errors; malformed individual records, unknown IDs,
and invalid witnesses leave unrelated unique entries eligible.

- [x] **Step 3: Add separate RED→GREEN tests for duplicate JSON keys, identical duplicates, unknown IDs, booleans, oversized integers, extra keys, and record limits**

  Observed: Added the planned cases plus byte/depth/node bounds, immutability, malformed-copy poisoning, and configuration validation. Quality review drove complete normalization of raw JSON errors: attacker-controlled keys are absent from messages, causes, contexts, and formatted tracebacks.

- [x] **Step 4: Run and commit**

  Observed: Final focused suite passed (`46 passed`), and submission plus strict-JSON/schema passed (`73 passed`). Independent spec review and two quality re-review rounds approved the slice with no remaining findings.

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_submission.py -q`

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/submission.py 2.0/problems/lwe_structured_recovery/tests/test_submission.py
git commit -m "feat(structured-lwe): parse cumulative witness ledgers"
```

### Task 7: Score verified witnesses equally in the secretless evaluator core

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/evaluator_core.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/fixtures/submission_one_valid.json`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_evaluator_core.py`

- [x] **Step 1: Write the failing equal-score integration test**

  Observed: The original toy fixture had no valid witness, so the reviewed seam changed only `toy-uniform.b` and its digest to bind `[1,0,-1]` with residual `(1,-1,0,1)`. The one-of-two scoring test then established the intended missing-core RED.

```python
from lwe_challenge.evaluator_core import evaluate_bytes


def test_one_of_two_valid_witnesses_scores_fifty(catalog, valid_submission_bytes) -> None:
    result = evaluate_bytes(valid_submission_bytes, catalog=catalog)
    assert result.score == 50.0
    assert result.score_unbounded == 1.0
    assert result.solved_ids == ("toy-uniform",)
    assert result.metrics["solved_count"] == 1
```

- [x] **Step 2: Verify RED and implement the public result**

  Observed: Implemented exact equal scoring, deeply immutable aggregate metrics, capped redacted examples, family/tier/octave diagnostics, and stable whole-ledger/path error boundaries. Submission reads are bounded, nonblocking, and regular-file checked; unexpected evaluator/I/O failures still propagate.

```python
@dataclass(frozen=True, slots=True)
class EvaluationResult:
    score: float
    score_unbounded: float
    message: str
    metrics: Mapping[str, object]
    solved_ids: tuple[str, ...]
```

Implement `evaluate_bytes(data: bytes, *, catalog: Catalog) ->
EvaluationResult` and `evaluate_path(path: str | Path, *, catalog: Catalog) ->
EvaluationResult`.

Score `100.0 * solved_count / len(catalog.instances)` and set
`score_unbounded = float(solved_count)`. Include public counts for solved,
submitted, conflicts, unknowns, and rejection codes; include sorted solved IDs,
`instance_count`, easy/paper and hard totals, solved counts by family and hard octave, and the
hardest solved octave. Cap invalid-ID/reason examples at twenty while retaining
complete aggregate counts.
Do not include source paths, exceptions, submitted secrets, residual vectors,
or tracebacks. Convert every parse failure into score zero and message
`submission_invalid code=<stable_code>`. `evaluate_path` likewise converts
only expected missing/unreadable submission-file `OSError`s into a stable
public code; it does not catch `Exception` broadly. Schema/catalog/materializer
errors and every unexpected evaluator exception propagate as infrastructure
failures. Public predicate failures are normal rejection codes, not exceptions,
and one invalid entry never erases another ID's valid score.

- [x] **Step 3: Add RED→GREEN tests for partial credit, malformed whole-file score zero, an invalid record beside a valid record, and alternate-witness acceptance**

  Observed: Added the planned integration cases plus duplicate/unknown aggregates, 20-example cap, metadata metrics, alternate-witness acceptance, redaction scans, file-growth/short-read/path hazards, and infrastructure-exception propagation.

- [x] **Step 4: Run and commit**

  Observed: Final focused suite passed (`32 passed`); evaluator plus submission/verification passed (`109 passed`). Spec and quality re-reviews approved the slice. Nested metrics remain truly immutable; Task 11 now owns recursive conversion to a separate JSON-native snapshot.

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_evaluator_core.py -q`

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/evaluator_core.py 2.0/problems/lwe_structured_recovery/tests/fixtures/submission_one_valid.json 2.0/problems/lwe_structured_recovery/tests/test_evaluator_core.py
git commit -m "feat(structured-lwe): score secretless witnesses equally"
```

### Task 8: Add canonical cumulative ledger helpers

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/ledger.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/add_solution.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_ledger.py`

- [x] **Step 1: Write the failing idempotent-merge test**

  Observed: Added the idempotent-merge behavior before the ledger module existed and observed the intended import failure.

```python
from lwe_challenge.ledger import Ledger, merge_witness


def test_identical_merge_is_idempotent() -> None:
    ledger = Ledger(schema_version=1, solutions={"a": (1, 0)})
    merged = merge_witness(ledger, instance_id="a", secret=(1, 0), replace=False)
    assert merged == ledger
```

- [x] **Step 2: Implement ledger APIs with atomic canonical output**

  Observed: Implemented bounded duplicate-safe loading, immutable canonical ledgers, conflict-aware merges, and descriptor-isolated atomic replacement. Review hardening added a stable sibling `fcntl` transaction lock, pre-created private quarantine, foreign-inode recovery, ledger/lock symlink rejection, complete short-write handling, and parent-directory `fsync` after replacement.

```python
@dataclass(frozen=True, slots=True)
class Ledger:
    schema_version: int
    solutions: Mapping[str, tuple[int, ...]]
```

Implement `load_ledger(path: str | Path) -> Ledger`, `merge_witness(ledger:
Ledger, *, instance_id: str, secret: Sequence[int], replace: bool = False) ->
Ledger`, and `write_ledger_atomic(path: str | Path, ledger: Ledger) -> None`.

`load_ledger` uses the same bounded duplicate-key-safe decoder, exact top-level
and record keys, integer rules, and repeat-ID rejection as the submission
contract. Write compact UTF-8 JSON with IDs sorted lexicographically and a final
newline. Write to an exclusive sibling temporary file, flush and `os.fsync`,
then `os.replace`; on failure unlink only the temporary file created by that
call. Refuse a conflicting existing ID unless `replace=True`.

- [x] **Step 3: Add RED→GREEN tests for conflict refusal, explicit replacement, canonical ordering, and atomic preservation when serialization fails**

  Observed: Added the planned cases plus size/depth/node bounds, malformed records, nonregular paths, cleanup races, foreign regular/symlink/FIFO/directory recovery, partial writes, durability ordering, lock safety, and synchronized multiprocess lost-update/conflict regressions.

- [x] **Step 4: Implement `add_solution.py` as a thin CLI**

  Observed: Added the sanitized thin CLI; its lock encloses the post-acquisition reread, merge, and atomic write, and successful output reveals only the updated witness count.

Accept `INSTANCE_ID`, a comma-separated integer vector, optional `--ledger /app/solution.json`, and `--replace`. Import only `lwe_challenge.ledger`; print the updated witness count without printing secrets.

- [x] **Step 5: Run and commit**

  Observed: Final focused suite passed (`67 passed`), the combined Tasks 8–10 check passed (`160 passed`), and repeated reviewer stress found no lost updates in 100 distinct-ID races or incorrect outcomes in 100 same-ID races. Independent final specification and quality reviews approved the slice with no remaining findings.

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_ledger.py -q`

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/ledger.py 2.0/problems/lwe_structured_recovery/harbor/app/add_solution.py 2.0/problems/lwe_structured_recovery/tests/test_ledger.py
git commit -m "feat(structured-lwe): add cumulative ledger helper"
```

### Task 9: Generate synthetic fixtures without publishing private seeds

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/generator.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_generator.py`
- Create: `2.0/problems/lwe_structured_recovery/catalog.synthetic.json`

- [x] **Step 1: Write the failing non-disclosure test**

  Observed: Added the structural public-artifact non-disclosure test before the generator module existed and observed the intended missing-module failure.

```python
from lwe_challenge.generator import generate_synthetic_instance


def test_public_instance_omits_private_seed_and_witness(toy_template) -> None:
    generated = generate_synthetic_instance(template=toy_template, private_seed=bytes.fromhex("11" * 32))
    public = generated.public_json()
    assert "private_seed" not in public
    assert "private_secret" not in public
    assert "planted_secret" not in public
    assert "private_error" not in public
    assert "planted_error" not in public
    assert public["secret"]
    assert public["error"]
    assert generated.instance.b
```

- [x] **Step 2: Implement injected private entropy and generated artifacts**

  Observed: Implemented domain-separated synthetic and production generation for all four secret and four error distributions. Sampling and attestation consume only normalized immutable schema records; private seed, secret, error, and attestation remain in-memory-only and are excluded from repr and public serialization. Review hardening added allocation-free dimension/work preflight, bounded immutable alphabet snapshots, canonical-error bounds, and a fresh fully specified Decimal context for Gaussian tables.

```python
@dataclass(frozen=True, slots=True)
class GenerationTemplate:
    instance_id: str
    n: int
    m: int
    q: int
    matrix: MatrixSpec
    secret_distribution: SecretDistributionSpec
    secret: SecretPredicateSpec
    error_distribution: ErrorDistributionSpec
    error: ErrorPredicateSpec
    family: str
    tier: str
    cohort: str
    octave: int | None
    runtime_bin: str
    analysis_path: str
    generator_version: str
    calibration_status: str
    calibration_model_id: str
    predicted_runtime_seconds: float
    measured_runtime_seconds: float | None

@dataclass(frozen=True, slots=True)
class GeneratedInstance:
    instance: InstanceSpec
    private_secret: tuple[int, ...] = field(repr=False)
    private_error: tuple[int, ...] = field(repr=False)
    private_attestation: "GenerationAttestation" = field(repr=False)
    public_sha256: str

@dataclass(frozen=True, slots=True)
class GenerationAttestation:
    instance_id: str
    instance_digest: str
    distribution_checks_passed: bool
    planted_witness_valid: bool
    secret_nonzero: int
    error_nonzero: int
    error_max_abs: int

```

Implement `GeneratedInstance.public_json() -> dict[str, object]`,
`generate_synthetic_instance(*, template: GenerationTemplate, private_seed:
bytes) -> GeneratedInstance`, and `generate_production_instance(*, template:
GenerationTemplate) -> GeneratedInstance`. Define a concrete `toy_template`
pytest fixture in `test_generator.py`; do not rely on an undeclared helper.

Use a private `_generate(template, private_seed, mode)` implementation with
`mode` restricted to `synthetic` or `production`. Synthetic streams use
`FCS-STRUCTURED-LWE-SYNTHETIC-SECRET-v1` and
`FCS-STRUCTURED-LWE-SYNTHETIC-ERROR-v1`; production streams use distinct
`FCS-STRUCTURED-LWE-PRODUCTION-SECRET-v1` and
`FCS-STRUCTURED-LWE-PRODUCTION-ERROR-v1`. `generate_synthetic_instance`
requires exactly 32 injected bytes. `generate_production_instance` has no seed
or entropy-provider parameter and draws exactly 32 bytes with
`secrets.token_bytes`; it must not call the synthetic entry point.

Cover
all four secret distributions (`uniform_mod_q`, `iid_alphabet`, exact weight
over nonzero alphabet values, and centered binomial with public `eta`) and all
four declared error
distributions. Truncated discrete Gaussian sampling must use the documented
finite table over `[-bound, bound]`; centered binomial samples the difference
of two `eta`-bit Hamming weights; bounded uniform samples every integer in the
declared interval; sparse bounded first samples an exact support. Derive
`b = A*s + e mod q`, validate the generated secret/error against the public
predicates, compute the canonical instance digest excluding linkage fields,
and keep private values only in memory. Return a private generation attestation
that binds the public digest to distribution/verification results and private
summary statistics, without creating reusable hashes of the answer. Neither
the attestation nor its statistics may enter the catalog, task image,
evaluator image, analyses, calibration logs, or git; the production
orchestrator passes the ephemeral secret/error through a private pipe to a
separate clean-room checker and destroys all private state before exit.
`public_json` must serialize only the public
`InstanceSpec`, including its verified digest.

No method may serialize the attestation, secret, error, or private seed; their
dataclass fields are `repr=False`, and tests also reject them from `repr()` and
`public_json()`. The Phase 4 one-record subprocess sends the public record plus
`private_secret` and `private_error` directly to its independent checker over a
private stdin pipe, compares that check with the in-memory attestation, writes
only a scrubbed boolean receipt, and relies on process teardown—not a false
Python zeroization claim—to destroy private state. No answer/secret/error hash
is computed or retained.

- [x] **Step 3: Add RED→GREEN tests for deterministic synthetic generation, synthetic/production domain separation with an injected private `_generate` test seam, changed `b` under a different private seed, every secret/error distribution, valid generated witnesses, attestation binding, redacted repr/attestation non-serialization, absence of answer hashes, and public hash stability**

  Observed: Added the planned coverage plus all 16 distribution combinations, ambient-context independence, dishonest-length/index/mutation alphabets, exact/over resource bounds, q-boundary canonical residuals, and raw-error checks for every published predicate plus exact centered-residual equality.

The non-disclosure assertion is structural, not a substring ban: catalog keys
`secret`, `secret_distribution`, `error`, and `error_distribution` are required
public predicates/distributions and must remain allowed. Reject only planted,
submitted, seed, private-entropy, private-attestation, or answer-hash material.

- [x] **Step 4: Generate the two tiny checked-in synthetic fixtures**

  Observed: Generated exactly two cohort-`synthetic` fixtures with fixed test-only seeds. The public catalog is 3,236 bytes with SHA-256 `6a12049c04f15670a06a95ab11e8faf160ab9d9318ed15c5a81fc6bdfd13b19a`; final review found no private material, and repeated generation preserved both instance digests and `b` vectors.

Use fixed test-only private seeds, inspect the resulting catalog diff, and verify neither seed nor witness is serialized. Write exactly two cohort-`synthetic` entries to `catalog.synthetic.json`.

- [x] **Step 5: Run and commit**

  Observed: Final focused suite passed (`88 passed`), targeted final spec probes passed (`24 passed`), and the combined Tasks 8–10 check passed (`160 passed`). Independent final specification and quality reviews approved the slice with no Critical or Important findings.

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_generator.py -q`

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_challenge/generator.py 2.0/problems/lwe_structured_recovery/tests/test_generator.py 2.0/problems/lwe_structured_recovery/catalog.synthetic.json
git commit -m "feat(structured-lwe): add secret-safe synthetic generator"
```

### Task 10: Freeze the solver-facing facade

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_instance.py`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_public_facade.py`

- [ ] **Step 1: Write a failing end-to-end facade test**

```python
import lwe_instance


def test_public_facade_supports_phase3_solver_workflow(catalog_path) -> None:
    catalog = lwe_instance.Catalog.load(catalog_path)
    instance = catalog.get("toy-uniform")
    assert len(instance.b) == instance.m
    assert instance.family == "DS_TER"
    assert instance.matrix_kind == "uniform"
    assert instance.secret_distribution_kind == "exact_weight_alphabet"
    assert instance.secret_predicate_kind == "alphabet"
    assert tuple(instance.iter_rows()) == instance.materialize_rows()
    assert instance.materialize_row_block(1, 3) == instance.materialize_rows()[1:3]
    assert len(instance.materialize_rows()) == instance.m
    assert len(instance.matvec((0,) * instance.n)) == instance.m
    assert instance.validate_secret((0,) * instance.n).code in {
        "ok", "secret_weight", "error_linf", "error_l1", "error_l2"
    }
```

- [ ] **Step 2: Implement wrapper objects without exposing internals**

`lwe_instance.Catalog` wraps `schema.Catalog`; `get` returns an
`lwe_instance.Instance`. `Instance` exposes all read-only primitive properties
listed in the fixed contract, including public `b`, family/difficulty labels,
and matrix/secret/error distribution parameters. It delegates row iteration,
row-block/full materialization, matvec, and validation to `matrix` and
`verification`. Export `Catalog`, `Instance`, and `WitnessVerdict` through
`__all__`; callers never need to import `lwe_challenge.*` or parse raw JSON to
implement an attack.

Cache one wrapper per ID so repeated `get` calls and `instances` share object
identity and ordering. Do not expose the wrapped `InstanceSpec`, generator
private types, filesystem paths beyond the public relative `analysis_path`, or
any mutator.

- [ ] **Step 3: Add a public-surface test**

Assert `set(lwe_instance.__all__) == {"Catalog", "Instance", "WitnessVerdict"}` and that no test or Phase-3 caller needs a private module import.

- [ ] **Step 4: Run and commit**

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_public_facade.py -q`

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_instance.py 2.0/problems/lwe_structured_recovery/tests/test_public_facade.py
git commit -m "feat(structured-lwe): freeze public instance facade"
```

### Task 11: Wire the Frontier-CS evaluator and local wrapper

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/evaluator.py`
- Create: `2.0/problems/lwe_structured_recovery/evaluate.sh`
- Create: `2.0/problems/lwe_structured_recovery/tests/test_fcs_wrapper.py`

- [ ] **Step 1: Write the failing FCS tuple-contract test**

```python
from pathlib import Path


def test_fcs_evaluator_returns_public_four_tuple(task_dir: Path, task_module_loader, monkeypatch) -> None:
    monkeypatch.setenv("FCS_STRUCTURED_LWE_CATALOG", str(task_dir / "catalog.synthetic.json"))
    module = task_module_loader(task_dir / "evaluator.py", "lwe_evaluator_synthetic")
    result = module.evaluate(str(task_dir / "reference.json"))
    assert len(result) == 4
    score, unbounded, message, metrics = result
    assert score == unbounded == 0.0
    assert "traceback" not in message.lower()
    assert metrics["instance_count"] == 2
```

- [ ] **Step 2: Implement the evaluator with a strict infrastructure boundary**

`evaluator.py` resolves the explicit test override first. Otherwise use
`FRONTIER_PUBLIC_DIR` when present, then `harbor/app/public` beside the
source-tree evaluator. Add that resolved directory to `sys.path`, then
import internal `lwe_challenge.schema.Catalog` and
`lwe_challenge.evaluator_core.evaluate_path`; the solver-facing facade stays
narrow. Cache by resolved absolute catalog path plus verified catalog digest,
not with a zero-argument cache that can survive a test override change, and
expose:

```python
def prepare() -> dict[str, object]:
    catalog = _catalog()
    return {"instance_count": len(catalog.instances), "catalog_id": catalog.catalog_id}

def evaluate(solution_path: str) -> tuple[float, float, str, dict[str, object]]:
    catalog = _catalog()
    result = evaluate_path(solution_path, catalog=catalog)
    return result.score, result.score_unbounded, result.message, _plain_data(result.metrics)
```

`_plain_data` recursively copies immutable internal mappings/tuples into fresh
plain `dict`/`list` containers and accepts only JSON scalar leaves. A shallow
`dict(result.metrics)` is insufficient because the evaluator core deliberately
keeps nested metrics immutable. Test that `json.dumps(_plain_data(metrics))`
succeeds and that mutating the returned snapshot cannot mutate the core result.

Resolve the catalog in this order: the explicit test/development override
`FCS_STRUCTURED_LWE_CATALOG`; `FRONTIER_PUBLIC_DIR/catalog.jsonl` in the judge;
then `harbor/app/public/catalog.jsonl` relative to `evaluator.py` in a source
checkout. Never silently fall back to the synthetic catalog in production;
tests that need it must set the explicit override. For either production path,
require sibling `catalog.sha256`, verify it against the exact catalog bytes,
require exact sidecar text `<64 lowercase hex>  catalog.jsonl\n`, and require
exactly 200 instances before `prepare()` succeeds. The explicit
synthetic override may omit the sidecar and use a smaller catalog. Missing or
corrupt production assets are infrastructure errors and must propagate from
`prepare()`/`_catalog()`; do not convert them into an agent score of zero. Only
enumerated submission I/O/JSON/record/witness contract failures are sanitized
inside `evaluate_path`. Unexpected implementation errors propagate as
infrastructure failures rather than being charged to the agent. Do not include
exception text in returned values.

- [ ] **Step 3: Create `evaluate.sh`**

Use strict Bash, locate `/work/execution_env/solution_env/solution.json`, and run `python3 evaluator.py "$SOLUTION"`. `evaluator.py`'s CLI must print its public message to stderr and `score score_unbounded` as the final stdout line.

- [ ] **Step 4: Add RED→GREEN tests for judge/source catalog precedence, cache isolation between overrides, production sidecar mismatch, production row-count mismatch, preparation failure propagation, unexpected matrix exception propagation, missing solution file, malformed ledger, valid partial ledger, and absence of tracebacks/paths/secrets/residuals in public output**

- [ ] **Step 5: Run and commit**

Run: `PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests/test_fcs_wrapper.py -q`

```bash
git add 2.0/problems/lwe_structured_recovery/evaluator.py 2.0/problems/lwe_structured_recovery/evaluate.sh 2.0/problems/lwe_structured_recovery/tests/test_fcs_wrapper.py
git commit -m "feat(structured-lwe): wire secretless FCS evaluator"
```

### Task 12: Write the agent contract and run non-solver verification

**Files:**
- Create: `2.0/problems/lwe_structured_recovery/readme`
- Modify: `2.0/problems/lwe_structured_recovery/harbor/app/solution.json`
- Test: `2.0/problems/lwe_structured_recovery/tests/`
- Test: `tests/test_lwe_structured_recovery_registration.py`

- [ ] **Step 1: Write the readme-contract test first**

Extend `tests/test_lwe_structured_recovery_registration.py` to assert the readme names `/app/solution.json`, `bash /app/submit.sh`, `public/lwe_instance.py`, cumulative submissions, equal per-instance scoring, exact duplicate behavior, conflicting duplicate behavior, and the fact that the evaluator holds no secret.

- [ ] **Step 2: Run and verify RED**

Expected: FAIL because `readme` is absent.

- [ ] **Step 3: Write the complete agent readme**

Document the public catalog, stable Python facade with a runnable import example, JSON ledger schema, strict validity predicates, equal-count formula, cumulative merge workflow using `add_solution.py`, CPU/memory/time budget, public feedback fields, and explicit instruction to submit after every newly validated secret while retaining previous entries.

- [ ] **Step 4: Run the complete task-local and root suites**

Run without invoking any recovery solver:

```bash
PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public uv run pytest 2.0/problems/lwe_structured_recovery/tests -q
uv run pytest tests/test_lwe_structured_recovery_registration.py -q
PYTHONPYCACHEPREFIX=/private/tmp/frontier-cs-pycache python3 -m py_compile 2.0/problems/lwe_structured_recovery/evaluator.py 2.0/problems/lwe_structured_recovery/harbor/app/public/lwe_instance.py
```

Expected: all task-local and root tests pass; compilation exits zero. Do not run a lattice solver or any calibrated attack.

- [ ] **Step 5: Run the local empty-ledger smoke**

Run: `FCS_STRUCTURED_LWE_CATALOG=$PWD/2.0/problems/lwe_structured_recovery/catalog.synthetic.json python3 2.0/problems/lwe_structured_recovery/evaluator.py 2.0/problems/lwe_structured_recovery/reference.json`

Expected final stdout line: `0.000000000000 0.000000000000`.

- [ ] **Step 6: Commit the documented core**

```bash
git add 2.0/problems/lwe_structured_recovery/readme 2.0/problems/lwe_structured_recovery/harbor/app/solution.json tests/test_lwe_structured_recovery_registration.py
git commit -m "docs(structured-lwe): document public witness workflow"
```

## Self-review result

- Spec coverage: scaffold, JSON reference, strict catalog, SHAKE matrices, all four matrix structures, public secret/error predicates, any-witness acceptance, duplicate-safe submission semantics, equal scoring, cumulative ledger helper, synthetic generation, public Phase-3 facade, FCS wrapper, agent readme, and task/root tests each map to a task above.
- Secretlessness: production secret/error seeds are neither accepted by public schemas nor serialized; evaluator logic uses only catalog `(A,b)` materialization and submitted secrets.
- API consistency: Phase 3 depends only on the documented `lwe_instance`
  catalog/instance properties, streamed/block/full row methods, matvec, and
  witness verdict; all signatures match the fixed contract and expose every
  public sampling/verifier parameter needed by an attack.
- Packaging boundary: this core plan validates local imports. Installing the public package and production catalog into the generated Harbor judge image is deliberately assigned to the later packaging phase; no claim of a Harbor smoke is made here.
- Placeholder scan: implementation steps specify concrete paths, signatures, behaviors, commands, expected failures, and commits; no unresolved implementation marker remains.
- Scope check: no production 200-instance catalog, cryptanalytic solver, calibration run, long benchmark, or hidden witness is created or executed in Phase 2.
