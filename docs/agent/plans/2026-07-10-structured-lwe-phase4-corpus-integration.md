# Structured LWE Phase 4 Corpus and Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Curate, generate, calibrate, individually analyze, independently review, package, and release-audit the approved 200-instance corpus, then complete Frontier-CS and Harbor integration.

**Architecture:** A deterministic slot registry imports all family ordering,
runtime-bin bounds, target formulas, and admission decisions from the Phase 3
`analysis_tools.ladder` module; Phase 4 does not implement a second ladder.
Each production candidate moves through a one-way staging pipeline: reviewed
parameter spec, secret-safe one-record generation, private-pipe cross-check,
public instance audits, Phase 3 calibration/admission, individually authored
analysis, two digest-bound reviews, and atomic canonical-catalog admission. A
single scoped release-audit engine validates either one exact family or the
complete corpus and binds every per-instance artifact into one release
manifest.

**Tech Stack:** Python 3.11+, canonical JSON/JSONL, SHA-256, Markdown, pytest, the Phase 2 public verifier/generator, the Phase 3 solvers/audits/calibration tools, Frontier-CS CLI, and Harbor.

---

## File map

**Create:**

- `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/slot_registry.py` — canonical ID/family/bin allocation.
- `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/family_contracts.py` — exact matrix, secret, and error semantics for all ten families.
- `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/review_manifest.py` — digest-bound review records.
- `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/release_audit.py` — complete release gate.
- `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/work_queue.py` — one-instance-at-a-time author/reviewer routing.
- `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/staging.py` — immutable candidate staging, linkage finalization, and atomic admission.
- `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/capture_hardware.py` — allowlisted, non-sensitive reference-platform capture.
- `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/verify_harbor_package.py` — generated agent/judge asset-boundary verifier.
- `2.0/problems/lwe_structured_recovery/harbor/app/tools/generator/generate_instance.py` — one-record production generator with ephemeral attestation checks.
- `2.0/problems/lwe_structured_recovery/harbor/app/tools/generator/private_check.py` — separate clean-room checker reading private values only from a pipe.
- `2.0/problems/lwe_structured_recovery/harbor/app/public/slots.json` — generated immutable slot registry.
- `2.0/problems/lwe_structured_recovery/harbor/app/public/specs/*.json` — 200 individually selected parameter specs.
- `2.0/problems/lwe_structured_recovery/harbor/app/public/catalog.jsonl` — canonical public instances.
- `2.0/problems/lwe_structured_recovery/harbor/app/public/catalog.sha256` — catalog digest.
- `2.0/problems/lwe_structured_recovery/harbor/app/public/format.md` — canonical record and matrix-expansion specification.
- `2.0/problems/lwe_structured_recovery/harbor/app/analyses/*.md` — 200 individually authored analyses.
- `2.0/problems/lwe_structured_recovery/harbor/app/analyses/reviews.jsonl` — 400 current review records.
- `2.0/problems/lwe_structured_recovery/harbor/app/analyses/work-events.jsonl` — hash-chained one-at-a-time author/reviewer events.
- `2.0/problems/lwe_structured_recovery/harbor/app/LITERATURE.md` — corrected task-local literature map.
- `2.0/problems/lwe_structured_recovery/calibration/hardware.json` — reference platform manifest.
- `2.0/problems/lwe_structured_recovery/calibration/summaries/*.json` — per-instance measured/predicted evidence.
- `2.0/problems/lwe_structured_recovery/calibration/generation_receipts/*.json` — scrubbed per-instance generation checks.
- `2.0/problems/lwe_structured_recovery/calibration/attack_estimates/*.json` — all applicable and rejected exact-attack estimates per instance.
- `2.0/problems/lwe_structured_recovery/calibration/reduction_audits/*.json` — theorem-hypothesis and lower-bound margins per instance.
- `2.0/problems/lwe_structured_recovery/calibration/uniqueness/*.json` — rank, kernel, and alternative-witness result per instance.
- `2.0/problems/lwe_structured_recovery/calibration/ladder/*.json` — Phase 3 admission receipt per instance.
- `2.0/problems/lwe_structured_recovery/calibration/instance_manifests/*.json` — per-instance release manifests binding slot, record, evidence, runs/model, analysis, and reviews.
- `2.0/problems/lwe_structured_recovery/calibration/scrubbed_logs/*/*.json` — witness-free measured-run records; the only release location allowed to contain `output_sha256`.
- `2.0/problems/lwe_structured_recovery/calibration/models.json` — fitted model registry.
- `2.0/problems/lwe_structured_recovery/calibration/release-manifest.json` — canonical path/digest inventory for all release artifacts.
- `2.0/problems/lwe_structured_recovery/calibration/FIRST_SOLVER_RUN.md` — Phase 3 gate-crossing record, verified and manifest-bound here.
- `2.0/problems/lwe_structured_recovery/DESIGN.md` — task-local design summary.
- `2.0/problems/lwe_structured_recovery/AUDIT_REPORT.md` — release and Harbor evidence.
- `tests/lwe_structured_recovery/test_slot_registry.py` — exact allocation tests.
- `tests/lwe_structured_recovery/test_family_contracts.py` — exact family and error schedule tests.
- `tests/lwe_structured_recovery/test_review_manifest.py` — digest and role tests.
- `tests/lwe_structured_recovery/test_work_queue.py` — one-instance author/reviewer state tests.
- `tests/lwe_structured_recovery/test_staging.py` — immutable-field and atomic-admission tests.
- `tests/lwe_structured_recovery/test_release_audit.py` — complete-corpus and leak tests.
- `tests/lwe_structured_recovery/test_production_generator.py` — production-mode non-disclosure and attestation tests.
- `tests/lwe_structured_recovery/test_capture_hardware.py` — allowlist and sensitive-field rejection tests.
- `tests/lwe_structured_recovery/test_harbor_package.py` — agent/judge packaging-boundary tests.
- `tests/lwe_structured_recovery/lwe_test_support.py` — isolated task-module and synthetic-release helpers.

**Modify:**

- `2.0/problems/lwe_structured_recovery/readme` — final public task instructions and immediate-submit workflow.
- `2.0/README.md` — register the new task.

## Task 1: Lock the 200 immutable slots

**Files:**

- Create: `tests/lwe_structured_recovery/test_slot_registry.py`
- Create: `tests/lwe_structured_recovery/test_family_contracts.py`
- Create: `tests/lwe_structured_recovery/lwe_test_support.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/slot_registry.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/family_contracts.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/slots.json`

- [ ] **Step 1: Add the isolated task-module loader and write the failing quota and ID test**

Implement `REPO_ROOT = Path(__file__).resolve().parents[2]`,
`TASK_ROOT = REPO_ROOT / "2.0/problems/lwe_structured_recovery"`, and
`load_task_module(relative_path, module_name)` in `lwe_test_support.py`.
Resolve `relative_path` against `TASK_ROOT`, temporarily prepend both
`TASK_ROOT` and `TASK_ROOT / "harbor/app/public"` to `sys.path`, use
`importlib.util.spec_from_file_location`, and fail if either the file or loader
is absent. Restore `sys.path` in `finally`. All paths passed below are relative
to the task root.

```python
from collections import Counter

from lwe_test_support import load_task_module


def test_slot_registry_has_exact_approved_shape():
    module = load_task_module(
        "harbor/app/tools/corpus/slot_registry.py", "lwe_slot_registry"
    )
    slots = module.build_slots()
    assert len(slots) == 200
    assert [slot["instance_id"] for slot in slots] == [
        f"lwe_{index:04d}" for index in range(1, 201)
    ]
    assert Counter(slot["family"] for slot in slots) == {
        family: 20 for family in module.FAMILIES
    }
    assert Counter(slot["runtime_bin"] for slot in slots if slot["tier"] == "easy") == {
        f"E{index}": 10 for index in range(6)
    }
    assert Counter(slot["runtime_bin"] for slot in slots if slot["tier"] == "hard") == {
        f"H{index}": 14 for index in range(10)
    }
    for family in module.FAMILIES:
        easy = [
            slot["runtime_bin"]
            for slot in slots
            if slot["family"] == family and slot["tier"] == "easy"
        ]
        assert easy == [f"E{index}" for index in range(6)]
    assert Counter(slot["required_error_kind"] for slot in slots) == {
        kind: 50 for kind in module.ERROR_KINDS
    }
    for family in module.FAMILIES:
        assert Counter(
            slot["required_error_kind"] for slot in slots if slot["family"] == family
        ) == {kind: 5 for kind in module.ERROR_KINDS}
```

- [ ] **Step 2: Run the test and verify the missing-module failure**

Run:

```bash
uv run pytest tests/lwe_structured_recovery/test_slot_registry.py -q
```

Expected: FAIL because `slot_registry.py` does not exist.

- [ ] **Step 3: Implement the allocation strictly from the Phase 3 ladder API**

```python
from __future__ import annotations

import json
from pathlib import Path

from analysis_tools.ladder import (
    EASY_BOUNDS_SECONDS,
    FAMILY_CODES,
    easy_target_seconds,
    hard_octave,
    hard_target_hours,
)

FAMILIES = FAMILY_CODES
ERROR_KINDS = (
    "truncated_discrete_gaussian",
    "centered_binomial",
    "bounded_uniform",
    "sparse_bounded",
)


def build_slots() -> list[dict[str, object]]:
    slots: list[dict[str, object]] = []
    next_id = 1
    for family_index, family in enumerate(FAMILIES):
        for easy_index, _bounds in enumerate(EASY_BOUNDS_SECONDS):
            slots.append(
                {
                    "instance_id": f"lwe_{next_id:04d}",
                    "family": family,
                    "tier": "easy",
                    "cohort": "paper",
                    "runtime_bin": f"E{easy_index}",
                    "target_seconds": easy_target_seconds(family_index, easy_index),
                    "required_error_kind": ERROR_KINDS[easy_index % 4],
                }
            )
            next_id += 1
        for hard_index in range(14):
            octave = hard_octave(family_index, hard_index)
            slots.append(
                {
                    "instance_id": f"lwe_{next_id:04d}",
                    "family": family,
                    "tier": "hard",
                    "cohort": "ladder",
                    "runtime_bin": f"H{octave}",
                    "target_hours": hard_target_hours(octave, hard_index),
                    "required_error_kind": ERROR_KINDS[(hard_index + 6) % 4],
                }
            )
            next_id += 1
    return slots


def write_slots(path: Path) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(build_slots(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    write_slots(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

The import is mandatory: if `analysis_tools.ladder` is missing or its family
tuple differs, slot generation fails. Phase 4 must not copy a bin bound,
target formula, admission rule, or family ordering into another module.

- [ ] **Step 4: Define and test exact family semantics**

Implement `validate_family_contract(slot, record) -> list[str]` in
`family_contracts.py`, and table-driven tests for every accepted and rejected
combination. Enforce this exact mapping:

| Family | Matrix | Secret distribution and public predicate |
| --- | --- | --- |
| `DS_BIN` | `uniform` | `exact_weight_alphabet`, nonzero alphabet `[1]`, predicate alphabet `[0,1]`, exact nonzero weight |
| `DS_TER` | `uniform` | `exact_weight_alphabet`, nonzero alphabet `[-1,1]`, predicate alphabet `[-1,0,1]`, exact nonzero weight |
| `DS_SMALL` | `uniform` | `iid_alphabet` over `[0,1]` or `[-1,0,1]`, or `centered_binomial`; no exact weight |
| `SA_Q` | `sparse_uniform` | `uniform_mod_q` with `mod_q` predicate |
| `SA_SMALL` | `sparse_small_alphabet` with `[1]` or `[-1,1]` | `uniform_mod_q` with `mod_q` predicate |
| `DA_BIN` | `small_alphabet` over `[0,1]` | `uniform_mod_q` with `mod_q` predicate |
| `DA_TER` | `small_alphabet` over `[-1,0,1]` | `uniform_mod_q` with `mod_q` predicate |
| `MIX_Q_SPARSE` | `sparse_uniform` | exact-weight binary or signed ternary as above |
| `MIX_SMALL_SPARSE` | `sparse_small_alphabet` with `[1]` or `[-1,1]` | exact-weight binary or signed ternary as above |
| `MIX_DENSE_SMALL` | dense `small_alphabet` binary or ternary | dense `iid_alphabet`/`centered_binomial`, or exact-weight binary/signed ternary |

For an exact-weight distribution require `weight == secret.min_nonzero ==
secret.max_nonzero`; for iid alphabet require the distribution and predicate
alphabets to match and `weight is None`; for centered binomial require
`eta >= 1`, `weight is None`, and predicate alphabet exactly every integer in
`[-eta, eta]`; for `uniform_mod_q` require empty alphabets, no weight/eta, a
`mod_q` predicate, and bounds `0..n`.

For sparse matrices require `1 <= row_weight < n`; for non-sparse matrices
require `row_weight is None`. Require prime `q` for `sparse_uniform`, so its
sampled nonzero coefficients are units. A composite modulus in any other
family requires a complete prime-power factor audit in that instance's
reduction artifact.

Require `record.error_distribution.kind == slot.required_error_kind`. Enforce
the Phase 2 field semantics exactly: truncated Gaussian has `sigma > 0`,
`eta is None`, positive `bound`, and no `weight`; centered binomial has
`sigma is None`, integer `eta >= 1`, `bound == eta`, and no `weight`; bounded
uniform has only a positive `bound`; sparse bounded has only a positive
`bound` and `1 <= weight <= m`. In every case require
`error.max_abs >= error_distribution.bound`; for sparse bounded require
`error.max_nonzero >= error_distribution.weight`. The generated residual must
still satisfy every declared predicate; these coherence checks do not replace
witness validation.

- [ ] **Step 5: Generate the registry and rerun both tests**

Run:

```bash
PYTHONPATH=2.0/problems/lwe_structured_recovery:2.0/problems/lwe_structured_recovery/harbor/app/public \
  uv run python 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/slot_registry.py \
  --output 2.0/problems/lwe_structured_recovery/harbor/app/public/slots.json
uv run pytest tests/lwe_structured_recovery/test_slot_registry.py tests/lwe_structured_recovery/test_family_contracts.py -q
```

Expected: PASS; `slots.json` contains exactly 200 records.

- [ ] **Step 6: Commit the immutable allocation**

```bash
git add tests/lwe_structured_recovery/lwe_test_support.py tests/lwe_structured_recovery/test_slot_registry.py tests/lwe_structured_recovery/test_family_contracts.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/slot_registry.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/family_contracts.py 2.0/problems/lwe_structured_recovery/harbor/app/public/slots.json
git commit -m "feat: lock structured LWE corpus slots"
```

## Task 2: Add digest-bound review records

**Files:**

- Create: `tests/lwe_structured_recovery/test_review_manifest.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/review_manifest.py`

- [ ] **Step 1: Write failing tests for current-artifact reviews**

Create fixtures with one analysis digest, instance digest, and the exact six
evidence digests (`generation_receipt`, `attack_estimates`,
`reduction_audit`, `uniqueness`, `calibration_summary`, `ladder_receipt`).
Assert that `validate_reviews` accepts exactly one current approved
`cryptanalysis` record and one current approved `reproducibility` record when
their reviewers are distinct non-authors, both bind all current digests, and
each names at least two concrete analysis claim IDs. Add separate tests that
reject self-review, one person filling both roles, stale analysis/instance or
evidence digests, empty findings, unresolved `changes_requested`, duplicate
current approvals, and an edit after approval.

- [ ] **Step 2: Run the tests and verify the missing-module failure**

Run:

```bash
uv run pytest tests/lwe_structured_recovery/test_review_manifest.py -q
```

Expected: FAIL because `review_manifest.py` is absent.

- [ ] **Step 3: Implement review creation and validation**

```python
from __future__ import annotations

from datetime import datetime, timezone
from typing import Mapping, Sequence

REQUIRED_ROLES = {"cryptanalysis", "reproducibility"}


def make_review(
    instance_id: str,
    role: str,
    reviewer: str,
    version: int,
    author: str,
    instance_digest: str,
    analysis_sha256: str,
    artifact_sha256: Mapping[str, str],
    verdict: str,
    checked_claim_ids: Sequence[str],
    findings: str,
    resolution: str,
) -> dict[str, object]:
    if role not in REQUIRED_ROLES:
        raise ValueError(f"unsupported review role: {role}")
    if version < 1:
        raise ValueError("review version must be positive")
    if verdict not in {"approved", "changes_requested"}:
        raise ValueError(f"unsupported verdict: {verdict}")
    if reviewer == author:
        raise ValueError("self-review is forbidden")
    if len(set(checked_claim_ids)) < 2:
        raise ValueError("at least two concrete claim ids are required")
    if not findings.strip() or (verdict == "approved" and not resolution.strip()):
        raise ValueError("findings and approval resolution are required")
    return {
        "review_id": f"{instance_id}-{role}-v{version}",
        "instance_id": instance_id,
        "role": role,
        "version": version,
        "reviewer": reviewer,
        "author": author,
        "instance_digest": instance_digest,
        "analysis_sha256": analysis_sha256,
        "artifact_sha256": dict(sorted(artifact_sha256.items())),
        "verdict": verdict,
        "checked_claim_ids": sorted(set(checked_claim_ids)),
        "findings": findings.strip(),
        "resolution": resolution.strip(),
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
    }


def validate_reviews(
    instance_id: str,
    author: str,
    instance_digest: str,
    analysis_sha256: str,
    artifact_sha256: Mapping[str, str],
    records: list[dict[str, object]],
) -> list[str]:
    errors: list[str] = []
    matching = [record for record in records if record["instance_id"] == instance_id]
    current = [
        max(
            (record for record in matching if record["role"] == role),
            key=lambda record: int(record["version"]),
        )
        for role in REQUIRED_ROLES
        if any(record["role"] == role for record in matching)
    ]
    approved_roles = set()
    for record in current:
        if record["reviewer"] == author:
            errors.append("self-review is forbidden")
        if record["instance_digest"] != instance_digest:
            errors.append("review instance digest is stale")
        if record["analysis_sha256"] != analysis_sha256:
            errors.append("review digest is stale")
        if record["artifact_sha256"] != dict(sorted(artifact_sha256.items())):
            errors.append("review evidence digest is stale")
        if record["verdict"] == "approved":
            approved_roles.add(record["role"])
    if approved_roles != REQUIRED_ROLES:
        errors.append("both current approved review roles are required")
    approved = [record for record in current if record["verdict"] == "approved"]
    if len(approved) != 2:
        errors.append("exactly two current approvals are required")
    if len({record["reviewer"] for record in approved}) != len(approved):
        errors.append("reviewers must be distinct")
    return sorted(set(errors))
```

- [ ] **Step 4: Rerun the review tests**

Run:

```bash
uv run pytest tests/lwe_structured_recovery/test_review_manifest.py -q
```

Expected: PASS.

- [ ] **Step 5: Implement an append-only, hash-chained work queue**

`work_queue.py` exposes only `append_event(path, event)` and
`replay_events(path)`. `append_event` exclusively locks the log, replays the
current chain, appends exactly one canonical JSONL line, flushes and `fsync`s
it before unlocking, and rejects a truncated tail or stale predecessor. Every
event contains `event_id`,
`instance_id`, `actor`, `role`, `from_state`, `to_state`, UTC timestamp,
`input_artifact_sha256`, `previous_event_sha256`, and `event_sha256`; the last
field is SHA-256 over the other canonical fields. Permit only:

```text
selected -> spec_reviewed -> generated -> instance_audited -> calibrated -> authored
authored -> crypto_reviewed -> repro_reviewed -> admitted
selected | spec_reviewed | generated | instance_audited | calibrated -> changes_requested -> selected
authored | crypto_reviewed | repro_reviewed -> changes_requested -> authored
```

An author may have only one instance between `selected` and `authored`; the
`spec_reviewed` event must be signed by a non-author cryptanalysis reviewer
and bind the exact spec digest. A
reviewer may have only one active review; roles must use the author and two
distinct reviewers recorded in the events. `input_artifact_sha256` must bind
the exact spec at selection, record/receipt/uniqueness at instance audit,
Phase 3 evidence at calibration, analysis at authorship, and current analysis
plus six evidence digests at each review; `admitted` binds the completed
per-instance manifest digest. A changed artifact invalidates all
downstream states and requires explicit `changes_requested -> selected` or
`changes_requested -> authored` restart events. Tests reject broken hashes,
time reversal, a skipped transition, overlapping author/reviewer work,
actor-role changes, reusing a reviewer, and admission without current reviews.
Review versions start at one and increase after every
`changes_requested` cycle; only the greatest version for each role may be a
current approval.

- [ ] **Step 6: Add auditable anti-boilerplate checks**

Add `audit_analysis_distinctness(paths)`. Ignore headings, metadata lines,
tables of raw parameters, fenced commands, and citation-only lines; normalize
case, whitespace, IDs, and decimal/hex numbers in remaining prose. Reject an
identical normalized paragraph of at least 25 words in two analyses. Compute
five-word shingles over each remaining body and reject pairwise Jaccard
similarity `>= 0.80`. Require at least eight instance-specific claim IDs and
citations to all six evidence artifacts in each analysis. Tests include two
templated analyses whose changed IDs/numbers must still be rejected and two
independently written synthetic analyses that pass. This detector is a release
gate in addition to, not a substitute for, one-at-a-time work events.

- [ ] **Step 7: Commit the review contract**

```bash
git add tests/lwe_structured_recovery/test_review_manifest.py tests/lwe_structured_recovery/test_work_queue.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/review_manifest.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/work_queue.py
git commit -m "feat: bind LWE analyses to independent reviews"
```

## Task 3: Add the release auditor

**Files:**

- Create: `tests/lwe_structured_recovery/test_release_audit.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/release_audit.py`

- [ ] **Step 1: Write a failing incomplete-corpus test**

```python
from pathlib import Path

from lwe_test_support import load_task_module


def test_release_audit_rejects_missing_artifacts(tmp_path):
    module = load_task_module(
        "harbor/app/tools/corpus/release_audit.py", "lwe_release_audit"
    )
    errors = module.audit_release(tmp_path)
    assert "slots.json is missing" in errors
    assert "catalog must contain exactly 200 instances" in errors
    assert "reviews must contain exactly 400 current approvals" in errors
```

- [ ] **Step 2: Run the test and verify the missing-module failure**

Run:

```bash
uv run pytest tests/lwe_structured_recovery/test_release_audit.py -q
```

Expected: FAIL because `release_audit.py` is absent.

- [ ] **Step 3: Implement the auditor entry point**

```python
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[4]
for import_root in (
    TASK_ROOT,
    TASK_ROOT / "harbor/app",
    TASK_ROOT / "harbor/app/public",
):
    sys.path.insert(0, str(import_root))

from analysis_tools.ladder import FAMILY_CODES
from analysis_tools.leak_audit import audit_release_tree
from lwe_instance import Catalog

APPROVED_FAMILIES = frozenset(FAMILY_CODES)


def _jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def audit_release(
    task_root: Path,
) -> list[str]:
    public = task_root / "harbor" / "app" / "public"
    slots_path = public / "slots.json"
    if not slots_path.exists():
        return [
            "catalog must contain exactly 200 instances",
            "reviews must contain exactly 400 current approvals",
            "slots.json is missing",
        ]
    slots = json.loads(slots_path.read_text(encoding="utf-8"))
    return audit_scope(task_root, slots=slots, scope_kind="full")
```

`audit_scope` is the only artifact-validation engine. Full, family, and the
non-CLI candidate-overlay admission path select immutable slots and delegate to
it; no caller reimplements a per-instance check. `scope_kind` is the strict
enum `candidate|family|full`, not caller-supplied expected counts.

- [ ] **Step 4: Extend tests with a complete synthetic release fixture**

Add a `write_synthetic_release(task_root)` helper to
`tests/lwe_structured_recovery/lwe_test_support.py`. It writes the exact 200
synthetic-domain slots and, for every slot, one tiny public record, one
complete per-instance manifest, one analysis, and two current approvals. It
also writes every global sidecar with the production cardinalities. Audit it
only through the production wrappers:

```python
assert module.audit_release(task_root) == []
for family in module.APPROVED_FAMILIES:
    assert module.audit_family(task_root, family) == []
```

Then mutate the catalog, one analysis, and one review digest in three separate
tests and assert the exact errors `catalog digest mismatch`, `analysis digest
mismatch`, and `review digest is stale`. The Phase 2 helper and every fixture
use only the `synthetic-test-v1` domain.

Extend `release_audit.py` with this digest helper and call it from
`audit_release`:

```python
def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _digest_errors(
    task_root: Path,
    catalog: list[dict],
    review_rows: list[dict],
) -> list[str]:
    errors: list[str] = []
    app = task_root / "harbor" / "app"
    catalog_path = app / "public" / "catalog.jsonl"
    digest_path = app / "public" / "catalog.sha256"
    if catalog_path.exists() and digest_path.exists():
        expected_sidecar = f"{_sha256(catalog_path)}  catalog.jsonl\n"
        if digest_path.read_text(encoding="ascii") != expected_sidecar:
            errors.append("catalog digest mismatch")
    for row in catalog:
        analysis_path = app / row["analysis_path"]
        if not analysis_path.exists():
            errors.append(f'{row["instance_id"]}: analysis is missing')
            continue
        actual = _sha256(analysis_path)
        matching = [
            review
            for review in review_rows
            if review.get("instance_id") == row["instance_id"]
            and review.get("verdict") == "approved"
        ]
        if matching and any(
            review.get("analysis_sha256") != actual for review in matching
        ):
            errors.append("review digest is stale")
            errors.append("analysis digest mismatch")
    return errors
```

- [ ] **Step 5: Implement the one shared strict scope audit**

Implement
`audit_scope(task_root, *, slots, scope_kind) -> list[str]`.
Load the complete `catalog.jsonl` through Phase 2 `Catalog.load`, then select
exactly the IDs in `slots`. Require `catalog.sha256` to match the complete
catalog bytes and canonical one-record-per-line JSON sorted by ID. For each
All other JSON/JSONL artifacts use the Phase 2 duplicate-key-safe decoder,
strict unknown-field schemas, canonical bytes, LF/final-newline rules, and
bounded size/depth/count; `_jsonl` above is only introductory pseudocode and
must not remain a permissive production parser. For each
selected ID require exactly one slot, spec, catalog row, analysis, generation
receipt, attack-estimate artifact, reduction audit, uniqueness result,
calibration summary, Phase 3 ladder receipt, per-instance manifest, top-level
release-manifest entry, and exactly two current reviews. Reject an unrecognized
catalog ID—meaning absent from the global immutable 200-slot registry—even
during candidate/family audit. Other already admitted, globally recognized
out-of-scope IDs are allowed and retain global catalog/manifest integrity;
they are not mistaken for members of the selected family/candidate scope.

Validate every selected record with `validate_family_contract`. Require exact
slot equality for family/tier/cohort/bin/octave/error kind. Require the
generation receipt's instance digest, every analysis artifact reference, both
reviews, and manifest entry to match current bytes. Recompute every
`artifact_sha256` independently; reject missing, extra, duplicate, absolute,
escaping, symlinked, or untracked paths.

Each canonical `calibration/instance_manifests/<id>.json` contains
`schema_version`, `instance_id`, `instance_digest`, and these exact bindings:

```text
slot, spec, public_record, generation_receipt, attack_estimates,
reduction_audit, uniqueness, calibration_summary, ladder_receipt,
runtime_model, analysis, cryptanalysis_review, reproducibility_review,
run_log_artifacts
```

Ordinary file bindings contain a task-root-relative `path` and full-file
`artifact_sha256`. `slot` also binds the canonical selected object in
`slots.json`; `public_record` and each review bind their exact canonical JSONL
line; `runtime_model` binds its model ID, canonical entry, and `models.json`;
and `run_log_artifacts` is the ID-sorted set of run IDs named by the summary,
with one scrubbed-log path and file digest each. The per-instance manifest is
created after both reviews, avoiding a digest cycle. For an easy measured
instance `runtime_model` is exactly `{"status":"not_applicable"}`; for a hard
instance it is the required path/file/entry binding.

The top-level release manifest is canonical JSON with `schema_version`,
`catalog_sha256`, `models_sha256`,
`slots_sha256`, `reviews_sha256`, `work_events_sha256`, `hardware_sha256`,
`first_solver_run_sha256`, `lattice_estimator_lock_sha256`, and
`reduction_assumptions_sha256`, plus an
ID-sorted `instances` array. Each entry contains exactly `instance_id`,
`instance_digest`, `manifest_path`, and `manifest_sha256`. Its top-level
`run_log_artifacts` inventory must equal the union in the per-instance
manifests. Neither manifest copies a solver-output digest.

Call the Phase 3 ladder admission API for each selected summary/slot. In full
For `scope_kind="full"`, require the supplied slots to equal the complete immutable registry, call
its complete-corpus validator, and require exactly 200 records,
20/family, 60 measured easy, 140 modeled hard, ten per `E0`–`E5`, fourteen per
`H0`–`H9`, and the Phase 3 cyclic balance. For `scope_kind="family"`, use the same
per-instance validators and require all and only the immutable twenty slots
(six easy, fourteen hard) for one approved family; do not accept a subset,
count override, or weaker local formula. Require exactly five instances of
each error kind per family and fifty of each kind globally. The synthetic
release uses these same counts; production code has no reduced-count mode.

For internal `scope_kind="candidate"`, require exactly one immutable slot and
one prospective overlay record, run every per-instance schema, family,
theorem, evidence, review, digest, distinctness-against-current-corpus, leak,
manifest, and transaction check, but defer only the mathematically impossible
20/200 aggregate quotas. Candidate mode is not exposed by the release-audit
CLI and cannot weaken a family/full audit; tests prove an artifact mutation
produces the same per-instance error in all three scopes.

Construct a canonical 200-entry ledger using the longest valid representative
for every public secret predicate and require it to remain below Phase 2's
2,000,000-byte parser cap (and the repository submission limit). This is a
release gate so a valid complete solution can always be submitted cumulatively.

For every non-mixed single-structure family (`DS_*`, `SA_*`, and `DA_*`),
require `passes_gate` for every applicable reduction, including
Brakerski-Döttling/Micciancio/GVV secret mappings, BBTV/JLS sparse-matrix
mappings, and the dense-binary BLMR check; `rejects_candidate` and
`requires_human_review` are inadmissible. Mixed families must retain all
single-structure diagnostics, declare `known_composition: false` when no
interaction theorem is known, and include `normal_lwe_fallback` among attack
estimates when no interaction-specific exact attack applies. Apply the same
fallback rule to every family: if no specialized exact-search estimate is
applicable, `normal_lwe_fallback` is mandatory; absence of an identified
specialized attack never means absence of an estimate. Decision and refutation
estimates can occur only under `non_qualifying_leads`.

For every analysis, require explicit `Instance:`, `Author:`,
`Instance-Digest:`, and eight or more `Claim-ID:` metadata entries. For
its current digest require exactly one approved cryptanalysis review and one
approved reproducibility review, with two distinct non-author reviewer IDs;
reject extra current approvals. Recompute instance-to-analysis-to-review
linkage, replay the entire hash-chained work event log, and run
`audit_analysis_distinctness` over the selected analyses. Recursively call the
Phase 3 `audit_release_tree` for private keys/files.

Allow `output_sha256` only in
`calibration/scrubbed_logs/<instance_id>/<run_id>.json`, only when both path
components match the record's IDs, and only when the same record says
`output_disposition: "deleted_after_validation"`. Summaries,
models, specs, catalog, receipts, analyses, reviews, ladder records, uniqueness
records, per-instance manifests, and the top-level release manifest may
contain artifact/instance/catalog digests but never `output_sha256`; they
refer to run IDs and bind the scrubbed log files instead.

- [ ] **Step 6: Run all release-audit tests**

Run:

```bash
uv run pytest tests/lwe_structured_recovery/test_release_audit.py -q
```

Expected: PASS for the synthetic complete fixture and PASS for every expected
tamper rejection. Add a paired regression that mutates the same artifact and
asserts both `audit_release` and `audit_family` report the same scoped error;
this proves the family wrapper cannot bypass the shared strict engine.

- [ ] **Step 7: Add the full-release and focused-family CLI**

```python
def audit_family(task_root: Path, family: str) -> list[str]:
    if family not in APPROVED_FAMILIES:
        return [f"unsupported family: {family}"]
    slots_path = task_root / "harbor/app/public/slots.json"
    slots = json.loads(slots_path.read_text(encoding="utf-8"))
    selected = [slot for slot in slots if slot["family"] == family]
    return audit_scope(task_root, slots=selected, scope_kind="family")


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--family", choices=sorted(APPROVED_FAMILIES))
    args = parser.parse_args(argv)
    task_root = Path(__file__).resolve().parents[4]
    errors = (
        audit_family(task_root, args.family)
        if args.family
        else audit_release(task_root)
    )
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Add a regression that changes the process working directory to `tmp_path`,
invokes `main`, and proves `Path(__file__).resolve().parents[4]` is the task
root (`.../lwe_structured_recovery`), not `harbor`, `app`, or the caller's
working directory. Keep all test helper paths task-root-relative through the
`lwe_test_support.py` loader defined in Task 1.

- [ ] **Step 8: Commit the release gate**

```bash
git add tests/lwe_structured_recovery/test_release_audit.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/release_audit.py
git commit -m "feat: audit structured LWE release artifacts"
```

## Task 3B: Add the one-record production generator boundary

**Files:**

- Create: `tests/lwe_structured_recovery/test_production_generator.py`
- Create: `tests/lwe_structured_recovery/test_staging.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/generator/generate_instance.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/generator/private_check.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/staging.py`

- [ ] **Step 1: Write failing production non-disclosure tests**

Load the CLI module through `lwe_test_support`. With an injected synthetic
entropy provider, generate one tiny record into `tmp_path` and assert:

- `generated.jsonl` contains exactly one newline-terminated canonical JSON
  object (not an array and with no blank/second line) and is accepted by Phase
  2 `Catalog.load`;
- its instance digest recomputes;
- the in-memory private attestation binds that digest and reports successful
  support/predicate/witness checks, and a separate checker agrees after
  receiving the ephemeral values only through an anonymous stdin pipe;
- neither the public record nor the scrubbed receipt contains a planted/
  submitted secret vector, planted error vector, private seed/attestation,
  private hash, answer hash, or witness (the required public `secret`,
  `error`, and distribution predicate objects remain allowed); and
- the checker emits a public-safe uniqueness result and neither process retains
  the ephemeral private attestation after the independent check.

Also assert the production CLI refuses every deterministic/fixed-entropy
argument. Tests needing fixed entropy inject the Phase 2 synthetic generator
API directly and may write only below pytest's temporary directory; there is
no production-CLI switch that weakens this boundary.

- [ ] **Step 2: Run the focused test and verify RED**

Run:

```bash
PYTHONPATH=2.0/problems/lwe_structured_recovery:2.0/problems/lwe_structured_recovery/harbor/app:2.0/problems/lwe_structured_recovery/harbor/app/public \
  uv run pytest tests/lwe_structured_recovery/test_production_generator.py -q
```

Expected: FAIL because the production CLI is absent.

- [ ] **Step 3: Implement a fail-closed one-record CLI**

The CLI accepts exactly `--spec`, `--staging-dir`, and
`--alternative-search-seconds`. Parse the reviewed spec with strict duplicate
key/unknown-field rejection and construct the Phase 2 `GenerationTemplate`;
the spec has no `b`, secret/error seed, witness, digest, or calibration result.
Set its planned `analysis_path`, `calibration_status="unmeasured"`, empty model
ID, zero predicted runtime, and no measured runtime. Call Phase 2
`generate_production_instance(template=template)` with no caller-supplied
entropy. That API draws private entropy internally. Refuse an existing or
nonempty staging directory and refuse a destination under the tracked task
tree.

Only after every private-pipe check succeeds, atomically write
`<staging-dir>/generated.jsonl`, `<staging-dir>/generation-receipt.json`, and
`<staging-dir>/uniqueness.json`. The receipt contains exactly schema version,
instance ID/digest, generator revision, UTC time, named boolean checks, checker
revision, and
`private_material_disposition: "destroyed_after_pipe_crosscheck"`. It has no
record/output hash or private summary statistic. The CLI never accepts a seed
in production, never appends to `catalog.jsonl`, never prints private material,
and exits nonzero without leaving any of the three files if a check fails.

Use a short-lived subprocess per production instance. Send one length-bounded
canonical JSON object containing `public_record`, `private_secret`, and
`private_error` to `private_check.py` over stdin; close stdin immediately.
Redirect checker stderr to a fixed, witness-free error code and forbid echoing
input in exceptions. The checker independently verifies sample support and
exact weights, recomputes `b` using the independent native materializer,
checks `Instance.validate_secret`, and recomputes the public instance digest
and private summary statistics. The
generator process compares those results with its in-memory Phase 2
attestation. The attestation itself never crosses the pipe.

Before the pipe closes and the planted secret disappears, invoke the Phase 3
registered exact solver best suited to alternative-witness search with a
`SolveRequest` whose `exclude_secret` is the planted witness and whose limit is
`--alternative-search-seconds`. Return only the `UniquenessResult` fields
`status`, `accepted_count`, `search_complete`, `rank`, `kernel_dimension`,
`method`, elapsed time, and work units; never return the excluded or discovered
witness. Reject `known_multiple`; accept `proven_unique` or a budgeted
`no_second_witness_found` with its bound recorded. This ordering is mandatory
for hard cases: the alternative search occurs after `b` exists but before the
only known witness is destroyed. Later public rank/kernel checks must agree.
Use an OS temporary work directory outside the repository, disable resume, and
remove every checkpoint before returning the scrubbed result.

Checker stdout is exactly one size-bounded canonical JSON response with named
booleans and that scrubbed uniqueness result. The generator validates the
response schema, closes pipes, waits for both processes, and only then writes
staging artifacts. Drop mutable private
buffers before process exit; do not claim reliable erasure of immutable Python
objects—the security boundary is that the short-lived processes exit without
serializing them. The private
`GenerationAttestation` is never serialized or committed.

- [ ] **Step 4: Add failure-injection tests**

Independently inject a digest mismatch, failed planted-witness verdict,
support-check failure, native/Python materializer disagreement, alternate
witness found, checker crash/timeout/malformed stdout, oversized pipe input,
attempted seed argument, tracked/existing destination, and interrupted atomic
write. Each case must leave no generated record, receipt, or uniqueness file.
Run leak-audit assertions over every success/failure artifact and inspect
captured stdout/stderr for planted coordinates.

- [ ] **Step 5: Implement immutable staging and atomic admission**

`staging.py` exposes `validate_staged_candidate(staging_dir, slot, spec)`,
`finalize_linkage(staging_dir, summary, ladder_receipt)`, and
`build_instance_manifest(staging_dir, task_root)`, and
`admit_candidate(staging_dir, task_root)`. Validation loads the one-record
JSONL through `Catalog.load`, checks slot/family/error semantics, receipt and
uniqueness bindings, Python/native matrix equality, rank, reduction, duplicate
equivalence, and leak results. `finalize_linkage` may change only Phase 2's
digest-excluded fields: `analysis_path`, `calibration_status`,
`calibration_model_id`, `predicted_runtime_seconds`, and
`measured_runtime_seconds`; it must prove all generator-facing canonical bytes
and `instance_digest` are unchanged. It writes `final.jsonl` atomically with
the same exact one-record JSONL framing as `generated.jsonl`.

After analysis and both reviews are final, `build_instance_manifest` writes
exactly one canonical `instance-manifest.json` in staging with the schema from
Task 3. It resolves every planned canonical path against `task_root`, binds the
exact staged bytes that admission will publish, and rejects a missing,
unreferenced, or extra artifact.

`admit_candidate` first invokes the shared `audit_scope(...,
scope_kind="candidate")` against an overlay containing the candidate and all
current canonical artifacts. Under one
admission lock it prepares the final sorted catalog, merged review log,
`admitted` work event (binding the per-instance manifest), canonical artifact
copies, and catalog sidecar; only then does it compute the top-level manifest
against those final bytes. A write-ahead journal, same-filesystem temporary
files, `fsync`, atomic replacements, and rollback/recovery make the group a
single logical transaction. On any exception or injected interruption,
catalog, reviews, work events, per-instance manifests, and top-level manifest
retain their old logical state. Tests reject direct append, immutable-field edits, stale
linkage, duplicate IDs, partial copies, admission before both reviews, and a
manifest/catalog split-brain after injected replacement failure.

Provide matching `validate`, `finalize`, `manifest`, and `admit` CLI
subcommands. Every
path argument is resolved, must stay under either the declared staging root or
task root, and is passed to the same functions tested above; the CLI contains
no second implementation.

- [ ] **Step 6: Run and commit**

```bash
PYTHONPATH=2.0/problems/lwe_structured_recovery:2.0/problems/lwe_structured_recovery/harbor/app:2.0/problems/lwe_structured_recovery/harbor/app/public \
  uv run pytest tests/lwe_structured_recovery/test_production_generator.py tests/lwe_structured_recovery/test_staging.py -q
git add tests/lwe_structured_recovery/test_production_generator.py tests/lwe_structured_recovery/test_staging.py \
  2.0/problems/lwe_structured_recovery/harbor/app/tools/generator/generate_instance.py \
  2.0/problems/lwe_structured_recovery/harbor/app/tools/generator/private_check.py \
  2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/staging.py
git commit -m "feat: add secret-safe LWE production generator"
```

## Task 4: Record the reference platform and solver-gate crossing

**Files:**

- Create: `tests/lwe_structured_recovery/test_capture_hardware.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/capture_hardware.py`
- Create: `2.0/problems/lwe_structured_recovery/calibration/hardware.json`
- Verify: `2.0/problems/lwe_structured_recovery/calibration/FIRST_SOLVER_RUN.md`

- [ ] **Step 1: Test an allowlisted, non-sensitive capture**

Mock `platform`, `sysctl`, compiler, Python, fplll/fpylll, NumPy/SciPy, and
psutil responses. Assert `capture_manifest()` emits schema version, machine
class, CPU brand, architecture, physical/logical and performance/efficiency
core counts, memory ceiling, OS build/kernel, compiler and dependency
versions, timer (`time.monotonic_ns`), single-worker environment variables,
process affinity/QoS method, and UTC capture time. Assert recursively that no
key or value contains `serial`, `uuid`, `provision`, `hostname`, username, MAC
address, home path, or IP address. Unknown/missing allowlisted commands must
produce an explicit `unavailable` field and nonzero CLI status, never silently
reuse a hard-coded value.

- [ ] **Step 2: Implement and run capture on the reference machine**

`capture_hardware.py --output PATH` queries only an explicit command/key
allowlist, canonicalizes JSON, rereads it through its schema validator, and
refuses an existing output. `--verify-existing PATH` never rewrites it: it
requires canonical bytes, validates the recorded capture timestamp, and
compares every reproducibility-critical field with fresh allowlisted probes;
the historical timestamp itself is not expected to equal the verification
time. It must record the performance-core-targeting/QoS methodology and the
effective telemetry. Because macOS does not expose a guaranteed public hard
P-core affinity API, it must not claim pinning unless independently observed;
runs with background/E-core-class or thermal-pressure telemetry are rejected.
Run:

```bash
PYTHONPATH=2.0/problems/lwe_structured_recovery \
  uv run pytest tests/lwe_structured_recovery/test_capture_hardware.py -q
PYTHONPATH=2.0/problems/lwe_structured_recovery \
  uv run python 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/capture_hardware.py \
  --output 2.0/problems/lwe_structured_recovery/calibration/hardware.json
```

Expected: tests pass and the resulting manifest reports the observed Apple M5
MacBook Pro class, 4 performance + 6 efficiency cores, 16 GiB, arm64, and
Darwin 25.4.0 without any machine-unique identifier. If observation differs,
record the observation and update calibration claims; do not force these
expected values.

- [ ] **Step 3: Verify the captured calibration contract**

```json
{
  "schema_version": 1,
  "machine": "MacBook Pro Mac17,2",
  "processor": "Apple M5",
  "performance_cores": 4,
  "efficiency_cores": 6,
  "memory_bytes": 17179869184,
  "architecture": "arm64",
  "os_family": "macOS",
  "kernel": "Darwin 25.4.0",
  "max_solver_workers": 1,
  "max_solver_memory_bytes": 17179869184,
  "excluded_fields": ["serial_number", "hardware_uuid", "provisioning_id"]
}
```

Treat the JSON above as the expected initial observation, not source code.
Require `max_solver_workers == 1`, a memory ceiling no larger than observed
physical memory, all BLAS/OpenMP thread variables equal to `1`, and pinned
compiler/attack-tool versions before admitting a run.

- [ ] **Step 4: Verify the execution gate before starting a solver**

Run at or after 23:00 HKT:

```bash
date '+%Y-%m-%dT%H:%M:%S%z'
```

Expected: no earlier than `2026-07-10T23:00:00+0800`.

- [ ] **Step 5: Verify and bind the first permitted start**

Verify the `FIRST_SOLVER_RUN.md` created exactly once by the Phase 3
execution-gate helper. It must contain the observed HKT timestamp, solver name,
synthetic fixture ID, exact command, git commit, machine class, and a statement
that no solver was invoked before the gate. Cross-check that machine class
against `hardware.json`. It must not contain a
production secret, output hash, or answer hash. The current date is after the
historical gate, so preserve the actual first gated-run evidence; never
recreate it. Bind its file digest at the release-manifest top level.

- [ ] **Step 6: Commit the calibration platform record**

```bash
git add tests/lwe_structured_recovery/test_capture_hardware.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/capture_hardware.py 2.0/problems/lwe_structured_recovery/calibration/hardware.json
git commit -m "docs: record LWE calibration platform and gate"
```

## Tasks 5–14: Admit one approved family at a time

Each family task owns exactly twenty IDs. Within a family, process one ID at a
time; do not generate analysis prose in a loop. An ID enters
`catalog.jsonl` only after both current review records approve its exact
analysis digest.

| Task | Family | IDs | Setup command |
| --- | --- | --- | --- |
| 5 | `DS_BIN` | `lwe_0001`–`lwe_0020` | `export LWE_FAMILY=DS_BIN` |
| 6 | `DS_TER` | `lwe_0021`–`lwe_0040` | `export LWE_FAMILY=DS_TER` |
| 7 | `DS_SMALL` | `lwe_0041`–`lwe_0060` | `export LWE_FAMILY=DS_SMALL` |
| 8 | `SA_Q` | `lwe_0061`–`lwe_0080` | `export LWE_FAMILY=SA_Q` |
| 9 | `SA_SMALL` | `lwe_0081`–`lwe_0100` | `export LWE_FAMILY=SA_SMALL` |
| 10 | `DA_BIN` | `lwe_0101`–`lwe_0120` | `export LWE_FAMILY=DA_BIN` |
| 11 | `DA_TER` | `lwe_0121`–`lwe_0140` | `export LWE_FAMILY=DA_TER` |
| 12 | `MIX_Q_SPARSE` | `lwe_0141`–`lwe_0160` | `export LWE_FAMILY=MIX_Q_SPARSE` |
| 13 | `MIX_SMALL_SPARSE` | `lwe_0161`–`lwe_0180` | `export LWE_FAMILY=MIX_SMALL_SPARSE` |
| 14 | `MIX_DENSE_SMALL` | `lwe_0181`–`lwe_0200` | `export LWE_FAMILY=MIX_DENSE_SMALL` |

For every Task 5–14, perform these checked steps with the table's exact family
and range. Complete IDs in ascending order. Do not open the next ID until the
current ID reaches `authored`; reviewers likewise take one queued review at a
time. `work-events.jsonl` is the auditable record of this sequencing.

- [ ] **Step A: Select and review six easy parameter specs**

Select one parameter point for each `E0` through `E5`. Name a cited
exact-recovery attack before generating the instance. Use the slot's exact
`required_error_kind`, run `validate_family_contract`, and run every applicable
Phase 3 reduction screen. Every non-mixed single-structure candidate must
already have `passes_gate` for all applicable secret/matrix reductions; a
reviewer cannot waive a rejection or `requires_human_review` result.
Record a distinct cryptanalysis review of the parameter choice and append the
`selected` and `spec_reviewed` work events before generation.

- [ ] **Step B: Generate the six public easy instances**

Run `generate_instance.py` separately for each ID using fresh private entropy
and its reviewed public matrix seed. Verify the planted witness and alternate-
witness result inside the private checker, emit only the staged public record
and scrubbed artifacts, and destroy private generation material.
The concrete command is:

```bash
export LWE_TASK_ROOT=2.0/problems/lwe_structured_recovery
PYTHONPATH="$LWE_TASK_ROOT:$LWE_TASK_ROOT/harbor/app:$LWE_TASK_ROOT/harbor/app/public" \
  uv run python 2.0/problems/lwe_structured_recovery/harbor/app/tools/generator/generate_instance.py \
  --spec "2.0/problems/lwe_structured_recovery/harbor/app/public/specs/${INSTANCE_ID}.json" \
  --staging-dir "build/lwe-staging/${INSTANCE_ID}" \
  --alternative-search-seconds 60
```

Run it in a fresh process for each ID, then perform the independent public-only
audits and append `generated` then `instance_audited` work events. No batch
generation entry point, direct canonical-catalog write, or early artifact copy
is permitted.

- [ ] **Step C: Measure the easy ladder**

Use Phase 3's calibration runner in one-worker, performance-core-targeted and
QoS/telemetry-verified mode
and pass its summary to Phase 3's easy-admission function; Phase 4 implements
no threshold logic. The selected solver citation must resolve in Phase 3's
primary-source registry, be classified exact search, identify the exact
algorithm/section implemented, and match that solver's applicability record.
For a deterministic attack, provide at least three cold
successful runs and require **every** run to lie inside the assigned bin and
below 3600 seconds. For a randomized attack, provide at least ten independent
solver seeds, include censored runs, require empirical `T50` inside the bin and
`T90 < 3600`, and publish the bootstrap interval. Recheck each recovered
witness with the public facade and official evaluator, then delete plaintext
output. Reject and regenerate a parameter point that fails admission; do not
relabel it. The scrubbed run log is the only artifact retaining
`output_sha256` and must say `deleted_after_validation`.

- [ ] **Step D: Select and review fourteen hard parameter specs**

Use the immutable slot octaves. For each candidate, compute every applicable
pre-generation exact-search work formula and every applicable reduction gate.
Do not claim rank, kernel, duplicate equivalence, residual behavior, or
alternative-witness evidence before `b` is generated. Require a feasible
anchor/model plan for the assigned Phase 3 octave and a normal-LWE generic
fallback whenever no specialized interaction attack exists.

- [ ] **Step E: Generate and audit the fourteen hard instances**

Generate each record separately with fresh private entropy and perform the
bounded exclude-planted-witness search in `private_check.py` before destroying
the witness. After generation, run public digest, Python/native matrix,
information, rank/kernel, duplicate-equivalence, reduction, and leak checks;
compare public rank/kernel results with the scrubbed private-pipe uniqueness
record. Reject `known_multiple`, inconsistent evidence, a trivial row
permutation/scaling of an admitted record, or an obviously underdetermined
case before calibration.

- [ ] **Step F: Produce and admit Phase 3 evidence**

For the concrete generated record, write exactly one schema-valid artifact at
each of:

```text
build/lwe-staging/<id>/generation-receipt.json
build/lwe-staging/<id>/attack-estimates.json
build/lwe-staging/<id>/reduction-audit.json
build/lwe-staging/<id>/uniqueness.json
build/lwe-staging/<id>/calibration-summary.json
build/lwe-staging/<id>/ladder-receipt.json
build/lwe-staging/<id>/scrubbed-logs/<run-id>.json
```

These exact staging names map to the canonical calibration paths listed in the
file map only during atomic admission. The first six names are singleton
artifacts; `scrubbed-logs` contains every run ID referenced by the summary and
no unreferenced log.

Easy summaries reference their 3+ or 10+ scrubbed run IDs. Hard summaries
reference all anchor run IDs, the pinned model ID, held-out error, uncertainty
interval, interpolation/extrapolation class, phase-transition checks, and the
minimum over every credible exact attack. Invoke Phase 3's hard-admission
function and require its median prediction inside the immutable octave. Append
the `calibrated` event only after all six artifact digests are fixed. Finalize
the digest-excluded record linkage with:

```bash
PYTHONPATH="$LWE_TASK_ROOT:$LWE_TASK_ROOT/harbor/app:$LWE_TASK_ROOT/harbor/app/public" \
  uv run python "$LWE_TASK_ROOT/harbor/app/tools/corpus/staging.py" finalize \
  --staging-dir "build/lwe-staging/${INSTANCE_ID}" \
  --summary "build/lwe-staging/${INSTANCE_ID}/calibration-summary.json" \
  --ladder "build/lwe-staging/${INSTANCE_ID}/ladder-receipt.json"
```

- [ ] **Step G: Author twenty instance analyses one at a time**

For each exact ID, open its work item and write parameter-specific sections for structure and
predicate, primary exact attack, losing exact alternatives, non-qualifying
decision/refutation leads, reduction audit, measured/model evidence, ladder
justification, interaction analysis, uncertainty, optimization avenues, and
citations. Include eight or more stable claim IDs, current instance digest,
all six evidence paths/digests, author ID, and preallocated cryptanalysis and
reproducibility review IDs. Append `authored`, close that author's item, and
run the anti-boilerplate audit against all previously authored analyses before
opening the next ID. Write the draft to
`build/lwe-staging/<id>/analysis.md`; its metadata names the planned canonical
`harbor/app/analyses/<id>.md` path. Tools may check facts but may not generate
prose.

- [ ] **Step H: Run two independent reviews per analysis**

Assign a non-author cryptanalysis reviewer and a different reproducibility
reviewer. Each review binds current instance, analysis, and all six evidence
digests; names two or more checked claim IDs; records parameter-specific
findings/resolution; and either requests changes or approves. Append the two
review events. After any edit or evidence change, invalidate both approvals,
restart at `authored`, and repeat both reviews. Store current and historical
records in `build/lwe-staging/<id>/reviews.jsonl`; atomic admission merges them
into the canonical review log by immutable review ID.

- [ ] **Step I: Atomically admit each instance and audit the family**

Call the following separately for each fully approved ID; never append or copy
artifacts manually:

```bash
PYTHONPATH="$LWE_TASK_ROOT:$LWE_TASK_ROOT/harbor/app:$LWE_TASK_ROOT/harbor/app/public" \
  uv run python "$LWE_TASK_ROOT/harbor/app/tools/corpus/staging.py" manifest \
  --staging-dir "build/lwe-staging/${INSTANCE_ID}" \
  --task-root "$LWE_TASK_ROOT"
PYTHONPATH="$LWE_TASK_ROOT:$LWE_TASK_ROOT/harbor/app:$LWE_TASK_ROOT/harbor/app/public" \
  uv run python "$LWE_TASK_ROOT/harbor/app/tools/corpus/staging.py" admit \
  --staging-dir "build/lwe-staging/${INSTANCE_ID}" \
  --task-root "$LWE_TASK_ROOT"
```

It updates the sorted catalog, digest, and release manifest atomically and
appends `admitted`. After the twentieth ID, run:

```bash
uv run python 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/release_audit.py --family "$LWE_FAMILY"
```

Expected: twenty accepted IDs, six measured easy cases, fourteen hard cases,
forty current approvals, exact five-of-each error schedule, no leak/digest/
manifest/work-event/distinctness error, and the same per-instance checks as the
full audit.

- [ ] **Step J: Commit the reviewed family**

```bash
git add 2.0/problems/lwe_structured_recovery/harbor/app/public 2.0/problems/lwe_structured_recovery/harbor/app/analyses 2.0/problems/lwe_structured_recovery/calibration
git commit -m "data: add reviewed $LWE_FAMILY LWE instances"
```

Set `LWE_FAMILY` to the task table's exact code at the beginning of each
family task and record it in the durable plan log. The ten permitted values are
`DS_BIN`, `DS_TER`, `DS_SMALL`, `SA_Q`, `SA_SMALL`, `DA_BIN`,
`DA_TER`, `MIX_Q_SPARSE`, `MIX_SMALL_SPARSE`, and
`MIX_DENSE_SMALL`.

## Task 15: Complete task-facing documentation

**Files:**

- Create: `2.0/problems/lwe_structured_recovery/harbor/app/LITERATURE.md`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/public/format.md`
- Create: `2.0/problems/lwe_structured_recovery/DESIGN.md`
- Modify: `2.0/problems/lwe_structured_recovery/readme`
- Modify: `2.0/README.md`

- [ ] **Step 1: Write the public literature map**

Cover every attack and reduction used by the 200 analyses. Correct the dense
binary-matrix reduction omission without modifying the user's root
`LWE-literature.md`. Cite primary paper URLs, exact theorem/algorithm
locations, and decision-versus-search status.

Write `public/format.md` alongside it with every catalog field, canonical JSONL
rules, the instance-digest exclusion set, SHAKE/native golden vectors, matrix
row/block expansion pseudocode, canonical modular representatives, and all
secret/error sampling and verification predicates. Document the exact loader
paths: an agent imports from `/app/public`; the judge resolves
`FRONTIER_PUBLIC_DIR=/judge/public`; a source checkout falls back to
`harbor/app/public`; only tests may use `FCS_STRUCTURED_LWE_CATALOG` to select a
synthetic catalog. No production path may silently load `catalog.synthetic.json`.

- [ ] **Step 2: Finalize the task statement**

Document the public catalog, matrix materialization, secret and error
predicates, JSON ledger, equal scoring, 8-core/32-GiB/no-GPU budget, local
helpers, cumulative submission commands, per-instance analysis locations, and
the release-manifest/catalog digests. Include this exact instruction:

> Whenever you recover a new valid secret, merge it into
> `/app/solution.json`, submit immediately with `bash /app/submit.sh`, and
> continue attacking the remaining instances.

- [ ] **Step 3: Add the task to the 2.0 index**

Add one concise `lwe_structured_recovery` entry to `2.0/README.md` describing
the public 200-instance exact-recovery objective and secretless validation.

- [ ] **Step 4: Run documentation checks**

Run:

```bash
rg -n 'TBD|TODO|FIXME' 2.0/problems/lwe_structured_recovery
uv run python 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/release_audit.py
```

Expected: the search returns no unresolved marker and release audit succeeds.

- [ ] **Step 5: Commit task documentation**

```bash
git add 2.0/problems/lwe_structured_recovery/readme 2.0/problems/lwe_structured_recovery/DESIGN.md 2.0/problems/lwe_structured_recovery/harbor/app/LITERATURE.md 2.0/problems/lwe_structured_recovery/harbor/app/public/format.md 2.0/README.md
git commit -m "docs: document structured LWE recovery task"
```

## Task 16: Run full repository and FCS verification

**Files:**

- Create: `tests/lwe_structured_recovery/test_harbor_package.py`
- Create: `2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/verify_harbor_package.py`
- Create: `2.0/problems/lwe_structured_recovery/AUDIT_REPORT.md`

- [ ] **Step 1: Run focused and root tests**

```bash
uv run pytest tests/lwe_structured_recovery -q
uv run pytest -q
```

Expected: all tests pass.

The focused suite must include the Harbor package verifier with a synthetic
generated-tree fixture. It rejects changed/missing public bytes, a judge copy
of all `harbor_app`, a judge reference to `tools` or `analyses`, a missing
`FRONTIER_PUBLIC_DIR`, and any calibration/private artifact placed under the
shared `public` subtree.

- [ ] **Step 2: Compile and evaluate the empty reference**

```bash
PYTHONPYCACHEPREFIX=/private/tmp/frontier-cs-pycache python3 -m py_compile 2.0/problems/lwe_structured_recovery/evaluator.py
PYTHONPATH=2.0/problems/lwe_structured_recovery/harbor/app/public \
  python3 2.0/problems/lwe_structured_recovery/evaluator.py 2.0/problems/lwe_structured_recovery/reference.json
```

Expected: successful zero score, zero solved instances, and no traceback.

- [ ] **Step 3: Run Frontier-CS discovery and validation**

```bash
uv run frontier list 2.0
uv run frontier show 2.0 lwe_structured_recovery
uv run python scripts/validate_problems.py --track 2.0 --problems lwe_structured_recovery --verbose
```

Expected: the task is listed and reference validation succeeds.

- [ ] **Step 4: Generate the Harbor task**

```bash
PYTHONPATH=adapters/frontier-cs-2.0/src uv run --no-sync python -m frontier_cs_2_0.main --source "$PWD" --output-dir /private/tmp/frontier-cs-2-lwe --task-ids lwe_structured_recovery --overwrite
```

Expected: one task generated. The agent and judge build contexts contain
one staged `harbor_app` tree for the agent image. The judge Dockerfile copies
only its `public` child; tools and analyses remain in the shared Docker build
context but are not copied into the judge image.

- [ ] **Step 5: Verify exact generated packaging and loader paths**

Run:

```bash
PYTHONPATH=2.0/problems/lwe_structured_recovery:2.0/problems/lwe_structured_recovery/harbor/app/public \
  uv run python 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/verify_harbor_package.py \
  --task-root 2.0/problems/lwe_structured_recovery \
  --generated-root /private/tmp/frontier-cs-2-lwe \
  --build-images
```

The verifier locates exactly one generated task with ID
`lwe_structured_recovery`; compares the relative-path/SHA-256 map of source
`harbor/app/public` with generated `environment/harbor_app/public`; requires
agent `COPY harbor_app/ /app/`; requires judge
`COPY harbor_app/public/ /judge/public/` and
`ENV FRONTIER_PUBLIC_DIR=/judge/public`; rejects a judge `COPY harbor_app/`,
or any judge reference to `tools`, `analyses`, or `calibration`; and rejects
private/staging/solution/checkpoint files under the shared public subtree.
Then point `FRONTIER_PUBLIC_DIR` at the generated public directory and call
the generated evaluator's `prepare()`; require 200 instances and the same
catalog ID as source. Expected: `harbor package audit: clean`.

With `--build-images`, build the generated agent and judge Dockerfiles, then
inspect fresh containers rather than trusting Dockerfile text alone. Require
the agent image to import NumPy, SciPy, fpylll, cysignals, and psutil and to
report the pinned versions; require the judge image to import the public
evaluator modules, run `prepare()`, and contain a byte-identical `/judge/public`
tree. Assert `/judge/tools`, `/judge/analyses`, `/judge/calibration`, and any
private/staging/checkpoint path are absent. Bind both resulting image IDs and
version output in `AUDIT_REPORT.md`.

Also build Phase 3's digest-pinned
`analysis_tools/docker/Dockerfile`, run its lock-verification command, import
the official Lattice Estimator at the recorded immutable commit, validate a
recorded tiny raw-output fixture, and emit the Sage/Python/dependency/license
version manifest. Record the analysis-image content digest in the audit report;
this image is a research/calibration tool and is never copied into the judge.

- [ ] **Step 6: Run the Harbor smoke trial**

```bash
uv run frontier harbor trial 2.0 lwe_structured_recovery -a codex -m gpt-5 --agent-timeout 600 --verifier-timeout 600 --force-build --json
```

Expected: judge readiness succeeds and a syntactically valid ledger receives a
numeric score. A model-access failure is recorded as an external smoke blocker,
not disguised as task verification.

- [ ] **Step 7: Write the audit report**

Record every command, relevant version/digest, test count, release-audit
summary, release-manifest digest, reference result, generated task path,
package-verifier result, and Harbor result. Include known model uncertainty
without weakening any corpus gate.

- [ ] **Step 8: Commit final evidence**

```bash
git add tests/lwe_structured_recovery/test_harbor_package.py 2.0/problems/lwe_structured_recovery/harbor/app/tools/corpus/verify_harbor_package.py 2.0/problems/lwe_structured_recovery/AUDIT_REPORT.md
git commit -m "test: record structured LWE release verification"
```
