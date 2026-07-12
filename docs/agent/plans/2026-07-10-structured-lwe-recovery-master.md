# Structured LWE Recovery Master Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` (recommended) or `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the approved 200-instance `lwe_structured_recovery` Frontier-CS 2.0 task, including its secretless evaluator, public corpus, reference attacks, calibration evidence, instance-wise cryptanalysis, reviews, and Harbor integration.

**Architecture:** Four plans form a strict dependency chain. Phase 1 adds generic JSON and judge-visible public-asset support. Phase 2 builds the task's public arithmetic, generator, evaluator, ledger, and synthetic tests. Phase 3 adds exact-recovery solvers, reduction audits, runtime calibration, and ladder assignment. Phase 4 curates, generates, analyzes, independently reviews, and packages the 200 production instances before final repository and Harbor verification.

**Tech Stack:** Python 3.11+, SHAKE-256, canonical JSON/JSONL, NumPy for agent-side attacks, fplll/fpylll or command-line fplll for lattice attacks, pytest, Frontier-CS 2.0, and Harbor.

---

## Source of truth

The approved specification is
`docs/agent/specs/2026-07-10-structured-lwe-recovery-design.md`.
If a plan and the specification disagree, stop that slice and correct the plan
before implementation. Do not silently weaken the 200-instance count,
60/140 split, ten-family balance, easy ladder, hard ladder, reduction gates, or
instance-wise review requirements.

The untracked root file `LWE-literature.md` belongs to the user. Preserve it
unchanged. Add task-local literature files instead.

## Execution gate

No command that starts a reference attack, recovery solver, calibration run, or
production-instance solution attempt may run before
`2026-07-10T23:00:00+08:00`. Code authoring, compilation, static schema
validation, unit tests that do not solve an LWE fixture, and planning may run
before the gate.

The implementation must add a machine-enforced gate before the first solver is
run. The first permitted run must record its HKT timestamp in the durable
execution log.

## Plan dependency map

```text
Phase 1: FCS JSON + public assets
    |
    v
Phase 2: task core + secretless evaluator + generator primitives
    |
    v
Phase 3: exact solvers + audits + calibration + ladder machinery
    |
    v
Phase 4: 200-instance curation + analyses + reviews + release integration
```

The executable phase plans are:

1. `docs/agent/plans/2026-07-10-structured-lwe-phase1-infrastructure.md`
2. `docs/agent/plans/2026-07-10-structured-lwe-phase2-core.md`
3. `docs/agent/plans/2026-07-10-structured-lwe-phase3-solvers-calibration.md`
4. `docs/agent/plans/2026-07-10-structured-lwe-phase4-corpus-integration.md`

## Execution waves and research stop conditions

Implementation proceeds in evidence-producing waves rather than generating
200 points up front:

1. finish and review generic FCS/JSON/public-asset infrastructure;
2. finish the secretless arithmetic/generator/evaluator core and adversarial
   synthetic tests;
3. implement every registered exact solver, theorem audit, Estimator wrapper,
   calibration statistic, and release schema, then validate on synthetic data;
4. run a ten-instance pilot (one candidate per family) through generation,
   exact-attack estimates, reduction gates, calibration, analysis, both
   reviews, and release audit;
5. admit the six easy bins family-by-family, replacing any point that misses
   its measured bin rather than relabeling it;
6. fit and cross-validate attack-regime models, then admit the fourteen hard
   slots per family only within the approved interpolation/extrapolation
   limits; and
7. complete the digest-bound corpus, final multi-review, generated-image tests,
   and Harbor smoke.

Stop and revise parameters or machinery whenever a theorem gate applies, an
exact attack absent from the current model is faster, a measured point misses
its bin, an uncertainty interval violates admission limits, a family lacks the
required error diversity, a review finds generic boilerplate, or a release
digest/leak check fails. No quota is filled by weakening a gate.

## File ownership

| Phase | Exclusive write scope |
| --- | --- |
| 1 | `src/frontier_cs/config.py`, adapter templates/code/docs, and generic adapter/config tests |
| 2 | task scaffold, `harbor/app/public/lwe_challenge/`, evaluator, ledger/generator core, and core task tests |
| 3 | solver, audit, estimator, calibration, ladder, and leak-audit code plus their tests |
| 4 | production specs/catalog, calibration artifacts, 200 analyses, review manifest, task docs/audit report, README registration, and release checks |

No two implementers may edit the same file concurrently. Phase 4 may use many
parallel authors and reviewers only after assigning disjoint instance IDs.
The sole sequential shared-file exception is task-local `tests/conftest.py`:
Phase 2 creates core path/fixture plumbing, then Phase 3 extends it with gated
solver fixtures after Phase 2 review is complete.

## Requirements traceability

| Approved design requirement | Owning plan tasks | Required evidence |
| --- | --- | --- |
| Ten non-standard families; exact 200/60/140 balance and both logarithmic ladders | Phase 3 Task 12; Phase 4 Tasks 1 and 5–14 | immutable slots plus full/family release audits |
| General `n,m,q`, four error distributions, matrix/secret sparsity and alphabets | Phase 2 Tasks 3, 5, 9; Phase 4 Tasks 5–14 | strict public specs/catalog and family/error semantic audit |
| Named one-core runtime unit, measured easy points, censor-aware modeled hard points | Phase 3 Tasks 10–12; Phase 4 Task 4 and Tasks 5–14 | hardware/tool manifest, scrubbed runs, models, summaries |
| Brakerski–Döttling, sparse-LWE, dense-binary, and other reduction exclusions | Phase 3 Task 8; Phase 4 Tasks 5–14 | theorem-input records, numerical margins, fail-closed verdicts |
| Mixed structures always scored; normal-LWE fallback when no interaction estimate exists | Phase 3 Tasks 7–8; Phase 4 Tasks 12–14 | attack inventory and non-composition/fallback fields per ID |
| Canonical seeded matrices, secretless public generation, private cross-check | Phase 2 Tasks 3–5 and 9; Phase 4 Task 3B | Python/native vectors, ephemeral pipe check, scrubbed receipt |
| Any-valid-witness evaluator and cumulative immediate submissions | Phase 2 Tasks 5–8 and 10–12 | adversarial evaluator tests, ledger helper, task readme |
| Clean-room exact-recovery portfolio and pinned generic Lattice Estimator | Phase 3 Tasks 1–7 and 14 | source registry, dependency images, synthetic recoveries, raw estimator records |
| Separately authored cryptanalysis and two independent reviews per instance | Phase 4 Task 2 and Tasks 5–14 | append-only work ledger, analysis lint/similarity audit, 400 digest-bound reviews |
| FCS JSON/public-assets support and secretless judge packaging | Phase 1 Tasks 1–8; Phase 4 Task 16 | generic regressions, generated-context byte/absence checks, Harbor smoke |
| Complete release integrity and no answer material | Phase 3 Task 13; Phase 4 Tasks 3 and 16 | per-instance release manifests, leak audit, final audit report |

## Durable execution protocol

- [ ] **Step 1: Confirm the feature branch and clean staged state**

Run:

```bash
git branch --show-current
git status --short
```

Expected: branch `feat/lwe-structured-recovery`; the only pre-existing
untracked user file is `LWE-literature.md`, plus plan files currently being
authored.

- [ ] **Step 2: Create the live execution tracker**

Use the session plan tracker with exactly one in-progress phase. Treat every
phase plan as a durable execution log: check completed boxes and add an
`Observed:` line containing actual tests, review fixes, and deviations.

- [ ] **Step 3: Execute and review Phase 1**

Complete every checkbox in the Phase 1 plan. Run its targeted tests and a
combined spec/quality review. Do not begin Phase 2 until Phase 1's generated
Dockerfile test proves public assets reach the judge and tasks without public
assets remain unchanged.

- [ ] **Step 4: Execute and review Phase 2**

Complete every checkbox in the Phase 2 plan. Before 23:00 HKT, skip any test
that invokes an LWE recovery algorithm; record the skip as gate-enforced rather
than passed. Static PRG, schema, verifier, parser, and evaluator tests may run.

- [ ] **Step 5: Execute the static portion of Phase 3**

Implement solver code, audit formulas, schemas, calibration logging, and gate
tests without launching a solver. Confirm the early path only through an
injected-clock unit test; do not invoke the solver CLI before the user's gate.
The tested public message is
`solver execution is disabled until 2026-07-10T23:00:00+08:00`.

- [ ] **Step 6: Cross the solver gate explicitly**

At or after 23:00 HKT, run:

```bash
date '+%Y-%m-%dT%H:%M:%S%z'
```

Expected: a timestamp no earlier than `2026-07-10T23:00:00+0800`.
Record it in
`2.0/problems/lwe_structured_recovery/calibration/FIRST_SOLVER_RUN.md`
before starting the first recovery test.

- [ ] **Step 7: Finish and review Phase 3**

Run synthetic solver recovery tests, calibration smoke runs, estimator/audit
tests, and ladder-assignment tests. Complete spec and quality reviews for each
solver/audit slice before Phase 4 uses it.

- [ ] **Step 8: Execute Phase 4 as a rolling corpus pipeline**

Curate and review instances family by family. A candidate cannot enter the
canonical catalog until its parameter spec, public generation receipt,
reduction audit, attack estimates, calibration placement, authored analysis,
and two review records all pass release audit.

- [ ] **Step 9: Run the complete local verification matrix**

Run the exact commands listed at the end of Phase 4. Expected: all root and
task tests pass; the reference scores zero successfully; the generated Harbor
task contains byte-identical public assets on agent and judge sides; the corpus
has exactly 200 accepted records with the required ladders.

- [ ] **Step 10: Dispatch final combined review**

Run independent final reviews for cryptanalytic correctness, security/data
leakage, architecture/maintainability, and tests/documentation. Route every
finding through an owned fix slice and repeat the relevant review.

- [ ] **Step 11: Record the Harbor smoke trial**

Generate the Harbor task and run one smoke trial with the empty reference or a
synthetic test ledger. Do not put a production witness in the smoke artifact.
Record the command, task digest, result path, bounded score, and judge readiness
result in `2.0/problems/lwe_structured_recovery/AUDIT_REPORT.md`.

- [ ] **Step 12: Finish the development branch**

Use the `finishing-a-development-branch` workflow after all acceptance
criteria pass. Present the user with the complete verification evidence and
the safe PR/merge options. Do not merge or push without explicit authorization.

## Completion gate

The master plan is complete only when all four phase plans are checked off and
the release audit proves:

- 200 instances, 20 per approved family;
- 60 measured paper cases, ten in each easy bin and one per family per bin;
- 140 modeled cases, fourteen per hard octave and fourteen per family;
- every deterministic easy case has three cold runs inside its bin; every
  randomized easy case has at least ten seeds, in-bin T50, and T90 below one
  hour;
- every hard case uses the joint minimum over all applicable exact-search
  attacks, publishes censor-aware uncertainty, and passes interpolation/
  extrapolation admission limits;
- no scored standard-LWE instance;
- no prohibited single-structure hardness-reduction case;
- theorem-specific reduction inputs, assumed base instances, numerical
  margins, and fail-closed verdicts for every applicable reduction;
- exact immutable slot/family/tier/bin semantics and at least three error
  distributions per family, with all four error families represented in both
  easy and hard cohorts globally;
- no production witness, secret seed, error seed, or reusable answer hash;
  the only permitted witness-derived digest is `output_sha256` inside a
  scrubbed calibration log whose plaintext output was deleted;
- 200 individually authored analyses with instance-specific machine facts and
  anti-boilerplate checks;
- 400 current independent review records, two distinct non-author reviewers
  per analysis;
- a per-instance release manifest binding slot, parameter spec, public record,
  scrubbed generation receipt, attack estimates, reduction audit, uniqueness
  evidence, calibration runs/model/summary, analysis, and reviews;
- a secretless evaluator that accepts alternative witnesses;
- production catalog sidecar/count/digest integrity fails preparation rather
  than scoring the agent zero;
- equal-count scoring;
- reproducible Harbor-agent and Sage-analysis environments with pinned source,
  dependency, version, and license manifests;
- passing unit, adversarial, corpus, adapter, CLI, and Harbor generation tests;
  and
- a recorded Harbor smoke result.
