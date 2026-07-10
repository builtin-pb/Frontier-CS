# Structured LWE Recovery Benchmark Design

**Date:** 2026-07-10

**Status:** Approved

**Proposed Frontier-CS 2.0 problem id:** `lwe_structured_recovery`

## 1. Goal

Add a self-contained Frontier-CS 2.0 cryptanalysis task in which an agent
recovers valid secrets for as many as possible of 200 fixed, public, structured
Learning With Errors instances. The evaluator stores no planted secret or
error. It accepts any submitted secret that satisfies the instance's public
secret constraints and whose centered modular residual satisfies the public
error predicate.

The benchmark must provide:

- ten non-standard LWE families covering matrix sparsity, matrix alphabets,
  secret sparsity, secret alphabets, and combinations of those structures;
- variation in dimension, sample count, modulus, and error distribution;
- exactly 60 paper-backed exact-recovery cases measured below one reference
  core-hour, with their own smooth logarithmic difficulty ladder;
- exactly 140 further cases distributed uniformly across ten logarithmic
  runtime octaves from one through 1024 reference core-hours;
- public generators, materializers, parameters, reference attack
  implementations, calibration evidence, and instance-by-instance
  cryptanalysis;
- a cumulative JSON submission workflow that encourages the agent to submit
  every newly recovered secret immediately; and
- a PR-ready FCS-2.0 integration with automated tests and a Harbor smoke path.

Ordinary standard LWE is not a scored family. When no structure-specific
recovery attack is known, a calibrated generic LWE attack is used only as the
upper-bound estimate.

## 2. Non-goals

The task does not:

- hide instances or use a private test set;
- compare a candidate to a stored planted answer;
- count decision or refutation results as secret recovery;
- claim that Lattice Estimator operation counts are measured runtimes;
- copy non-compatible third-party attack implementations;
- award more score merely because an instance was predicted to be harder; or
- admit a single-structure instance whose applicable reduction gives it a
  meaningful standard-LWE hardness guarantee in the selected regime.

## 3. Benchmark Population

### 3.1 Structural families

There are exactly 20 instances in each of the following ten families.

| Code | Matrix distribution | Secret distribution | Primary structure |
| --- | --- | --- | --- |
| `DS_BIN` | Dense uniform over Z_q | Exact-weight binary | Secret sparsity and binary alphabet |
| `DS_TER` | Dense uniform over Z_q | Exact-weight signed ternary | Secret sparsity and ternary alphabet |
| `DS_SMALL` | Dense uniform over Z_q | Dense binary, ternary, or centered-binomial | Dense small secret |
| `SA_Q` | Exact-k row-sparse, nonzeros uniform in Z_q* | Uniform over Z_q | Matrix sparsity |
| `SA_SMALL` | Exact-k row-sparse, nonzeros in {1} or {-1,1} | Uniform over Z_q | Matrix sparsity and small nonzero alphabet |
| `DA_BIN` | Dense entries in {0,1} over a larger q | Uniform over Z_q | Dense binary matrix |
| `DA_TER` | Dense entries in {-1,0,1} over a larger q | Uniform over Z_q | Dense ternary matrix |
| `MIX_Q_SPARSE` | Exact-k row-sparse with q-ary nonzeros | Exact-weight binary or signed ternary | Sparse matrix and sparse secret |
| `MIX_SMALL_SPARSE` | Exact-k row-sparse with small nonzeros | Exact-weight small secret | Sparse small matrix and sparse small secret |
| `MIX_DENSE_SMALL` | Dense binary or ternary | Dense or exact-weight small secret | Dense small matrix and small secret |

Every family contains six measured paper cases and fourteen modeled ladder
cases. Every scored instance has at least one non-standard matrix or secret
distribution.

### 3.2 General-parameter and error coverage

Within every family, instances vary `n`, `m`, and `q`. Most moduli are odd
primes so centered reduction and rank checks are unambiguous. Composite moduli
may be used only when the per-instance analysis deliberately studies their
effect and audits every prime-power factor.

The corpus uses four bounded error families:

1. truncated discrete Gaussian;
2. centered binomial;
3. bounded centered uniform; and
4. sparse bounded error.

The sampling distribution and the verifier predicate are separate public
fields. A predicate may combine a coordinate bound, a squared Euclidean-norm
bound, and an error Hamming-weight bound. Each family uses at least three error
families, and all four occur across both the measured and modeled portions of
the corpus.

### 3.3 Sub-hour ladder

The 60 paper cases form a difficulty ladder rather than a flat easy tranche.
There is exactly one instance from every structural family in each of these six
single-core runtime bins:

| Bin | Measured T50 |
| --- | --- |
| `E0` | [1, 4) seconds |
| `E1` | [4, 16) seconds |
| `E2` | [16, 64) seconds |
| `E3` | [64, 256) seconds |
| `E4` | [256, 1024) seconds |
| `E5` | [1024, 3600) seconds |

For bin `r` with endpoints `L` and `U`, family `f` receives the
geometric target

`L * (U/L)^(((f+r) mod 10 + 0.5) / 10)`.

The target orders families differently in adjacent bins. Admission is based on
the observed interval, not proximity to the point target.

Every easy instance cites a published exact-recovery algorithm and has a
complete measured run. A generic primal, hybrid, BKW, or algebraic algorithm
from the literature may qualify on a structured instance when no specialized
attack exists. Decision and refutation algorithms do not qualify.

### 3.4 One-to-1024-hour ladder

The remaining 140 instances occupy ten runtime octaves:

`H0=[1,2), H1=[2,4), ..., H9=[512,1024)` core-hours.

Every octave contains exactly fourteen instances. Every family contains
fourteen hard-ladder instances and occurs either once or twice in every octave.
A deterministic cyclic assignment balances the family counts:

- the first ten hard instances of family `f` go to octaves
  `(f+j) mod 10` for `j=0..9`;
- its final four go to `(f+j) mod 10` for `j=0..3`.

Within octave `k`, the fourteen point targets are

`2^(k + (j + 0.5)/14)` core-hours for `j=0..13`.

Admission requires the predicted median time to lie in the assigned octave.
Uncertainty and extrapolation distance are published and do not affect score.

## 4. Runtime Definition and Calibration

### 4.1 Reference unit

A runtime hour is one hour of a single attack worker on one performance core of
a named consumer processor. The initial calibration platform is an Apple M5
consumer CPU with a 16 GiB memory ceiling. The final calibration manifest pins
the exact machine class, operating-system build, compiler, attack-tool
versions, command line, thread settings, and timing method.

Only one computational worker is permitted. OpenMP, BLAS, and similar library
thread counts are set to one. Dependency installation is excluded; parsing,
preprocessing, lattice reduction, search, verification, and checkpoint I/O are
included.

The primary statistic is wall-clock time to the first evaluator-accepted
witness. CPU time and peak resident memory are also recorded. The manifest
records enough scheduler and quality-of-service information to distinguish
performance-core runs on heterogeneous processors.

### 4.2 Solver execution gate

No reference attack, recovery solver, calibration run, or production-instance
solution attempt may start before 2026-07-10 23:00 HKT (UTC+8). Specification,
planning, static inspection, code authoring, and tests that do not execute a
recovery solution may proceed before that time. The implementation log records
the start time of the first permitted solver execution.

### 4.3 Measured paper cases

Deterministic attacks receive at least three cold runs. All three must finish
within the assigned easy bin and below 3600 seconds.

Randomized attacks receive at least ten independent solver seeds. Their median
time `T50` must lie in the assigned bin, their empirical `T90` must be below
3600 seconds, and their bootstrap confidence interval is published. Censored
failures are included in the distribution rather than discarded.

Every resulting witness is rechecked by both the public checker and the
official evaluator. Public logs are scrubbed of the witness itself and retain
the command, seed, timings, peak memory, exit state, and canonical output hash.

### 4.4 Modeled ladder cases

For every applicable exact-recovery attack:

1. measure smaller anchors on the reference platform;
2. compute the paper or estimator work factor for those anchors;
3. fit a robust log-runtime calibration with family- and regime-specific
   constants;
4. validate on held-out parameter slices;
5. propagate model, residual, and randomized-success uncertainty; and
6. predict time and memory for the candidate.

The instance runtime is the predicted distribution of the minimum over all
applicable exact-recovery attacks. A convenient attack is not selected while a
faster credible attack is ignored.

Extrapolation may not cross an identified phase change such as a new optimal
BKZ block size, a meet-in-the-middle memory transition, a dense-minor
availability threshold, or a graph connectivity threshold without new
anchors. Each estimate is labeled `measured`, `interpolated`, or
`extrapolated`. Predictions are reported as intervals, not false-precision
point claims.

Lattice Estimator is pinned by commit. Its operation counts are calibrated
against the task's actual generic primal implementation and remain heuristic
upper bounds. Where a structure-specific attack is unavailable, the calibrated
generic LWE estimate is the required fallback.

## 5. Hardness-Reduction Admission Gates

Every instance analysis inventories all known relevant reductions, not only
the two guardrails named in the task request.

### 5.1 Secret-only cases

For each secret-only instance, compute:

- exact min-entropy;
- maximum Euclidean radius;
- noise-lossiness inputs;
- the selected base decision-LWE parameters;
- the general entropic-LWE sufficient-hardness threshold;
- the ball-bounded threshold; and
- the concrete mapping and slack terms.

The instance is rejected when the Brakerski-Döttling theorem or another
small-secret reduction applies to an assumed-hard base LWE regime. An instance
may remain only when the theorem conditions fail or the mapped base problem has
a documented recovery upper bound inside the benchmark ceiling. The analysis
records a numerical margin rather than a bare yes/no assertion.

### 5.2 Matrix-sparsity-only cases

For each matrix-sparsity-only instance, check:

- exact versus at-most-k support;
- support distribution;
- the distribution and unit status of nonzero coefficients;
- uniformity of the secret;
- modulus and noise hypotheses;
- sample preservation;
- the relation between k and the ambient dimension;
- the mapped dense dimension; and
- every parameter relation in the applicable dense-to-sparse theorem.

The instance is rejected when the Bangachev-Bresler-Tiegel-Vaikuntanathan
reduction or another sparse-LWE reduction gives a meaningful standard-LWE
hardness guarantee in the selected regime. Increasing the sample count is not
treated as an escape from a theorem that preserves samples.

### 5.3 Other matrix and secret reductions

Dense binary matrices receive the applicable
Boneh-Lewi-Montgomery-Raghunathan check, including its modulus-near-a-power-of-
two and dimension-expansion conditions. Dense and sparse binary or ternary
secrets receive all applicable binary-secret, sparse-secret, and hybrid
reduction checks. A task-local literature index records the exact sources and
which families they govern.

### 5.4 Mixed structure

Mixed matrix/secret families are mandatory. Their analysis first models
interaction attacks such as row filtering, graph peeling, support pruning,
dense minors on surviving coordinates, and geometric or greedy recovery.

The single-structure reductions are recorded as diagnostics but are not claimed
to compose without a proof. If no interaction-specific speedup is known, the
calibrated generic LWE recovery estimate is used. The instance remains part of
the main benchmark, not a separate experimental score.

## 6. Public Instance and Generator Format

### 6.1 Canonical public record

The public catalog is canonical JSON Lines. Every record contains:

- schema and generator versions;
- instance id, family, class, and runtime bin;
- `n`, `m`, and `q`;
- matrix distribution, public matrix seed, and expansion domain;
- explicit public vector `b`;
- secret distribution and verifier constraints;
- error sampling distribution and verifier predicate;
- an instance digest over the canonical generator-facing fields, excluding
  digest and analysis-linkage fields;
- cryptanalysis path; and
- calibration status and model identifier.

The catalog has a top-level digest file. The instance analysis cites the
instance digest. A separate review manifest cites the completed analysis file's
digest and records reviewer verdicts. This one-way chain avoids circular or
self-referential hashes. Records and vectors use canonical integer
representatives. The public materializer provides row, block, and full matrix
APIs so attacks need not allocate a full dense matrix.

### 6.2 Deterministic matrix materialization

Matrix entries are derived from SHAKE-256 using:

- a versioned domain string;
- the public 256-bit matrix seed;
- explicit row and stream identifiers;
- fixed little-endian integer encoding; and
- rejection sampling rather than biased modular reduction.

Sparse rows sample an exact support without replacement, then sample their
nonzero values from the declared alphabet. Test vectors cover every matrix
distribution in two independent implementations.

### 6.3 Production generation

The generator consumes one individually reviewed public parameter
specification and independent private entropy. Matrix randomness is public.
Secret and error randomness use separate private domain-separated streams.

Generation performs distribution checks, computes `b=A*s+e mod q`, verifies
the planted witness against the public predicate, writes only the public
record, and emits a private generation attestation. Production secret/error
seeds and plaintext witnesses are never committed or passed to the evaluator.

The public generator can create new instances from fresh private entropy.
Synthetic deterministic secret/error seeds exist only in tests and use
unmistakable non-production domains.

## 7. Evaluator and Submission Contract

### 7.1 Submission schema

The final artifact is `/app/solution.json`:

```json
{
  "schema_version": 1,
  "solutions": [
    {"instance_id": "lwe_0001", "secret": [0, 1, 0]}
  ]
}
```

Entries must be cumulative. The judge does not union separate submissions; the
agent-side helper atomically merges a new witness into the current ledger
before invoking `submit.sh`.

### 7.2 Validation

For each unique entry, the evaluator:

1. resolves a known instance id;
2. checks the exact vector length;
3. rejects booleans, floats, strings, and oversized integers;
4. checks canonical representatives, alphabet, and exact or maximum weight;
5. reconstructs the required rows of `A`;
6. computes `r = centered(b - A*s mod q)`; and
7. checks every public residual predicate.

The evaluator stores no planted secret, error, secret hash, or answer seed.
Any vector satisfying the public constraints is valid.

The parser rejects duplicate JSON keys, duplicate instance ids, unknown schema
versions, excessive nesting, more than 200 entries, and files above the
task-specific size cap. A malformed top level scores zero. An invalid
individual witness does not erase other valid witnesses.

Catalog corruption is an infrastructure failure detected during judge
preparation, not an invalid agent answer. Agent-visible failures are concise
and never include raw tracebacks, evaluator paths, or submitted output.

### 7.3 Scoring

Each valid distinct instance is worth 0.5 bounded-score points:

`score = 100 * solved_count / 200`.

`score_unbounded` is the raw solved count. Secondary public metrics report
paper and hard-ladder counts, counts by family and octave, the hardest solved
octave, and a capped list of invalid ids and public reasons. Predicted
difficulty never changes primary reward.

## 8. Reference Attacks and Agent Workflow

The public workspace includes clean-room, cited implementations of:

- primal embedding and bounded-distance decoding through pinned lattice tools;
- sparse-secret enumeration and meet-in-the-middle;
- small-secret hybrid recovery;
- repeated-support, graph, peeling, and dense-minor sparse-matrix recovery;
- mixed sparse-row/sparse-secret filtering and greedy recovery; and
- a bounded-small-error algebraic or clean-subset solver where applicable.

No code is copied from the CC-BY-NC LWE-benchmarking implementation. External
tools are installed as dependencies or accompanied by compatible notices.

Every solver:

- offers a forced single-worker calibration mode;
- supports deterministic solver seeds where applicable;
- reports progress, checkpoints, and peak memory;
- validates a recovered witness before recording it;
- writes through the common cumulative-ledger helper; and
- can request submission immediately after each new valid secret.

The readme explicitly tells the agent to call the submit helper whenever a
witness is found, then continue attacking remaining instances.

## 9. Instance-wise Cryptanalysis and Review

There is one separately authored Markdown analysis for every instance. Tools
may validate machine facts but do not generate the analysis prose, attack
selection, justification, or review.

Each analysis records:

- public parameters, distributions, predicates, and hashes;
- why the instance is non-standard LWE;
- all applicable exact-recovery attacks;
- decision or refutation ideas in a separately labeled non-qualifying section;
- selected best attack and dominant work factor;
- paper citations and exact applicability conditions;
- estimator commit, command, and output where relevant;
- calibration anchors and observed runs;
- predicted `T50`, `T90`, interval, memory, and confidence class;
- every hardness-reduction calculation and margin;
- matrix/secret interaction analysis;
- information sufficiency, rank, and kernel checks;
- alternative-witness analysis and one of
  `proven_unique`, `known_multiple`, or `no_second_witness_found`;
- known limitations;
- author identity; and
- the review-manifest identifiers for its two reviews.

At minimum, the reviews are a cryptanalysis review and a reproducibility/data
review. The external review manifest records the analysis SHA-256, reviewer,
verdict, review date, findings, and resolution. Editing an approved analysis
invalidates the manifest digest and requires re-review. Duplicate instances,
trivial row permutations or scalings, obviously underdetermined cases, and
cases dominated by witness multiplicity are rejected.

## 10. Frontier-CS 2.0 Integration

### 10.1 Task layout

```text
2.0/problems/lwe_structured_recovery/
  config.yaml
  readme
  evaluator.py
  evaluate.sh
  reference.json
  DESIGN.md
  AUDIT_REPORT.md
  calibration/
    hardware.json
    models.json
    summaries/
    scrubbed_logs/
  harbor/app/
    public/
      catalog.jsonl
      catalog.sha256
      lwe_instance.py
      format.md
    analyses/
      lwe_0001.md
      ...
      lwe_0200.md
      reviews.jsonl
    tools/
      generator/
      solvers/
      ledger/
  tests/
```

The root-level user-owned `LWE-literature.md` is preserved. The task receives
its own corrected, cited literature index rather than silently rewriting that
source file.

### 10.2 Shared public assets

The FCS-2.0 adapter gains an optional public-assets convention:

`harbor/app/public -> /app/public and /judge/public`.

The agent and secretless judge therefore consume the byte-identical catalog and
materializer from one PR-reviewable source. The judge does not receive solver
code, analyses, calibration logs, or any private generation material.

The adapter change is conditional and backward-compatible for tasks without a
public directory. It is covered by generated-task tests with and without public
assets.

### 10.3 JSON artifacts and resources

Frontier-CS gains first-class `json` language/artifact configuration, including
reference discovery tests. The task declares:

- file submission at `/app/solution.json`;
- a 10,800-second agent/verifier task limit;
- 8 agent CPU cores;
- 32 GiB agent/judge memory;
- no GPU; and
- 32 GiB storage for lattice checkpoints and generated matrices.

The benchmark difficulty unit remains the one-worker reference core-hour. The
additional trial cores let agents attack independent instances concurrently;
they do not alter the published calibration.

The CI reference is a syntactically valid empty ledger. It tests the evaluator
path in under the repository's 300-second validation limit. Production recovery
runs are calibration artifacts, not ordinary CI work.

## 11. Verification and Test Strategy

### 11.1 Dataset gates

Automated checks enforce:

- exactly 200 instances and 20 per structural family;
- exactly 60 measured paper cases and 140 modeled cases;
- exactly ten easy cases per easy bin, one from every family;
- exactly fourteen hard cases per hard octave;
- family balance in every hard octave;
- absence of ordinary standard-LWE records;
- a bijection among specifications, catalog records, analyses, hashes, and
  calibration summaries;
- a valid one-way instance-to-analysis-to-review digest chain;
- required error-family coverage; and
- absence of production answer material, secret seeds, or valid witness files.

### 11.2 Generator and arithmetic tests

Tests cover SHAKE-256 vectors, rejection sampling, exact sparse supports,
alphabet frequencies on synthetic samples, secret/error constraints, centered
modular arithmetic, public-record hashes, and independent Python/native matrix
materialization.

Synthetic fixtures exercise planted-witness generation. Production data tests
operate only on public records and attestations.

### 11.3 Evaluator adversarial tests

Tests cover valid partial and complete ledgers, alternative valid witnesses,
wrong dimensions, alphabet and weight violations, residual near misses,
unknown and duplicate ids, duplicate JSON keys, noncanonical residues,
booleans, floats, huge integers, oversized files, excessive nesting, and
malformed UTF-8/JSON.

Adding a valid witness cannot lower the score. Invalid entries cannot erase
valid entries or leak raw errors. Catalog corruption fails judge preparation.

### 11.4 Solver and calibration tests

Every reference solver recovers tiny synthetic fixtures. The selected
production paper cases have scrubbed end-to-end run attestations. Model rebuilds
from public summaries reproduce the committed runtime bins and uncertainty
labels.

Long attacks are not run in PR CI. CI checks their artifact hashes and runs
short smoke anchors.

### 11.5 FCS integration tests

Validation includes:

- Python compilation and local empty-reference evaluation;
- first-class JSON reference discovery;
- FCS problem list/show;
- Harbor task generation;
- byte equality of the agent and judge public catalogs;
- confirmation that non-public task files do not enter the agent image;
- a local submission round trip;
- a malformed-submission security smoke test; and
- one full Harbor smoke trial.

## 12. Deliverables and Acceptance Criteria

The work is complete only when the PR contains:

1. the FCS-2.0 task and narrow adapter/JSON support;
2. all 200 public instances and generation/materialization code;
3. all 200 individually authored and reviewed cryptanalysis files;
4. the 60 verified sub-hour paper cases across the six easy bins;
5. the 140 log-uniform modeled cases across the ten hard octaves;
6. reduction audits showing that no single-structure case was admitted in a
   prohibited standard-LWE-hard regime;
7. public reference attacks and calibration models supporting the analyses;
8. the secretless evaluator and cumulative submission helpers;
9. automated unit, dataset, adversarial, adapter, and integration tests;
10. task documentation, literature index, design/audit reports, and licenses;
11. successful repository validation and Harbor generation; and
12. a recorded Harbor smoke result.

No mass-generated cryptanalysis or unreviewed instance is accepted merely to
reach the count.

## 13. Approved Design Decisions

The user explicitly approved:

- the stratified, individually curated approach;
- exactly 200 instances in ten balanced structural families;
- a 60-instance paper-backed sub-hour tranche;
- a logarithmic difficulty ladder within those 60 easy instances;
- a 140-instance log-uniform ladder through 1024 core-hours;
- single-worker consumer-CPU runtime normalization;
- downscaled uses of paper attacks for the measured tranche;
- public secret-domain and residual-predicate verification;
- acceptance of any valid alternative witness;
- mandatory inclusion of mixed matrix/secret families;
- generic LWE estimation as the fallback when no interaction attack is known;
- no solution or calibration execution before 2026-07-10 23:00 HKT.

## 14. Primary Design References

- Zvika Brakerski and Nico Döttling, “Hardness of LWE on General Entropic
  Distributions,” <https://eprint.iacr.org/2020/119>.
- Kiril Bangachev, Guy Bresler, Stefan Tiegel, and Vinod Vaikuntanathan,
  “Near-Optimal Time-Sparsity Trade-Offs for Solving Noisy Linear Equations,”
  <https://arxiv.org/abs/2411.12512>.
- Aayush Jain, Huijia Lin, and Sagnik Saha, “A Systematic Study of Sparse
  LWE,” <https://eprint.iacr.org/2024/1589>.
- Dan Boneh, Kevin Lewi, Hart Montgomery, and Ananth Raghunathan, “Key
  Homomorphic PRFs and Their Applications,”
  <https://crypto.stanford.edu/~dabo/papers/homprf.pdf>.
- Emily Wenger et al., “Benchmarking Attacks on Learning with Errors,”
  <https://arxiv.org/abs/2408.00882>.
- Martin Albrecht et al., Lattice Estimator,
  <https://github.com/malb/lattice-estimator>.
