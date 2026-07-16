# Structured-LWE Recovery — Audit Report

## Scope

This report covers the task contract, public-instance arithmetic, secretless
evaluator, cumulative submission path, generator reproducibility, reference
solver provenance, and the evidence currently available for difficulty
calibration.  It does not convert an estimate into a hardness claim.

## Summary

The evaluator design is intentionally simple: reconstruct the public matrix,
compute the centered residual for a submitted vector, and check public
predicates.  The judge needs no secret material.  The primary remaining risk is
calibration quality, not scoring correctness.

Contract documents describe the packaged release.  This audit separately lists
the checks demonstrated by the final repository state.  In particular, “the
evaluator holds no secret” means its algorithm and inputs require none; the
source and generated-package scans also confirm that packaging did not include
generation-only material.

| Area | Status | Evidence or limitation |
| --- | --- | --- |
| Mathematical witness check | Implemented | Candidate type, length, secret predicate, residual and all error bounds are checked |
| Alternative witnesses | Implemented | Acceptance depends only on the public relation and predicates |
| Production catalog integrity | Implemented contract | Canonical JSONL, instance digests, sidecar digest and exact 200-record preparation check |
| Cumulative scoring | Implemented | Strict ledger parser, atomic helper, independent per-record scoring and equal weights |
| Public feedback | Implemented | Aggregate solved/rejection/family/octave metrics; no candidate vectors or residuals are echoed |
| Reference solver provenance | Documented | Registry distinguishes paper methods, clean-room methods and folklore adaptations |
| Release-focused verification | Passed in this checkout | Full task-local and selected repository integration suites cover schema, matrix, generator, verifier, evaluator, wrapper, catalog and registration |
| Easy-ladder calibration | Partially established | Final-byte E0/E1 recoveries, complete E2/E3 recovery under capped deterministic-retry protocols, and bounded alternative-attack screens are recorded in `harbor/app/CALIBRATION.md`; the nominal E2/E3 and all E4--E5 upper edges remain extrapolated |
| Hard-ladder calibration | Analytical only | Instance-wise exact-enumeration/normal-LWE proxy portfolios are bound, but the advertised hard runtimes are not measured |

## Security and leakage review

The evaluator consumes only the released catalog and `/app/solution.json`.
Generation-only secret, error, and private seed values are absent from the
evaluation API.  It accepts any witness that satisfies public predicates, so it
does not need a planted answer or an answer hash.  Catalog failures are treated
as infrastructure errors, not as an agent score of zero.

The public response is aggregate.  It may identify solved instance IDs and
rejection categories, but it does not publish submitted vectors, residuals,
tracebacks, exception text, or filesystem paths.  The cumulative ledger helper
uses locking and atomic replacement so concurrent additions do not silently
discard earlier progress.

The final source and generated-package scans found no private generation seeds,
planted witnesses, error vectors, reusable answer hashes, or temporary solver
outputs.  The adapter now excludes Python bytecode and cache directories at
every depth, and a packaging regression verifies that exclusion together with
byte-identical public catalog assets.

## Corpus and estimator review

The design allocates exactly 200 instances: 20 in each of ten structured
families, with 60 easy slots across six sub-hour bins and 140 hard slots across
ten logarithmic octaves through 1024 hours.  The family definitions cover matrix
and secret sparsity and binary/ternary/small alphabets, while retaining `n`,
`m`, `q`, and error distribution as independent knobs.

The attack inventory includes exact combinatorial baselines, five registered
paper-method/component routes, and a pinned normal-LWE proxy.  Exactly 60/200
records form the literature-backed easy tranche.  Eighteen
`DS_BIN`/`DS_TER`/`MIX_Q_SPARSE` records use full planted-domain enumeration, a
degenerate specialization of Son--Cheon's exhaustive sparse-secret guessing
component; 42 use a clean-room generalized adaptation of the error-free-subset/
linear-solve/retry route in Sun--Tibouchi--Abe (ePrint 2020/666).  The six mixed
records retain the Chi--Cho--Kim--Lee greedy route only as a screened
alternative; exact enumeration supplies their runtime-bearing model and their
place in the 60-record count.  Because planted-domain enumeration traverses the
declared planted support/value domain, which contains the planted witness, and
validates the residual, this narrow component mapping is independent of `A`
and the error law.  For balanced signed distributions the planted domain is
narrower than the verifier-accepted exact-weight domain.  It does not
transfer Son--Cheon's lattice preprocessing, Gaussian success model, constants,
or full algorithm.  The Sun--Tibouchi--Abe mapping transfers neither its binary
independence assumptions nor its success probability or asymptotic constants
to generalized task predicates.  The classification also does not assert
source-identical implementations or unchanged transfer of any paper theorem.
Full final-byte E2 and E3 recovery replays exist, but they do not demonstrate
portable nominal E2--E5 bin-edge runtimes. Mixed structure
is treated jointly only with an explicit attack or a route that deliberately
ignores one structure.

The final-byte campaign records E0/E1 recoveries and selected E2 boundary
probes instance by instance under documented single-worker seeds.  Nine E2
probes censored at 16 seconds; seed 0 recovered the final `lwe_0083`
realization in 42.262039 internal seconds, inside E2 and near its
39.422135-second analytical median.  One in-bin recovery is not a portable E2
upper-tail measurement.  A later final-byte replay recovered all nine other E2
coordinates using 90-second single-worker attempts and deterministic seed
retries.  The largest per-instance retry budget was four attempts, at most six
minutes sequentially, and a fresh production-evaluator replay accepted all
nine new vectors with no invalid submission.  This supports the sub-hour easy
classification for every E2 coordinate but not the nominal 64-second upper
edge.  The original prerelease `lwe_0083` realization's reproducible
3.120821-second fast tail and the final `retune/11` public-matrix selection are disclosed in
`CALIBRATION.md`; private generation samples were never retained.  A full E3
replay likewise recovered all ten E3 coordinates.  The largest ordinary
solve/retry budget was three 360-second attempts (18 minutes sequentially),
and a fresh production-evaluator replay accepted all ten vectors with no
invalid submission.  The original `lwe_0144` record exposed a reproducible
0.42-second fast tail; a disclosed two-sided replacement screen retained a
record that censored at 64 seconds and recovered in 85.376816 internal seconds.
This supports sub-hour E3 paths but not its nominal 256-second upper edge.  A
two-second `primal_bdd` screen recovers none of the 60 easy records, and focused
MITM/matrix/hybrid screens find no additional lower-bin blocker.  The mixed
greedy method remains a screened `MIX_Q_SPARSE` alternative; exact
sparse-secret enumeration is the final runtime-bearing route.  Nothing in this
campaign demonstrates the nominal E2/E3 or E4--E5 modeled upper runtimes.
The final-registry `lwe_0142` exact recovery took 14.338797 internal seconds,
inside its nominal E1 upper edge on this host.  A historical same-byte run took
21.020 external seconds and missed the edge; the release retains both
observations and does not promote either to a portable runtime bound.

These checks still do not validate the nominal E2/E3 upper edges, E4--E5 upper
runtimes, or the proposed hard runtime distribution.  Estimated hard octaves
can be wrong because of constant factors, memory, phase transitions, or an
unmodeled interaction.  A normal-LWE
proxy is conservative bookkeeping, not a substitute for structured
cryptanalysis.  The all-record cross-check in
`harbor/app/analyses/normal_lwe.jsonl` is generated by the pinned
`harbor/app/tools/estimator/run_normal_lwe.py` runner and is bound to catalog
SHA-256
`bb24a596e43f781c4824c94292cd0093bb3f8da2b3fdd895337281df89d94081`.
It uses exact public `(n,m,q)` while explicitly substituting a uniform matrix
for structured matrices, an untruncated same-sigma Gaussian for truncated
Gaussian error, and a variance-matched iid Gaussian for dependent
exact-global-weight sparse error.  It is a non-selecting heuristic artifact:
it neither changes release labels nor proves or measures their cost.

Release parameters must also match the documented screening rules: secret-only
exact-weight cases have `h <= 14` plus an exact-entropy audit; and all 80
sparse-matrix records use `k = ceil(2*sqrt(n))`.  For those 80 records,
`k^2/n` is about 4.0--4.9, making the BBTV theorem's retained-sample factor
`1 - 3/l - k^2/n` negative.  In addition, 46 records use dependent
exact-global-weight sparse errors instead of the theorem's independent
per-sample noise law, and the 40 mixed sparse-matrix records have exact-weight
secrets rather than its uniform q-ary target.  Thus that theorem is not
instantiated; the audit does not claim to exclude every sparse-LWE hardness
result.  Mixed sparse-secret cases retain the matrix-independent exhaustive
candidate count as an upper bound while still searching for faster interaction
attacks.

## Reference solver review

The registered full paper-method implementations are:

- `primal_bdd`: Lindner--Peikert q-ary lattice/BDD construction;
- `dense_minor`: Jain--Lin--Saha dense-submatrix attack; and
- `mixed_filter_greedy`: Chi--Cho--Kim--Lee greedy statistical attack.

The registered paper-component specialization is `sparse_secret_enum`: it
implements only Son--Cheon's exhaustive full-guess component as an independent
clean-room traversal followed by the public witness checker, with no lattice
preprocessing or transfer of paper success constants.  `bounded_error` is the
registered clean-room generalized adaptation of Sun--Tibouchi--Abe Section 4.2;
it is not presented as Arora--Ge polynomial solving or Steiner's
Gröbner-basis analysis, and its generalized cases do not inherit the paper's
asymptotic analysis.  The remaining solvers are explicitly labeled clean-room
baselines/adaptations.  All successful candidates must pass the same public
witness checker as agent submissions.

The authoritative bounded release-byte evidence is recorded in
`harbor/app/CALIBRATION.md`, including catalog and solver revision bindings.  It is not a
complete benchmark: every `measured_runtime_seconds` field remains null, and
the per-instance analytical prediction remains the corpus difficulty label.
Superseded-candidate timings appear only where they explain a schedule change
and are explicitly identified as superseded.

## Release gate

The task is PR-ready only when repository state demonstrates all of the
following:

- the packaged public catalog and sidecar exist and contain exactly 200 valid
  records with 20 per family and the intended 60/140 allocation;
- task-local and repository registration tests pass from a clean checkout;
- the reference empty ledger prepares and evaluates successfully at score zero;
- generated Harbor agent and judge assets contain byte-identical public data;
- a leak scan finds no secret seed, planted witness, error vector, or reusable
  answer hash; and
- documentation and PR text describe runtime labels as provisional wherever
  production measurements are absent; and
- production parameter records obey the `h <= 14` and `k` near `2*sqrt(n)`
  screening rules documented by the literature rationale.

Do not claim that the nominal E2/E3 or E4--E5 upper runtimes or the hard
distribution are measured, or that attack implementations match paper
performance.  The supported claim is narrower: final-byte E0/E1 calibration,
complete E2/E3 recovery under the documented capped-retry protocols, and
bounded alternative-attack smoke screens.
