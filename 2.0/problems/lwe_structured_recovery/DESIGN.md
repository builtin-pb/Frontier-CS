# Design — `lwe_structured_recovery`

## 1. Task contract

An agent receives 200 public structured-LWE instances and earns one point for
each instance for which it submits any valid secret vector.  For public
`(A,b,q)`, the evaluator checks

```text
b = A s + e (mod q)
```

and accepts when `s` satisfies the public alphabet/modulus and weight predicates
and the centered residual `e` satisfies the public `L_inf`, optional `L_1`,
optional squared-`L_2`, and optional support-size bounds.  It does not compare
against a planted answer.  All instances have equal weight:

```text
score = 100 * solved_count / 200
score_unbounded = solved_count
```

Solutions are accumulated in `/app/solution.json`.  The agent validates a
candidate locally, adds it with `/app/add_solution.py`, and submits immediately.
The helper preserves earlier solutions, making partial progress useful.

## 2. Public, secretless evaluation

The agent and judge receive the same digest-bound public catalog.  Each record
contains dimensions, modulus, target vector, matrix kind, matrix seed and domain,
secret/error distribution metadata, and exact acceptance predicates.  The
evaluator reconstructs `A` from those public fields and validates the submitted
vector.  It holds no secret, error, private seed, planted witness, or reusable
answer digest.

The generator checks its temporary planted witness during corpus construction,
but that value is not an evaluator input.  Alternative valid witnesses are
deliberately accepted.

## 3. Corpus shape

The 200 slots are balanced across ten families, 20 per family:

| Family | Matrix structure | Secret structure |
| --- | --- | --- |
| `DS_BIN` | dense uniform | exact-weight binary |
| `DS_TER` | dense uniform | exact-weight signed ternary |
| `DS_SMALL` | dense uniform | dense small alphabet |
| `SA_Q` | sparse, general nonzero residues | unrestricted mod `q` |
| `SA_SMALL` | sparse, small alphabet | unrestricted mod `q` |
| `DA_BIN` | dense binary | unrestricted mod `q` |
| `DA_TER` | dense ternary | unrestricted mod `q` |
| `MIX_Q_SPARSE` | sparse, general nonzero residues | exact-weight binary/ternary |
| `MIX_SMALL_SPARSE` | sparse, small alphabet | exact-weight binary/ternary |
| `MIX_DENSE_SMALL` | dense small alphabet | dense or sparse small alphabet |

The public knobs are `n`, `m`, `q`, four error-distribution kinds, matrix
sparsity/alphabet, and secret sparsity/alphabet.  The corpus excludes a scored
plain-LWE family; normal-LWE estimates are retained only as a conservative
fallback for structured instances.

## 4. Difficulty ladder

The immutable allocation is 60 easy instances and 140 hard instances:

- Six easy bins `E0`–`E5`, with one instance per family in each bin.  Their
  target intervals are `[1,4)`, `[4,16)`, `[16,64)`, `[64,256)`, `[256,1024)`,
  and `[1024,3600)` seconds.
- Ten hard octaves `H0`–`H9`, with fourteen instances per family and fourteen
  instances per octave.  The target scale ranges from about one hour to 1024
  hours and is uniform on a logarithmic scale by construction.

These are two metadata axes: easy/hard is `tier`, while paper/ladder is
`cohort`.  Exactly 60/200 records form the literature-backed easy tranche: 18
`DS_BIN`/`DS_TER`/`MIX_Q_SPARSE` records use full planted-domain enumeration, a
degenerate specialization of Son--Cheon's exhaustive sparse-secret guessing
component, and 42 use an error-free-subset/linear-solve/retry adaptation of
Sun--Tibouchi--Abe (ePrint 2020/666).  The six `MIX_Q_SPARSE` records also keep
the Chi--Cho--Kim--Lee greedy route as a screened alternative, but it is not
part of the 60-record count; exact enumeration is their runtime-bearing model.
The planted-domain route is matrix/error-law independent because it traverses
the declared planted support/value domain, which contains the planted witness,
and validates the residual.  For balanced signed distributions that planted
domain is narrower than the verifier-accepted exact-weight domain.  This
accounting neither claims source-identical implementations nor
transfers Son--Cheon's lattice preprocessing, Gaussian success model, paper
constants, or any paper's full theorem unchanged. Full final-byte E2 and E3
recovery replays now exist, but they do not establish portable nominal bin-edge
runtimes for E2--E5 without isolated run artifacts.

The research model takes the minimum over applicable structured attacks and
retains a generic LWE estimate.  A mixed-structure instance is modeled jointly
only when there is a defensible interaction argument; otherwise the normal-LWE
fallback is explicitly labeled.  Runtime labels are difficulty hypotheses,
not cryptographic hardness claims.

For hard secret-governed slots, the concrete `analytical-attack-portfolio-min-v1`
model takes the minimum of exact secret enumeration and a pinned normal-LWE
Lattice Estimator proxy.  Exact-weight slots fix `q=257`, `m=n+8`, and `h=14`.
The binary `H0`--`H9` dimensions are
`[80,85,90,100,105,110,120,130,140,150]`; the signed dimensions are
`[75,80,85,90,100,105,110,120,130,135]`.  Hard `DS_SMALL` retains the modulus
cycle, uses `m=n+8`, and uses dimensions
`[70,72,74,76,78,80,82,84,86,88]`.

The easy schedules use reviewable analytical runtime models.  `DS_BIN`,
`DS_TER`, and `MIX_Q_SPARSE` use exact planted-secret enumeration with a
dimension-aware candidate-rate calibration.  Seven families use the
clean-subset model
`ln(2)/(Pr[clean subset] * rate(n))`, with family-specific calibrated rate
constants and explicit floors.  This quantity is a 50%-success median runtime
estimate under independent trials, not an upper bound; singular-minor
rejection and implementation costs are separate.  The registered paper-derived
`mixed_filter_greedy` method is retained as an adversarial screen for
`MIX_Q_SPARSE`, but it is not the selected runtime model.  These constants
remain analytical calibration inputs, not per-record
`measured_runtime_seconds` values.

The estimator records raw `log2(rop)` results for primal uSVP, primal BDD,
primal hybrid, and MITM hybrid under `ADPS16` and `gsa`, then normalizes the
fastest result at an explicit `10^6` abstract rop/second.  The pinned source
archive SHA-256 is
`aab320966fe4dc496a44e9223ab67d622e581d9ed052697e758907b0e437d539` and
the cached image digest is
`725595ce2bb23a86890808074388c24b01903c46f2a78f9aa5ca57412a7cbfee`.
This normalization is a transparent difficulty convention, not measured CPU
throughput.  For nonuniform matrix families the normal-LWE calculation is only
a uniform-matrix heuristic proxy, not a reduction or hardness claim.  Hard
signed plants use exactly seven positive and seven negative entries, so the
estimator profile `SparseTernary(7,7)` maps the planted distribution exactly.
The public verifier predicate deliberately remains broader and also permits an
unbalanced alternate valid secret; the model does not assert that such an
alternate exists for a generated record.

For cross-family review, `maintainer/analyses/normal_lwe.jsonl` records a
separate normal-LWE proxy for all 200 records, generated by the pinned
`maintainer/tools/estimator/run_normal_lwe.py` runner and bound to catalog
SHA-256
`bb24a596e43f781c4824c94292cd0093bb3f8da2b3fdd895337281df89d94081`.
It uses exact public `(n,m,q)`; replaces nonuniform matrices by a uniform-matrix
model; maps supported secret laws directly; maps bounded-uniform and
centered-binomial errors directly; uses an untruncated same-sigma Gaussian for
truncated Gaussian error; and uses a variance-matched iid Gaussian for
dependent exact-global-weight sparse error.  This all-record artifact is a
non-selecting heuristic cross-check: it does not alter catalog parameters,
attack selection, or runtime labels, and it is not a reduction or measurement.

The parameter-selection review is fail-closed with respect to the entropy-LWE
lower bound (Brakerski--Döttling) and the sparse-LWE lower bound
(Bangachev--Bresler--Tiegel--Vaikuntanathan): no reduction-based conclusion is
drawn unless every theorem precondition and parameter map is instantiated.
The present bounded-uniform hard-error schedule is not the Gaussian target
mapping required by the entropy-LWE theorem, and no composition establishing
such a map is claimed.  The task is attack research, not a collection of
instances advertised hard under a standard-LWE reduction.

The concrete release rules are:

- In secret-only exact-weight families, cap the secret weight at `h <= 14` and
  compute the exact min-entropy of the actual planted law.  This is
  `log2(binomial(n,h)) + h*log2(|nonzero alphabet|)` for the unbalanced law,
  but `log2(binomial(n,h)) + log2(binomial(h,h/2))` for the balanced hard
  signed law.  A low weight is only a screening rule; each dossier must still
  state the entropy and the limits of any Brakerski--Döttling comparison before
  making a reduction-based claim.
- Across all 80 sparse-matrix records, choose row weight
  `k = ceil(2*sqrt(n))` (while keeping `k < n`).  Concretely, `k^2/n` is about
  4.0--4.9, so the theorem's finite retained-sample factor
  `1 - 3/l - k^2/n` is negative rather than an admissible positive factor.
  Moreover, 46 records use an exact-global-weight sparse error whose
  coordinates are dependent, whereas the cited theorem assumes its independent
  per-sample noise law; and the 40 mixed sparse-matrix records use an
  exact-weight planted secret rather than the theorem's uniform q-ary target.
  Therefore the cited BBTV theorem is not instantiated by these parameters.
  This is a scope statement, not a claim that every sparse-LWE hardness result
  is avoided.
- In mixed sparse-matrix/sparse-secret families, the exact-weight planted-secret
  enumeration domain has size `binomial(n,h)` for binary,
  `binomial(n,h)*binomial(h,h/2)` for balanced hard signed plants, and
  `binomial(n,h)*2^h` for an unbalanced signed plant.  This remains a
  matrix-independent upper bound.  Easy `MIX_Q_SPARSE` additionally screens the
  paper-derived mixed-filter route while retaining exact enumeration as its
  runtime-bearing model.  Easy
  `MIX_SMALL_SPARSE` and `MIX_DENSE_SMALL` deliberately select a clean-subset
  error attack that ignores the secret structure, while retaining enumeration
  and interaction attacks as alternatives.  None of these choices assumes that
  all matrix/secret interactions are benign.

## 5. Reproducible public instances

Matrix expansion is deterministic SHAKE-256 with domain separation, rejection
sampling, and a canonical row order.  A record's `instance_digest` binds its
canonical contents; `catalog.sha256` binds the canonical JSONL catalog.  The
public `lwe_instance.py` facade streams rows and performs the same arithmetic as
the evaluator.

Synthetic fixtures are regenerated byte-for-byte from an explicit private test
seed.  Production targets use one-time private randomness during construction;
the released record, not the generation-only randomness excluded from release,
is the reproducibility boundary.  Anyone can reconstruct `A`, `b`, and all
predicates from the public catalog alone.

## 6. Reference research portfolio

The portfolio is deliberately small and practical:

| Solver | Provenance |
| --- | --- |
| `primal_bdd` | clean-room implementation of the Lindner--Peikert q-ary BDD attack |
| `dense_minor` | clean-room implementation of the Jain--Lin--Saha dense-submatrix attack |
| `mixed_filter_greedy` | clean-room implementation of the Chi--Cho--Kim--Lee greedy attack |
| `sparse_secret_enum` | clean-room full-guess specialization of Son--Cheon's exhaustive guessing component; no lattice stage or paper constants |
| `sparse_secret_mitm` | original clean-room MITM solver informed by sparse-secret literature |
| `small_secret_hybrid` | original clean-room guess-and-decode solver informed by hybrid literature |
| `repeated_support`, `graph_peeling` | original clean-room sparse-matrix solvers |
| `bounded_error` | clean-room generalized adaptation of Sun--Tibouchi--Abe Section 4.2 clean-subset/solve/retry; not Arora--Ge or a Gröbner-basis implementation |

Every candidate produced by any solver is replayed through the public verifier.
The authoritative provenance is `maintainer/tools/solvers/registry.json` plus
`sources.json`; `maintainer/LITERATURE.md` gives the human-readable map.

## 7. Calibration evidence and limits

The release-focused verification suite covers schema parsing, deterministic
matrix expansion, generation, witness validation, evaluator behavior, the FCS
wrapper, the production catalog, and repository registration.  Calibration
runs on the exact release bytes record E0 and E1 recoveries under documented
single-worker solver seeds, probe one E2 path per family at the 16-second lower
boundary, and screen all 60 easy records with `primal_bdd` for two seconds
without a recovery.  Separate capped
screens of MITM, repeated-support, dense-minor, graph-peeling, and hybrid routes
also found no faster release blocker.  The paper-derived mixed-filter route is
retained as a screened alternative for `MIX_Q_SPARSE`; exact sparse-secret
enumeration is the final runtime-bearing model.  Nine E2 probes censored at the
16-second lower edge, while seed 0 recovered the final `lwe_0083` realization
in 42.262039 internal seconds, inside E2 and near its 39.422135-second
analytical median.  A later final-byte replay recovered all nine other E2
coordinates with 90-second single-worker attempts and deterministic seed
retries.  The largest per-instance retry budget was four attempts (at most six
minutes sequentially), and a fresh production-evaluator replay accepted all
nine new vectors with no invalid submission.  This establishes a practical
sub-hour reference path for every E2 coordinate, but not the nominal 64-second
upper edge or a portable per-bin runtime guarantee.
A later E3 replay recovered all ten E3 coordinates.  The largest ordinary
solve/retry budget was three 360-second attempts (18 minutes sequentially),
and a fresh production-evaluator replay accepted all ten vectors with no
invalid submission.  The original `lwe_0144` realization exposed a
reproducible 0.42-second deterministic fast tail.  A disclosed two-sided
public-byte screen rejected one replacement below 64 seconds and one above 256
seconds; the retained realization censored at 64 seconds and recovered in
85.376816 internal seconds.  This establishes practical sub-hour E3 paths, not
the nominal 256-second upper edge or a portable per-bin runtime guarantee.
The original prerelease `lwe_0083` realization exposed a reproducible
3.120821-second seed-0 fast tail.  The final public matrix seed uses the disclosed
`retune/11` salt after salts 9 and 10 also screened too fast.  Candidate
secrets/errors were freshly sampled and never serialized.  This selection is
calibration of a public realization, not an unbiased validation of the
family-wide median model.
The final-registry `lwe_0142` recovery took 14.338797 internal seconds, inside
its nominal E1 upper boundary on the calibration host.  A historical run on
the same public bytes took 21.020 external seconds and missed the edge.  The
spread is retained rather than presented as portable per-bin validation.

This is still not a complete 60-point, full-duration recovery campaign, much
less a validation of all 140 hard predictions.  The nominal E2/E3 upper edges,
E4--E5 upper runtimes, attack crossover points, and unmodeled mixed-structure
interactions remain extrapolated.  Consequently every public
`measured_runtime_seconds` value is null and runtime labels remain hypotheses
rather than hardness claims.
