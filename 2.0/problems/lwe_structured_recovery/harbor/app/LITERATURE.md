# Structured-LWE literature and implementation map

This file records how the task uses the literature.  The machine-readable
authority is `tools/solvers/sources.json`, which pins publication versions,
digests, locators, hypotheses, and implementation mappings.  A citation marked
"context" does not imply that the local solver implements the paper.

## Implemented paper methods and narrow adaptations

- **Lindner and Peikert, “Better Key Sizes (and Attacks) for LWE-Based
  Encryption” (2011).** Sections 4–5 motivate the q-ary lattice and
  bounded-distance decoding construction used by `primal_bdd`.
  <https://web.eecs.umich.edu/~cpeikert/pubs/lwe-analysis.pdf>
- **Jain, Lin, and Saha, “A Systematic Study of Sparse LWE” (2024/2025).**
  Section 7.2 is the basis for `dense_minor`.  `repeated_support` and
  `graph_peeling` are independent heuristics and cite this work only for
  sparse-LWE context. <https://eprint.iacr.org/2024/1589.pdf>
- **Chi, Cho, Kim, and Lee, “Asymptotic Analysis of Ternary Sparse LWE”
  (2026).** `mixed_filter_greedy` implements the reviewed sparse-row ternary
  greedy statistical recovery in clean-room form.
  <https://eprint.iacr.org/2026/630.pdf>
- **Son and Cheon, “Revisiting the Hybrid attack on sparse and ternary secret
  LWE” (2019).** `sparse_secret_enum` implements the degenerate full-guess
  specialization of the exhaustive guessing component: when the whole secret
  is guessed, the residual lattice stage vanishes.  The local clean-room solver
  traverses the exact public support/value domain and validates each candidate;
  it does not implement or inherit the paper's lattice preprocessing, Gaussian
  success analysis, or constants. <https://eprint.iacr.org/2019/1019.pdf>
- **Sun, Tibouchi, and Abe, “Revisiting the Hardness of Binary Error LWE”
  (2020).** `bounded_error` is a clean-room generalized adaptation of the
  Section 4.2 error-free-subset/linear-solve/retry route.  It validates every
  candidate on the full public instance; non-binary, dependent, and structured
  task cases do not inherit the paper's success probability or asymptotic
  constants. <https://eprint.iacr.org/2020/666.pdf>

## Context for independent adaptations

- **Albrecht, Göpfert, Virdia, and Wunderer, “Revisiting the Expected Cost of
  Solving uSVP and Applications to LWE” (2017).** Success-model context for
  `primal_bdd`; not its registered method source.
  <https://eprint.iacr.org/2017/815.pdf>
- **Espitau, Joux, and Kharchenko, “On a hybrid approach to solve small secret
  LWE” (2020).** Context for `sparse_secret_mitm` and `small_secret_hybrid`;
  neither local solver claims paper fidelity.
  <https://eprint.iacr.org/2020/515.pdf>
- **Bi, Lu, Luo, Wang, and Zhang, “Hybrid Dual Attack on LWE with Arbitrary
  Secrets” (2021).** Parameterization context for `small_secret_hybrid`, not a
  local implementation of the hybrid-dual algorithm.
  <https://eprint.iacr.org/2021/152.pdf>
- **Arora and Ge, “New Algorithms for Learning in Presence of Errors” (2011)**
  and **Steiner, “The Complexity of Algebraic Algorithms for LWE” (2024).**
  These give bounded-error algebraic context.  Local `bounded_error` instead
  enumerates clean subsets, solves modular systems, and validates; it is not an
  annihilating-polynomial or Gröbner-basis implementation.
  <https://eccc.weizmann.ac.il/report/2010/066/download/>,
  <https://arxiv.org/pdf/2402.07852v2>

## Parameter-selection guardrails

- **Brakerski and Döttling, entropy-LWE lower bound**
  (<https://eprint.iacr.org/2020/119>): when only the secret distribution is
  changed, the corpus should not select parameters inside the reduction-backed
  regime and then advertise them as an attack ladder.
- **Bangachev, Bresler, Tiegel, and Vaikuntanathan, “Near-Optimal
  Time-Sparsity Trade-Offs for Solving Noisy Linear Equations”**
  (<https://arxiv.org/abs/2411.12512>): when only matrix sparsity is changed,
  the corpus should likewise avoid reduction-backed parameter regimes.  This
  lower-bound guard is distinct from the Jain--Lin--Saha dense-minor attack
  implemented locally.

Mixed matrix/secret structure is not treated as composable by default.  A
joint estimate requires an explicit argument that the two structures do not
interact adversely; otherwise the analysis records a normal-LWE estimate as a
fallback and labels the limitation.

The corpus uses three concrete screening rules, followed by theorem-specific
parameter review:

- Secret-only exact-weight instances use `h <= 14` and record the exact
  min-entropy of the planted law.  The unbalanced formula is
  `log2(binomial(n,h)) + h*log2(|nonzero alphabet|)`; a balanced signed plant
  instead uses `log2(binomial(n,h)) + log2(binomial(h,h/2))`.  The deliberately
  small domain keeps these points away from a high-entropy hardness claim; the
  cap alone is not treated as a theorem check.
- Matrix-sparsity-only instances use row weight near
  `k = ceil(2*sqrt(n))`, with `k < n`.  Across all 80 sparse-matrix records,
  `k^2/n` is about 4.0--4.9, so the cited BBTV theorem's finite
  retained-sample factor `1 - 3/l - k^2/n` is negative rather than positive.
  Forty-six records also use an exact-global-weight sparse error with dependent
  coordinates instead of the theorem's independent per-sample error law, and
  the 40 mixed sparse-matrix records use an exact-weight secret rather than the
  theorem's uniform q-ary target.  The BBTV theorem is therefore not
  instantiated here; this does not claim that every sparse-LWE result is out of
  scope.
- For mixed sparse-secret instances, exhaustive planted-secret enumeration has
  candidate count `binomial(n,h)` for binary, `binomial(n,h)*2^h` for the
  unbalanced signed law, and `binomial(n,h)*binomial(h,h/2)` for a balanced
  signed plant, regardless of whether matrix rows are dense, sparse, or
  small-alphabet.  This gives a
  matrix-independent recovery upper bound.  It does not rule out a faster
  interaction attack, so those alternatives and the normal-LWE fallback stay
  in the attack inventory.

## Estimation policy

A reproducible Lattice Estimator result may supply a generic-LWE cost reference,
but it is neither a proof nor a structured-attack implementation.  The proxy
mapping and cost-model caveats follow the methodology discussed by Albrecht,
Curtis, Deo, Davidson, Player, Postlethwaite, Virdia, and Wunderer in
[*Estimate All the {LWE, NTRU} Schemes!*](https://eprint.iacr.org/2018/331),
especially Sections 4--6; the exact modern software revision is pinned
separately in the source registry and runner metadata.  The 84 hard
secret-governed records retain their bound four-attack estimator/exact-secret
portfolio.  Separately, `analyses/normal_lwe.jsonl` records a non-selecting
normal-LWE cross-check for all 200 records, generated by the pinned
`tools/estimator/run_normal_lwe.py` runner and bound to catalog SHA-256
`bb24a596e43f781c4824c94292cd0093bb3f8da2b3fdd895337281df89d94081`.
The runner uses exact public `(n,m,q)` and the `ADPS16`/`gsa` configuration,
then records primal uSVP, primal BDD, primal hybrid, and MITM hybrid estimates
at the explicit normalization convention of `10^6` abstract rop/second.
Uniform matrices and supported iid secret/error laws map directly.  A
nonuniform matrix is replaced by a uniform-matrix model; truncated Gaussian
error becomes an untruncated same-sigma Gaussian; and dependent
exact-global-weight sparse error becomes a variance-matched iid Gaussian.  The
artifact does not select or relabel instances and is not a reduction-backed
estimate, measurement, or hardness claim.

Exactly 60/200 records form the literature-backed easy tranche.  Eighteen
`DS_BIN`/`DS_TER`/`MIX_Q_SPARSE` records use full planted-domain enumeration,
the degenerate full-guess specialization of Son--Cheon's exhaustive guessing
component.  Forty-two records use the generalized
error-free-subset/linear-solve/retry adaptation of Sun--Tibouchi--Abe.  The six
mixed records retain the registered Chi--Cho--Kim--Lee greedy method only as a
screened alternative; it is not needed for the count, while exact
sparse-secret enumeration is their runtime-bearing release model.  Planted-domain
enumeration is independent of the matrix and error laws because it traverses
the declared planted support/value domain, which contains the planted witness,
and checks candidates against the public witness relation.  For balanced
signed distributions this planted domain is narrower than the verifier-accepted
exact-weight domain.  The narrow Son--Cheon mapping transfers neither lattice
preprocessing, Gaussian success analysis, paper constants, nor the complete
hybrid algorithm.  The generalized Sun--Tibouchi--Abe route does not transfer
the paper's binary independence hypotheses, success model, or constants.
These are published core routes, not claims of source-identical local
implementations or unchanged theorem transfer.  `q^n`
remains only a universal fallback when no cheaper structured route is known.

Instance analysis should take the cheapest applicable structured attack
seriously, preserve memory and failure conditions, and validate every recovered
candidate against the public relation.  Release-byte E0/E1 evidence and E2
boundary probes are recorded instance by instance.  Nine E2 probes censored at
16 seconds, while seed 0 recovered the final `lwe_0083` realization in
42.262039 internal seconds, inside E2 and near its 39.422135-second analytical
median.  This one run does not establish a portable E2 upper tail.  The public
metadata remains honest: every `measured_runtime_seconds` value is null.  The
Complete final-byte E2 and E3 replays recovered all ten instances in each bin,
with evaluator acceptance. Those concurrent, host-contended campaigns do not
establish portable upper-tail or nominal bin-edge runtimes; E4--E5 remain
unreplayed, and all bin labels remain design targets rather than hardness
claims.
In particular, the final-registry `lwe_0142` receipt is 14.338797 internal
seconds, inside its nominal E1 upper edge on the calibration host.  A historical
same-byte run took 21.020 external seconds and missed the edge; both observations
are reported as variance evidence rather than silently selecting the favorable
one or claiming a portable bound.
