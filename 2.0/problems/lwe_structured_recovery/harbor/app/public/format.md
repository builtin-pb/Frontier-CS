# Structured-LWE public corpus format

`catalog.jsonl` contains 200 canonical JSON records, sorted by `instance_id`.
Each record is accepted by `lwe_challenge.schema.Catalog` and commits to its
cryptographic instance fields through `instance_digest`; that digest
intentionally excludes analysis, calibration, and runtime metadata.
`catalog.sha256` commits to the complete exact JSONL record bytes.

The public matrix is expanded from `matrix.seed_hex` using
`matrix.expansion_domain` and the algorithm implemented in
`lwe_challenge.matrix`. Dense matrix kinds generate every entry; sparse matrix
kinds generate exactly `row_weight` nonzero entries per row.

For each record, the public vector satisfies `b = A*s + e (mod q)` for at least
one secret and error satisfying the published predicates. The evaluator holds
no witness: it reconstructs the matrix and checks a submitted secret directly.

`slots.json` fixes the ten-family allocation and runtime bins. The corresponding
files in `specs/` are public, witness-free generation templates. Corpus builds
sample secret and error entropy freshly from the operating system; neither the
entropy nor the resulting private witness is written to disk.

Runtime predictions are analytical design estimates, not measurements. Easy
`DS_BIN` and `DS_TER` use `binomial(n,h) * a^h / (2400000/n)`, where `a` is the
nonzero-secret alphabet size. Easy `MIX_Q_SPARSE` uses the same exact-secret
enumeration model as its sole runtime-bearing attack. Its registered
mixed-filter route retains the paper's symbolic `O(m*k*3^k)` complexity and a
release-byte lower-edge screen, but has no modeled runtime; `n^3/60000` is only
a non-runtime dimension-sizing screen and is not an attack bound. Hard binary
exact-secret enumeration uses
`binomial(n,h)`, while hard balanced signed enumeration uses
`binomial(n,h)*binomial(h,h/2)`. Hard secret-governed families use the minimum
of the applicable enumeration upper bound and a pinned normal-LWE Lattice
Estimator proxy normalized at 10^6 abstract rop/s.
The proxy records the raw per-attack log2(rop), estimator configuration, source
archive hash, and cached-image digest. It is heuristic, is not a reduction or a
hardness claim, and models nonuniform public matrices as uniform; signed
hard plants are balanced while the verifier predicate also permits unbalanced
alternate valid secrets. Easy `DS_SMALL`, both small-matrix mixed families, and
the matrix-only families use sparse-bounded errors and the clean-subset median
`ln(2) / (rate * (binomial(m-w,n) / binomial(m,n)))`. The explicit assumed rates
and all intermediate work factors are recorded in each file under `specs/`.
Clean-subset rates use recorded family-specific baselines at `n=16`, scale as
`(16/n)^1.5` for modular solving, and are clamped to recorded conservative
floors. These are normalized analytical design rates, not consumer-CPU
throughput claims. Release-byte calibration evidence is recorded separately;
the public measurement fields remain null.
