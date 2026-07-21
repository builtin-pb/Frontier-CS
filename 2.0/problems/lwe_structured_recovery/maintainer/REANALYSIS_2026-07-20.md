# Maintainer reanalysis, 2026-07-20

Scope: internal evidence for revising the structured-LWE corpus. This file is
not participant-facing. Do not copy it into `harbor/app`.

## Executive summary

The old rich catalog gave a smooth theoretical ladder, but scratch attacks
found several much faster routes than the selected analytical estimates. The
public task has now been redacted so agents no longer see the intended
easy/hard split. The next corpus iteration should rebalance the 200 slots using
the attacks below as first-class models rather than treating them as outliers.

Most important conclusions:

1. Sparse-error families are substantially easier than the clean-subset median
   model predicts once low-dimensional left-kernel relations are sampled and
   decoded.
2. Mixed sparse-small and dense-small instances have strong correlation/local
   search attacks that dominate the normal-LWE proxy on many records.
3. Dense sparse-secret "easy" records can often be solved by public bounded
   integer feasibility, not only by exact enumeration.
4. Some high-weight `MIX_Q_SPARSE` records remain resistant to the current
   local/search/feasibility probes and are still useful as hard-ladder material.

## Catalog bindings

- Previous rich catalog SHA-256:
  `bb24a596e43f781c4824c94292cd0093bb3f8da2b3fdd895337281df89d94081`
- Current redacted public catalog SHA-256:
  `379fc96637a0b5bb5dfdc10de0605a0922f223ba5544f8f6b48f67c3f8b8bcb6`

The first redacted catalog reused all 200 public instances. The 2026-07-21
catalog then regenerated all 200 public `b` vectors and per-instance digests
from fresh production entropy while keeping the audited parameter grid stable.
See `CORPUS_DISTRIBUTION_2026-07-21.md` for the current hidden band allocation.

## New attack evidence

### Sparse-error relation decoder

Method: sample `n+c` rows, compute short left-kernel relations, and decode
relations whose error contribution is small. A compiled `c=3` hot loop gave
large wins over the old sparse-error clean-subset estimates.

Representative solve times observed during scratch runs:

| Instance | Old bin/model time | Observed method/time |
| --- | ---: | ---: |
| `lwe_0074` | 4,830 s | 74.64 s |
| `lwe_0093` | hard-ladder sparse-error | 11.93 s |
| `lwe_0112` | hard-ladder sparse-error | 23.86 s |
| `lwe_0114` | H2-ish sparse-error | 13.998 s compiled |
| `lwe_0131` | hard-ladder sparse-error | 51.85 s |
| `lwe_0067` | H3-ish sparse-error | 274.48 s |
| `lwe_0072` | H8-ish sparse-error | 1,743.34 s |
| `lwe_0130` | H9-ish sparse-error | 572.58 s |

Implication: clean-subset/linear-solve/retry is no longer a conservative upper
bound for sparse-error records. The sparse-error ladder should be redesigned
around relation-decoder parameters, or sparse-error-only families should be
reduced in count if the goal is broad structural diversity.

### Mixed-family active-hitting and correlation attacks

Methods:

- `active_hitting`: identify active sparse secret support by rows whose sparse
  incidence is most diagnostic, then validate locally.
- `small_corr` plus local swaps: exploit small-alphabet matrix/secret
  correlations and refine by local search.

Observed:

- `MIX_Q_SPARSE` easy records `lwe_0141` through `lwe_0146` solve quickly.
  Example: `lwe_0146` solved in about 0.21--0.35 s versus an old catalog model
  near 1,403 s.
- `MIX_SMALL_SPARSE`: 20/20 solved in scratch tests.
- `MIX_DENSE_SMALL`: 20/20 solved in scratch tests.
  Example: `lwe_0197` solved in about 0.05 s versus an old normal-LWE-proxy
  prediction near 2,968,273 s.

Negative evidence:

- Hard weight-14 `MIX_Q_SPARSE` records `lwe_0147` through `lwe_0160` remained
  unsolved by active cover, vote, WalkSAT-style local search, suffix-DP, and
  CP-SAT active-hit variants under the scratch caps. Best local residuals were
  still around 31--38 bad rows.

Implication: small-alphabet mixed families need a much steeper parameter range
or fewer slots. High-weight sparse-general mixed records remain promising hard
material, but the easier records need to be retuned because active support
identification collapses them.

### Public bounded-feasibility attack

Method: model the public witness condition directly as

```text
sum_j A[i,j] s[j] - b[i] - q k[i] in [-B, B]
```

with integer variables and public bounds only. CP-SAT was enough for several
dense sparse-secret records; no hidden planted witness was used.

Observed examples:

- `lwe_0001`: 0.064 s
- `lwe_0002`: 0.302 s
- `lwe_0003`: 0.021 s
- `lwe_0004`: 25.34 s
- `lwe_0005`: 14.43 s
- `lwe_0006`: 1.21--12.22 s in separate runs, versus an old model near 2,065 s
- signed examples: `lwe_0021` 2.99 s, `lwe_0022` 1.60 s,
  `lwe_0023` 10.6--68.8 s depending on centering/tactics.

Negative evidence:

- Dense hard sparse-secret records beyond the easy tail remained unsolved under
  CP-SAT variants, C annealing, explicit-error CP-SAT, HiGHS MIP, and fpylll
  embedding/CVP caps.

Implication: bounded feasibility should be added to the maintainer attack
portfolio for the lower dense sparse-secret range. It does not by itself break
the upper dense hard range under the tested caps.

## Distribution redesign implications

The next 200-instance release should not preserve the old 60 easy / 140 hard
split literally. A better hidden allocation is:

- 50--70 records with verified sub-2h reference routes, still spread across
  many structures and internally ordered by runtime.
- 80--100 middle records targeting minutes to tens of hours under the expanded
  attack portfolio.
- 40--60 stretch records where the best known route is still extrapolated or
  capped negative, but every record has a named fallback estimate.

Candidate family adjustments:

1. Reduce small-alphabet mixed density unless parameters are increased; current
   `MIX_SMALL_SPARSE` and `MIX_DENSE_SMALL` are overrepresented at trivial
   hardness after correlation attacks.
2. Keep high-weight `MIX_Q_SPARSE` as a hard subfamily, but retune low-weight
   examples using active-hitting estimates.
3. Rebuild sparse-error ladders using the relation decoder as the selected
   upper-bound attack instead of clean-subset only.
4. Keep dense sparse-secret hard records, but add CP-SAT/bounded-feasibility to
   the easy and middle calibration model.
5. Continue including normal-LWE/Lattice-Estimator proxy rows as fallback upper
   bounds when no structural route is identified, but never expose those
   estimates in participant artifacts.

## Public/private artifact rule

Participant-visible `/app` may contain:

- `public/catalog.jsonl`, `catalog.sha256`, and the public facade,
- evaluator and submission helpers,
- task instructions describing the public algebraic contract.

Maintainer-only material must stay outside `/app`:

- per-instance analyses,
- calibration receipts,
- attack registries and solver code,
- recovered solutions and timing notes,
- hidden slot schedules and runtime labels.

This separation is now enforced by moving rich artifacts into `maintainer/` and
emitting a redacted public catalog.
