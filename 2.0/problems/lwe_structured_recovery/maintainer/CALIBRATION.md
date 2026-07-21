# Release-byte calibration record

This record binds the bounded calibration campaign used to review the public
easy ladder.  It is evidence for parameter selection, not a hardness claim and
not a complete E0--E5 benchmark.  Timings vary by host; consequently the public
specifications retain `calibration_status="extrapolated"` and
`measured_runtime_seconds=null`.

The campaign was run before the 2026-07-21 fresh-witness regeneration.  The
receipts below remain honest parameter-level calibration evidence, but they are
not exact current-catalog solve receipts unless rerun against the current
catalog.

The compact, witness-free receipts for the selected easy-family E0--E2 runs
and the final MIX_Q alternative screens are in
`analyses/calibration_runs.jsonl`; recovered vectors remain private.

- Current catalog SHA-256: `379fc96637a0b5bb5dfdc10de0605a0922f223ba5544f8f6b48f67c3f8b8bcb6`
- Calibration-run catalog SHA-256: `66c3a9a22200087206891cc2842b8ec8e88a67e0ec8479ae6cfc905ef06944b6`
- Host: MacBook Pro `Mac17,2`, Apple M5 (10 cores), 16 GB RAM,
  `arm64` macOS 26.4
- Execution: one solver process, one worker, no constant-factor or parallel
  optimization
- Request parameters: `clean_subset_cap=1000000`,
  `work_unit_cap=10000000000`, checkpoint interval `10000000`

Solver revisions:

| Solver | Revision |
| --- | --- |
| `sparse_secret_enum` | `f488f140edffa610e76755e005e8fd0ec91e9ba856e6250ec3102a045f9909ec` |
| `bounded_error` | `7402fd4e720b8763c0fd24aceaa7c374fe758df7ee5459abf39fa31cbc0f8544` |
| `mixed_filter_greedy` | `27ddaef678be426ef51feb73d8f66f6146bcba3106acbc661ba83d0bdd66e119` |
| `primal_bdd` | `9e447f577da39ae762c864b47e0f2fdda7204d1cbec3cec9ac895bcc264ae639` |

## E0 and E1 recovery runs

Every listed result is `SUCCESS` and the recovered vector passed the public
verifier.  The seed selects the deterministic traversal for randomized
clean-subset solvers; exact enumeration ignores it.

| Instance | Bin | Solver | Seed | Internal elapsed (s) |
| --- | --- | --- | ---: | ---: |
| `lwe_0001` | E0 | `sparse_secret_enum` | 0 | 1.186478 |
| `lwe_0021` | E0 | `sparse_secret_enum` | 0 | 1.965437 |
| `lwe_0041` | E0 | `bounded_error` | 0 | 1.669663 |
| `lwe_0061` | E0 | `bounded_error` | 0 | 1.737373 |
| `lwe_0081` | E0 | `bounded_error` | 0 | 1.324362 |
| `lwe_0101` | E0 | `bounded_error` | 1 | 2.834664 |
| `lwe_0121` | E0 | `bounded_error` | 0 | 3.491026 |
| `lwe_0141` | E0 | `sparse_secret_enum` | 0 | 2.188721 |
| `lwe_0161` | E0 | `bounded_error` | 4 | 1.213006 |
| `lwe_0181` | E0 | `bounded_error` | 0 | 1.624055 |
| `lwe_0002` | E1 | `sparse_secret_enum` | 0 | 8.232024 |
| `lwe_0022` | E1 | `sparse_secret_enum` | 0 | 6.960854 |
| `lwe_0042` | E1 | `bounded_error` | 9 | 3.874551 |
| `lwe_0062` | E1 | `bounded_error` | 1 | 10.694595 |
| `lwe_0082` | E1 | `bounded_error` | 6 | 12.860943 |
| `lwe_0102` | E1 | `bounded_error` | 0 | 13.148994 |
| `lwe_0122` | E1 | `bounded_error` | 0 | 12.611157 |
| `lwe_0142` | E1 | `sparse_secret_enum` | 0 | 14.338797 |
| `lwe_0162` | E1 | `bounded_error` | 4 | 14.484213 |
| `lwe_0182` | E1 | `bounded_error` | 2 | 4.328560 |

The `lwe_0042` run is 0.125449 seconds below E1's nominal four-second lower
edge on this host.  It is retained as a small empirical edge miss; the
analytical median is 6.497 seconds, and neither value is a portable wall-clock
bound.

The final-registry `lwe_0142` receipt reports 14.338797125 internal seconds and
31,796,781 work units, reaching ordinal 268,022 of its 437,920-candidate
domain.  The recovered vector passed the public verifier, and this run is
inside E1's 16-second upper edge on this host.  An earlier
run of the same final public bytes, before the solver registry reclassification,
reported 20.887750125 internal and 21.020 external seconds and therefore missed
that edge.  Both observations are retained: they show host/run variance and do
not turn the analytical E1 design estimate into a portable wall-clock bound.

## E2 lower-bound checks

For one record per family, the selected reference path was run with a
16-second wall cap.  Nine results were `CENSORED` at the cap and recovered no
witness: `lwe_0003`, `lwe_0023`, `lwe_0043`, `lwe_0063`, `lwe_0103`,
`lwe_0123`, `lwe_0143`, `lwe_0163`, and `lwe_0183`.  The tenth,
`lwe_0083`, succeeded with seed 0 in 42.262039 internal seconds and passed the
public verifier.  That is inside E2's `[16,64)` interval and near the
39.422135-second clean-subset analytical median.  The nine censors check only
their E2 lower boundary, and the one success does not establish a portable
E2 upper-runtime guarantee.

The original prerelease `lwe_0083` realization had a reproducible
3.120821-second seed-0 fast tail.  The release generator therefore derives the
final matrix seed with a disclosed `retune/11` salt.  A bounded public-byte
screen rejected salts 9 and 10 as too fast; salt 11 produced the retained
42.262039-second result.  Every candidate used a fresh production secret and
error that were never serialized, and only a public-verifier result was
retained.  This makes the selection process reproducible and explicit, but it
also means the retained run is calibration of the chosen realization rather
than an unbiased test of the family-wide median model.

## Full E2 recovery replay

A subsequent final-byte replay extended the 16-second lower-bound probes to a
90-second cap per attempt.  Instances were run concurrently across families,
but every solver invocation still used one worker and one thread.  The
deterministic exact-enumeration routes succeeded on their first attempt.  The
randomized clean-subset route was restarted with the next integer seed after a
censor:

| Instance | Selected solver | Attempt outcomes |
| --- | --- | --- |
| `lwe_0003` | `sparse_secret_enum` | seed 0: success |
| `lwe_0023` | `sparse_secret_enum` | seed 0: success |
| `lwe_0043` | `bounded_error` | seed 0: censored; seed 1: success |
| `lwe_0063` | `bounded_error` | seeds 0--2: censored; seed 3: success |
| `lwe_0083` | `bounded_error` | seed 0: success at 42.262039 seconds under its 64-second cap |
| `lwe_0103` | `bounded_error` | seed 0: censored; seed 1: success |
| `lwe_0123` | `bounded_error` | seeds 0--1: censored; seed 2: success |
| `lwe_0143` | `sparse_secret_enum` | seed 0: success |
| `lwe_0163` | `bounded_error` | seed 0: censored; seed 1: success |
| `lwe_0183` | `bounded_error` | seed 0: censored; seed 1: success |

The nine newly recovered vectors were merged into a fresh canonical ledger and
the production evaluator reported `solved=9 submitted=9 invalid=0`.  Together
with the separately validated `lwe_0083` receipt, every E2 coordinate therefore
has final-byte recovery evidence.  The largest per-instance retry budget was
four 90-second attempts, or at most six minutes when run sequentially, which
supports inclusion in the sub-hour easy tranche.

This replay does **not** establish the nominal E2 `[16,64)` upper edge: most
success payloads intentionally contain only the recovered vector, the runs
shared a contended host, and retries were allowed 90 seconds.  It is
solve/retry evidence for the literature-derived route, not a portable timing
benchmark.  Recovered vectors and the temporary ledger were destroyed after
public-verifier replay; the table retains only witness-free outcomes.

## Full E3 recovery replay

The same final-byte protocol was extended to E3 with a 360-second cap per
attempt.  The first sweep ran one single-threaded worker per family; censored
clean-subset routes were restarted with the next integer seed:

| Instance | Selected solver | Attempt outcomes |
| --- | --- | --- |
| `lwe_0004` | `sparse_secret_enum` | seed 0: success |
| `lwe_0024` | `sparse_secret_enum` | seed 0: success |
| `lwe_0044` | `bounded_error` | seed 0: success |
| `lwe_0064` | `bounded_error` | seed 0: censored; seed 1: success |
| `lwe_0084` | `bounded_error` | seed 0: censored; seed 1: success |
| `lwe_0104` | `bounded_error` | seed 0: censored; seed 1: success |
| `lwe_0124` | `bounded_error` | seeds 0--1: censored; seed 2: success |
| `lwe_0144` | `sparse_secret_enum` | seed 0: success at 85.376816 seconds under a 256-second cap |
| `lwe_0164` | `bounded_error` | seed 0: success |
| `lwe_0184` | `bounded_error` | seed 0: success |

All ten recovered vectors were merged into a fresh canonical ledger and the
production evaluator reported `solved=10 submitted=10 invalid=0`.  The largest
ordinary solve/retry budget was three 360-second attempts, or at most 18
minutes sequentially, supporting the sub-hour easy classification for every
E3 coordinate.

The first `lwe_0144` public realization was a reproducible 0.42-second
deterministic fast tail.  Three fresh production realizations were screened:
candidate 1 censored at both 64 and 256 seconds, candidate 2 recovered below
64 seconds, and retained candidate 3 censored at 64 seconds before recovering
in 85.376816 internal seconds (85.54 external seconds, 261,076,643 work units).
The replacement `mixed_filter_greedy` screen also censored at 64.10 external
seconds.  This two-sided selection and its bias are explicit; it calibrates one
public realization and does not validate the family-wide model. Candidate 1,
candidate 2, and retained candidate 3's 64-second enumerator censor are
unarchived local observations: their rejected public bytes and private run
artifacts were destroyed. Only the retained candidate's 256-second success and
mixed-filter censor have witness-free checked-in receipts, so the rejected
candidate screen cannot be reproduced from the final tree.

As with E2, the aggregate E3 replay is not a portable bin benchmark.  Most
attempts used a 360-second cap, families were run concurrently, and the host
was contended.  It establishes runnable sub-hour reference paths, not the
nominal E3 `[64,256)` upper edge.  Private outputs and the replay ledger were
destroyed after validation.

## Alternative-attack screens

The exact release bytes were screened with `primal_bdd` for two seconds per
easy record: all 60 runs were censored or returned a rejected nearest-plane
candidate, with no recovery.  Additional two-second screens covered 12
applicable MITM runs and 24 repeated-support runs; focused E0/E1 screens also
covered dense-minor, graph-peeling, and small-secret-hybrid routes.  These are
only bounded smoke tests.

The alternative screen materially changed the release.  On a superseded
candidate, `mixed_filter_greedy` recovered the `MIX_Q_SPARSE` E0/E1/E2 records
in approximately 1.37, 6.17, and 9.72 seconds, invalidating the old E2 label.
The final six `MIX_Q_SPARSE` parameters therefore use
`analytical-easy-exact-secret-with-mixed-screen-v1`.  Exact sparse-secret
enumeration is its sole runtime-bearing route and is counted as the degenerate
full-guess specialization of Son--Cheon's exhaustive guessing component.  It
traverses the whole public exact-weight secret domain, so this narrow mapping
does not depend on `A` or the error law; it transfers no lattice preprocessing,
Gaussian success estimate, or paper constant.  The Chi--Cho--Kim--Lee-inspired
route remains only a screened alternative: it retains the paper's symbolic
`O(m*k*3^k)` cost and is screened at the lower edge of each bin, with no
transferred wall-clock model.  The recorded `n^3/60000` value is only a
dimension-sizing screen, not an attack bound.

Final-byte lower-edge screens are:

| Instance | Bin | Solver | Cap (s) | Outcome |
| --- | --- | --- | ---: | --- |
| `lwe_0141` | E0 | `mixed_filter_greedy` | 1 | censored |
| `lwe_0142` | E1 | `mixed_filter_greedy` | 4 | censored |
| `lwe_0143` | E2 | `mixed_filter_greedy` | 16 | censored |
| `lwe_0144` | E3 | `mixed_filter_greedy` | 64 | censored |
| `lwe_0145` | E4 | `mixed_filter_greedy` | 256 | censored |
| `lwe_0146` | E5 | `mixed_filter_greedy` | 1024 | censored |

Independently, final-registry exact enumeration recovered `lwe_0141` in
2.188721 internal seconds, recovered `lwe_0142` as detailed above, censored on
`lwe_0143` at the 16-second E2 lower edge before the later full-E2 recovery,
and recovered the retained `lwe_0144` in 85.376816 internal seconds.  No
selected-path full-duration run is claimed for E4--E5.

## Reproduction shape

Runs were launched from `harbor/app`.  For a mode-0700 fresh directory `$WORK`,
the exact worker shape was:

```text
../../../../../.venv-lwe-structured-recovery/bin/python -m tools.solvers.cli \
  --catalog public/catalog.jsonl --instance INSTANCE --solver SOLVER \
  --expected-solver-revision REVISION --max-seconds CAP --seed SEED \
  --threads 1 --work-dir "$WORK" --private-output "$WORK/result.json"
```

For the final `MIX_Q_SPARSE` evidence, substitute:

| Instance | Solver | Revision | Cap | Seed |
| --- | --- | --- | ---: | ---: |
| `lwe_0141` | `sparse_secret_enum` | `f488f140edffa610e76755e005e8fd0ec91e9ba856e6250ec3102a045f9909ec` | 8 | 0 |
| `lwe_0142` | `sparse_secret_enum` | `f488f140edffa610e76755e005e8fd0ec91e9ba856e6250ec3102a045f9909ec` | 64 | 0 |
| `lwe_0143` | `sparse_secret_enum` | `f488f140edffa610e76755e005e8fd0ec91e9ba856e6250ec3102a045f9909ec` | 16 | 0 |
| `lwe_0144` | `sparse_secret_enum` | `f488f140edffa610e76755e005e8fd0ec91e9ba856e6250ec3102a045f9909ec` | 256 | 0 |
| `lwe_0141` | `mixed_filter_greedy` | `27ddaef678be426ef51feb73d8f66f6146bcba3106acbc661ba83d0bdd66e119` | 1 | 0 |
| `lwe_0142` | `mixed_filter_greedy` | `27ddaef678be426ef51feb73d8f66f6146bcba3106acbc661ba83d0bdd66e119` | 4 | 0 |
| `lwe_0143` | `mixed_filter_greedy` | `27ddaef678be426ef51feb73d8f66f6146bcba3106acbc661ba83d0bdd66e119` | 16 | 0 |
| `lwe_0144` | `mixed_filter_greedy` | `27ddaef678be426ef51feb73d8f66f6146bcba3106acbc661ba83d0bdd66e119` | 64 | 0 |
| `lwe_0145` | `mixed_filter_greedy` | `27ddaef678be426ef51feb73d8f66f6146bcba3106acbc661ba83d0bdd66e119` | 256 | 0 |
| `lwe_0146` | `mixed_filter_greedy` | `27ddaef678be426ef51feb73d8f66f6146bcba3106acbc661ba83d0bdd66e119` | 1024 | 0 |

Private-output success payloads contain the recovered vector and therefore are
not checked in.  A recovery is counted only after replay through the canonical
public ledger/evaluator; censor payloads contain only cap, unit, status, and
reason.  The tables above are compact local receipts, not raw timing logs or a
cross-host benchmark.
