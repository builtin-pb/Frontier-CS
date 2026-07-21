# Maintainer corpus distribution, 2026-07-21

This file is maintainer-only.  Do not copy it into `harbor/app` or expose it
through the participant facade.

## Current catalog binding

- Current public catalog SHA-256:
  `379fc96637a0b5bb5dfdc10de0605a0922f223ba5544f8f6b48f67c3f8b8bcb6`
- Generation result: 200 fresh production public records generated, 0 reused.
- Hidden per-instance schedule:
  `maintainer/analyses/hidden_schedule.jsonl`

The regeneration kept the audited parameter grid stable so pinned estimator
coordinates remain applicable.  The public vector `b` and every public
`instance_digest` were regenerated from fresh OS entropy.

## Hidden distribution

The public catalog deliberately contains none of these labels.  Maintainers use
them to reason about the ladder:

| Hidden band | Count | Runtime interpretation |
| --- | ---: | --- |
| `easy` | 60 | literature/reference routes targeting E0--E5, below one hour |
| `middle` | 84 | H0--H5 model bins, roughly one to sixty-four hours |
| `stretch` | 56 | H6--H9 model bins, roughly sixty-four to 1024 hours |

This falls within the reanalysis target of roughly 50--70 verified easy
records, 80--100 middle records, and 40--60 stretch records.  The split should
be revisited whenever new structural attacks move a family between bands.

## Attack-model status

The hidden schedule records the selected catalog model for each instance.  The
current portfolio includes:

- exact sparse-secret enumeration for low-weight planted-secret records;
- clean-subset/retry estimates for sparse-error records;
- a normal-LWE estimator proxy or generic exhaustive ceiling where no stronger
  structural route is registered;
- post-hoc reanalysis notes for relation decoding, active hitting/correlation,
  and bounded integer feasibility in `REANALYSIS_2026-07-20.md`.

Historical solver receipts in `analyses/calibration_runs.jsonl` bind to the
previous redacted catalog
`66c3a9a22200087206891cc2842b8ec8e88a67e0ec8479ae6cfc905ef06944b6`.
They remain useful parameter-level calibration evidence, but they are not
current-catalog exact solve receipts after the fresh-witness regeneration.

Current-catalog smoke probes are recorded separately in
`analyses/current_probe_runs.jsonl`.  As of this note, four sparse-secret
records and one bounded-error record have fresh witness-free `SUCCESS`
receipts against the regenerated catalog, while two adjacent records censored
under short caps.  These probes are only spot checks; they do not replace a
full calibration campaign.

## Next iteration

Before claiming current-catalog measured easy coverage, rerun the reference
solvers against the current catalog and record fresh witness-free receipts.  In
particular, prioritize:

1. sparse-error relation decoding for old sparse-error hard-tail records;
2. active-hitting/correlation checks for mixed sparse-small and dense-small
   records;
3. bounded feasibility on the dense sparse-secret easy tail;
4. negative caps on high-weight `MIX_Q_SPARSE` stretch records.
