# Structured-LWE maintainer-only artifacts

This directory is intentionally outside `harbor/app`. Files here are for task
authors and PR reviewers; they are not part of the tested agent's `/app`
runtime payload.

The visibility boundary is:

| Path | Visible to tested agent? | Purpose |
| --- | --- | --- |
| `readme` | yes | public task statement copied into Harbor instructions |
| `harbor/app/` | yes | participant workspace, helper scripts, empty ledger, public catalog facade |
| `harbor/app/public/` | yes, and byte-identical on judge side as `/judge/public` | public catalog and deterministic verifier support |
| `evaluator.py`, `evaluate.sh` | no during Harbor trial; yes in repository review | black-box judge entry point |
| `maintainer/` | no | private research review, cryptanalysis, difficulty labels, calibration evidence, and reference solver sources |

The participant-visible app must not contain:

- per-instance cryptanalysis dossiers,
- difficulty labels, tier/cohort/runtime-bin metadata, or runtime estimates,
- reference solution ledgers or recovered secrets,
- solver registries that name which methods solve which families,
- calibration receipts or command logs.

## Private artifact index

Keep every report, cryptanalysis note, difficulty assignment, calibration
receipt, and reference-solver implementation in this directory or below.  The
current homes are:

| Artifact class | Maintainer-only location | Notes |
| --- | --- | --- |
| Instance-wise cryptanalysis dossiers | `analyses/lwe_0001.md` ... `analyses/lwe_0200.md` | One human-reviewable dossier per public instance.  Older top-level digest notes may bind legacy catalogs; see the current SHA notes below. |
| Hidden difficulty and selected-attack schedule | `analyses/hidden_schedule.jsonl` | Current 200-row map of instance ID to hidden family, band, runtime bin, model, selected attack, target, and digest. |
| Corpus distribution summary | `CORPUS_DISTRIBUTION_2026-07-21.md` | Current easy/middle/stretch allocation and current-catalog probe status. |
| Literature and theorem-scope review | `LITERATURE.md`, `REANALYSIS_2026-07-20.md` | Maintainer-facing interpretation of papers, lower-bound scope checks, and scratch attack notes. |
| Historical calibration receipts | `analyses/calibration_runs.jsonl`, summarized in `CALIBRATION.md` | Witness-free rows from the previous redacted catalog.  Useful as parameter-level evidence, not current-catalog exact receipts. |
| Current-catalog probe receipts | `analyses/current_probe_runs.jsonl`, `analyses/current_e0_probe_runs.jsonl` | Witness-free rows against the current regenerated catalog.  Successful rows record validation status but never retain candidate secrets. |
| Normal-LWE estimator proxy | `analyses/normal_lwe.jsonl` | Heuristic cross-check for all public records; not a hardness claim or participant hint. |
| Corpus generator and private slot/spec logic | `tools/corpus/` | Builds the public catalog from private parameter schedules while redacting private metadata from `harbor/app/public/catalog.jsonl`. |
| Reference/scratch solver implementations | `tools/solvers/` | Maintainer-only attack portfolio used for review and calibration; not starter code for contestants. |
| Native matrix audit helper | `tools/audit/matrix_ref.c` | Independent public-matrix expansion cross-check used by tests. |

Reference runs may validate a recovered candidate through the public verifier,
but retained receipts must stay witness-free: no row may contain `secret`,
`private_secret`, `private_error`, `private_seed`, or any reusable answer hash.
Use `secret_retained=false` for current-catalog probe rows.

Current public catalog byte binding:

- redacted participant catalog SHA-256:
  `379fc96637a0b5bb5dfdc10de0605a0922f223ba5544f8f6b48f67c3f8b8bcb6`
- previous rich catalog SHA-256 used by the older dossiers:
  `bb24a596e43f781c4824c94292cd0093bb3f8da2b3fdd895337281df89d94081`

The current redacted catalog was freshly regenerated on 2026-07-21: all 200
public records were emitted from the audited parameter grid with fresh
production witnesses/errors, and private metadata remains omitted. The old
per-instance dossiers remain useful for parameter review, but their older
top-level digest notes should be treated as legacy unless the analysis section
explicitly names the current catalog SHA.

Key subdirectories:

- `analyses/`: old instance-wise cryptanalysis dossiers and calibration rows.
  The current hidden schedule is `analyses/hidden_schedule.jsonl`.
- `tools/corpus/`: internal corpus builder and private slot/spec schedule.
- `tools/solvers/`: internal reference/scratch solvers used to audit the
  corpus, not contestant starter code.
- `REANALYSIS_2026-07-20.md`: latest scratch-cryptanalysis summary and
  redesign implications.
- `CORPUS_DISTRIBUTION_2026-07-21.md`: current hidden band allocation and
  regeneration notes.
