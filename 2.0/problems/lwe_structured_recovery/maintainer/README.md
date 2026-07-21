# Structured-LWE maintainer-only artifacts

This directory is intentionally outside `harbor/app`. Files here are for task
authors and PR reviewers; they are not part of the tested agent's `/app`
runtime payload.

The participant-visible app must not contain:

- per-instance cryptanalysis dossiers,
- difficulty labels, tier/cohort/runtime-bin metadata, or runtime estimates,
- reference solution ledgers or recovered secrets,
- solver registries that name which methods solve which families,
- calibration receipts or command logs.

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
