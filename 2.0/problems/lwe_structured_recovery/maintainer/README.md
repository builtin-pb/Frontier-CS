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
  `66c3a9a22200087206891cc2842b8ec8e88a67e0ec8479ae6cfc905ef06944b6`
- previous rich catalog SHA-256 used by the older dossiers:
  `bb24a596e43f781c4824c94292cd0093bb3f8da2b3fdd895337281df89d94081`

The redacted catalog reuses all 200 public `(A,b,predicates)` instances from
the rich catalog and recomputes `instance_digest` after removing private
metadata. The old per-instance dossiers remain useful for parameter review, but
their catalog SHA references the pre-redaction JSON shape unless individually
updated.

Key subdirectories:

- `analyses/`: old instance-wise cryptanalysis dossiers and calibration rows.
- `tools/corpus/`: internal corpus builder and private slot/spec schedule.
- `tools/solvers/`: internal reference/scratch solvers used to audit the
  corpus, not contestant starter code.
- `REANALYSIS_2026-07-20.md`: latest scratch-cryptanalysis summary and
  redesign implications.
