# Pinned normal-LWE proxy sweep

`run_normal_lwe.py` emits the fastest finite result among the pinned
primal-uSVP, BDD, hybrid, and MITM-hybrid Lattice Estimator recovery routes for
every public record, while retaining all four results.  It uses the exact public
`(n,m,q)`.  Uniform matrices and
supported iid secret/error laws map directly; every other substitution is
serialized as a heuristic next to its result.  In particular, a nonuniform
matrix is replaced by uniform `A`, and exact-global-weight sparse error is
replaced by an iid Gaussian with the same coordinate variance.  The output is
not a reduction, measured runtime, or hardness claim.

The all-record artifact names the MITM-enabled route
`primal_mitm_hybrid`.  The 84-record catalog portfolio uses the historical
local identifier `primal_hybrid_mitm` for the same pinned estimator call
(`LWE.primal_hybrid(mitm=True, babai=True)`); these are explicit aliases, not
different attacks.

Every row also retains a separate generic exact-recovery ceiling that enumerates
all `q^n` modular secrets.  Its conservative abstract-operation count is
`q^n * m * (2*n + 8)`, covering a direct matrix-vector product and public
predicate bookkeeping for each candidate.  This entry is not a Lattice
Estimator result.  It supplies a finite fail-closed upper bound when all four
pinned primal routines are outside the estimator's numerical/applicability
domain; the row selects the smallest finite value across the four estimator
entries and this generic ceiling.

The `10^6` rop/second normalization is a plotting and reporting convention,
not wall-clock time or a portable runtime upper bound.  The optimizer has a
minimum `beta=40`; under ADPS16's `2^(0.292*beta)` coordinate this creates a
mechanical floor of about `0.00328` normalized seconds before implementation
overhead.  Each row marks routes that hit that floor.  The task's empirical
two-second screen refers only to its runnable local `primal_bdd` implementation,
not to optimized uSVP or hybrid values in this artifact.  Easy-bin placement is
governed by the runnable structured route.  Hard portfolios may use their
separately registered provisional estimator coordinate when no validated
runtime exists.  The all-record inventory is always non-selecting and never
relabels a bin.

Pinned inputs:

- upstream: `https://github.com/malb/lattice-estimator`
- commit: `3e48ef421ec256afddb3e7d2249a77eab6e9ba12`
- source archive SHA-256:
  `aab320966fe4dc496a44e9223ab67d622e581d9ed052697e758907b0e437d539`
- local image reference: `lwe-estimator-phase3:latest`
- image ID:
  `sha256:725595ce2bb23a86890808074388c24b01903c46f2a78f9aa5ca57412a7cbfee`
- base image:
  `sagemath/sagemath:10.6@sha256:19995db6194f4a4bab18ce9a88556fd15b9ed5e916b4504fefe618a7796ddbdb`

The source archive is the Git tree at the pinned commit.  The image is local
run provenance, not a claim that the image can be reconstructed byte-for-byte
from this directory alone.  To reproduce the estimator environment, add that
tree at `/opt/lattice-estimator` on the pinned Sage base, set
`PYTHONPATH=/opt/lattice-estimator:/work` and `PYTHONNOUSERSITE=1`, and install
no extra runtime dependencies.  Verify the source commit and archive hash
before use; a rebuilt image may have a different image ID.

From the task root, an offline reproduction command is:

```bash
docker run --rm --network none -e HOME=/tmp \
  -v "$PWD/harbor/app:/work/task" \
  --entrypoint /bin/bash \
  lwe-estimator-phase3:latest -c \
  'sage -python /work/task/tools/estimator/run_normal_lwe.py \
    --catalog /work/task/public/catalog.jsonl \
    --output /work/task/analyses/normal_lwe.jsonl'
```

The checked-in output is canonical JSONL sorted by `instance_id`.  Its rows bind
the catalog SHA-256 and instance digest, record the exact distribution mapping,
and normalize `rop` at the explicit convention of `10^6` abstract operations
per second.

For parallel reproduction, run the same command with
`--shard-index I --shard-count N` into `N` distinct files, for every
`I=0,...,N-1`, then merge fail-closed:

```bash
python maintainer/tools/estimator/merge_normal_lwe.py \
  --catalog harbor/app/public/catalog.jsonl \
  --output maintainer/analyses/normal_lwe.jsonl \
  maintainer/analyses/normal_lwe.shard*.jsonl
```

The merger rejects empty, duplicate, unknown, stale, misbound, or
provenance-inconsistent rows and requires exact coverage of all 200 IDs.

After regenerating the complete 200-row artifact, refresh the instance-bound
dossier sections from the task root:

```bash
python maintainer/tools/estimator/update_dossiers.py \
  --catalog harbor/app/public/catalog.jsonl \
  --results maintainer/analyses/normal_lwe.jsonl \
  --analyses maintainer/analyses
```
