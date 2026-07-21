# Structured-LWE public corpus format

`catalog.jsonl` contains 200 canonical JSON records, sorted by `instance_id`.
Each record is accepted by `lwe_challenge.schema.Catalog` and commits to the
public cryptographic instance fields through `instance_digest`.
`catalog.sha256` commits to the complete exact JSONL record bytes.

The public matrix is expanded from `matrix.seed_hex` using
`matrix.expansion_domain` and the algorithm implemented in
`lwe_challenge.matrix`. Dense matrix kinds generate every entry; sparse matrix
kinds generate exactly `row_weight` nonzero entries per row.

For each record, the public vector satisfies `b = A*s + e (mod q)` for at least
one secret and error satisfying the published predicates. The evaluator holds
no witness: it reconstructs the matrix and checks a submitted secret directly.

The public artifacts deliberately omit tier labels, runtime bins, calibration
estimates, and cryptanalysis paths. Corpus builds sample secret and error
entropy freshly from the operating system; neither the entropy nor the
resulting private witness is written to disk. Internal design dossiers may
track attack estimates and calibration evidence, but those notes are not part
of the public instance format.
