"""Build the public 200-instance structured-LWE catalog.

The parameter schedule and matrix seeds are public and deterministic. Secret
and error samples use fresh operating-system entropy; that entropy and all
derived witnesses remain in memory and are never serialized.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from collections.abc import Mapping
from pathlib import Path

from lwe_challenge.generator import GenerationTemplate, generate_production_instance
from lwe_challenge.schema import (
    MATRIX_EXPANSION_DOMAIN,
    Catalog,
    ErrorDistributionSpec,
    ErrorPredicateSpec,
    MatrixSpec,
    SecretDistributionSpec,
    SecretPredicateSpec,
    _parse_instance,
    canonical_record_bytes,
)


FAMILY_CODES = (
    "DS_BIN",
    "DS_TER",
    "DS_SMALL",
    "SA_Q",
    "SA_SMALL",
    "DA_BIN",
    "DA_TER",
    "MIX_Q_SPARSE",
    "MIX_SMALL_SPARSE",
    "MIX_DENSE_SMALL",
)
_EASY_BOUNDS_SECONDS = (
    (1, 4),
    (4, 16),
    (16, 64),
    (64, 256),
    (256, 1024),
    (1024, 3600),
)
_MODULI = (257, 769, 1229, 2053, 4093)
_ERROR_KINDS = (
    "truncated_discrete_gaussian",
    "centered_binomial",
    "bounded_uniform",
)
_EXACT_SECRET_RATES = {
    "DS_BIN": 10_000.0,
    "DS_TER": 12_000.0,
    "MIX_Q_SPARSE": 15_000.0,
    "MIX_SMALL_SPARSE": 7_000.0,
    "MIX_DENSE_SMALL": 10_000.0,
}
_EASY_EXACT_SECRET_RATE_NUMERATOR = 2_400_000.0
_EASY_MIXED_FILTER_SIZING_DIVISOR = 60_000.0
_DENSE_SMALL_RATE = 200_000.0
_CLEAN_SUBSET_RATE_AT_N16 = 100.0
_CLEAN_SUBSET_MINIMUM_RATE = 10.0
_EASY_CLEAN_SUBSET_RATE_AT_N16 = {
    "DS_SMALL": 130.0,
    "SA_Q": 100.0,
    "SA_SMALL": 100.0,
    "DA_BIN": 100.0,
    "DA_TER": 80.0,
    "MIX_SMALL_SPARSE": 125.0,
    "MIX_DENSE_SMALL": 80.0,
}
_EASY_CLEAN_SUBSET_MINIMUM_RATE = {
    "DS_SMALL": 5.0,
    "SA_Q": 5.0,
    "SA_SMALL": 5.0,
    "DA_BIN": 5.0,
    "DA_TER": 2.0,
    "MIX_SMALL_SPARSE": 5.0,
    "MIX_DENSE_SMALL": 5.0,
}
_MAX_RUNTIME_SECONDS = 1024.0 * 3600.0
_HARD_BINARY_N_BY_OCTAVE = (80, 85, 90, 100, 105, 110, 120, 130, 140, 150)
_HARD_SIGNED_N_BY_OCTAVE = (75, 80, 85, 90, 100, 105, 110, 120, 130, 135)
_HARD_DENSE_SMALL_N_BY_OCTAVE = (70, 72, 74, 76, 78, 80, 82, 84, 86, 88)
_HARD_EXACT_SECRET_WEIGHT = 14
_EASY_CLEAN_SUBSET_MIXED_FAMILIES = frozenset(
    {"MIX_SMALL_SPARSE", "MIX_DENSE_SMALL"}
)
_EASY_ENUMERATION_FAMILIES = frozenset(
    {"DS_BIN", "DS_TER", "MIX_Q_SPARSE"}
)
_ESTIMATOR_ROP_PER_SECOND = 1_000_000.0
_ESTIMATOR_SOURCE_ARCHIVE_SHA256 = (
    "aab320966fe4dc496a44e9223ab67d622e581d9ed052697e758907b0e437d539"
)
_ESTIMATOR_CACHED_IMAGE_DIGEST = (
    "725595ce2bb23a86890808074388c24b01903c46f2a78f9aa5ca57412a7cbfee"
)


def _estimator_result_row(
    usvp: tuple[float, int],
    bdd: tuple[float, int],
    hybrid: tuple[float, int],
) -> tuple[dict[str, object], ...]:
    return (
        {"algorithm": "primal_usvp", "rop_log2": usvp[0], "beta": usvp[1]},
        {"algorithm": "primal_bdd", "rop_log2": bdd[0], "beta": bdd[1]},
        {
            "algorithm": "primal_hybrid",
            "options": {"mitm": False, "babai": False},
            "rop_log2": hybrid[0],
            "beta": hybrid[1],
        },
    )


# Raw output from the pinned offline Lattice Estimator image.  These are data,
# not an implementation of the estimator; regeneration instructions and full
# provenance are recorded in DESIGN.md and in each generated model record.
_ESTIMATOR_RESULTS: dict[
    tuple[str, int, int], tuple[dict[str, object], ...]
] = {
    ("binary_exact", 80, 257): _estimator_result_row(
        (31.828, 109), (32.12008708163089, 62), (31.982946557020934, 54)
    ),
    ("binary_exact", 85, 257): _estimator_result_row(
        (33.288, 114), (33.87223955543172, 73), (32.95827497378212, 58)
    ),
    ("binary_exact", 90, 257): _estimator_result_row(
        (34.748, 119), (35.0427154528346, 89), (33.877414336172016, 55)
    ),
    ("binary_exact", 100, 257): _estimator_result_row(
        (37.668, 129), (37.960987639756745, 94), (35.516738404853, 57)
    ),
    ("binary_exact", 105, 257): _estimator_result_row(
        (39.128, 134), (39.42181207733285, 102), (36.285391967616505, 57)
    ),
    ("binary_exact", 110, 257): _estimator_result_row(
        (40.588, 139), (40.884068553334686, 111), (36.995175385302154, 56)
    ),
    ("binary_exact", 120, 257): _estimator_result_row(
        (43.215999999999994, 148), (43.223458161152664, 122), (38.29339841669468, 59)
    ),
    ("binary_exact", 130, 257): _estimator_result_row(
        (45.843999999999994, 157), (45.86896869138994, 137), (39.4767864352936, 61)
    ),
    ("binary_exact", 140, 257): _estimator_result_row(
        (48.18, 165), (48.24767636606517, 150), (40.4773456355377, 53)
    ),
    ("binary_exact", 150, 257): _estimator_result_row(
        (50.516, 173), (50.69503613126183, 163), (41.43276109153262, 54)
    ),
    ("signed_exact", 75, 257): _estimator_result_row(
        (32.12, 110), (32.41253822533718, 72), (32.3040799038746, 55)
    ),
    ("signed_exact", 80, 257): _estimator_result_row(
        (33.58, 115), (34.1642395554149, 74), (33.28492122168016, 55)
    ),
    ("signed_exact", 85, 257): _estimator_result_row(
        (35.332, 121), (35.62443962061081, 82), (34.22284791123958, 58)
    ),
    ("signed_exact", 90, 257): _estimator_result_row(
        (36.791999999999994, 126), (37.08480672411891, 90), (35.08459223163888, 61)
    ),
    ("signed_exact", 100, 257): _estimator_result_row(
        (39.711999999999996, 136), (40.00671545267286, 106), (36.61785077951146, 56)
    ),
    ("signed_exact", 105, 257): _estimator_result_row(
        (41.172, 141), (41.17532392625723, 111), (37.31772281517573, 59)
    ),
    ("signed_exact", 110, 257): _estimator_result_row(
        (42.339999999999996, 145), (42.63945816115274, 120), (38.00724054165258, 59)
    ),
    ("signed_exact", 120, 257): _estimator_result_row(
        (44.967999999999996, 154), (45.284968691389956, 135), (39.23461900231796, 54)
    ),
    ("signed_exact", 130, 257): _estimator_result_row(
        (47.596, 163), (47.65151116550912, 147), (40.336576045111926, 50)
    ),
    ("signed_exact", 135, 257): _estimator_result_row(
        (48.763999999999996, 167),
        (48.846432323285555, 153),
        (40.83433017137583, 56),
    ),
    ("iid_binary", 70, 769): _estimator_result_row(
        (32.412, 111), (32.704087081528, 64), (32.704087081528, 64)
    ),
    ("iid_binary", 72, 1229): _estimator_result_row(
        (33.288, 114), (33.58010661622191, 68), (33.58010661622191, 68)
    ),
    ("iid_binary", 74, 2053): _estimator_result_row(
        (34.163999999999994, 117), (34.74823955538996, 76), (34.74823955538996, 76)
    ),
    ("iid_binary", 76, 4093): _estimator_result_row(
        (35.332, 121), (35.62429329088568, 80), (35.62429329088568, 80)
    ),
    ("iid_binary", 78, 257): _estimator_result_row(
        (36.208, 124), (36.50053822509965, 86), (36.50053822509965, 86)
    ),
    ("iid_binary", 80, 769): _estimator_result_row(
        (37.083999999999996, 127), (37.376658940996165, 90), (37.376658940996165, 90)
    ),
    ("iid_binary", 82, 1229): _estimator_result_row(
        (37.96, 130), (38.25280672411342, 94), (38.25280672411342, 94)
    ),
    ("iid_binary", 84, 2053): _estimator_result_row(
        (39.128, 134), (39.13712601639486, 109), (39.13712601640679, 109)
    ),
    ("iid_binary", 86, 4093): _estimator_result_row(
        (40.004, 137), (40.29781207733197, 105), (40.29781207733197, 105)
    ),
    ("iid_binary", 88, 257): _estimator_result_row(
        (41.172, 141), (41.17532392625723, 111), (41.17532392625723, 111)
    ),
}

_ESTIMATOR_MITM_RESULTS: dict[tuple[str, int, int], tuple[float, int]] = {
    ("binary_exact", 80, 257): (40.90637776988875, 40),
    ("binary_exact", 85, 257): (41.62204563721989, 40),
    ("binary_exact", 90, 257): (42.294862948037284, 40),
    ("binary_exact", 100, 257): (43.458062915392, 40),
    ("binary_exact", 105, 257): (44.0203821306462, 40),
    ("binary_exact", 110, 257): (44.556546128378145, 40),
    ("binary_exact", 120, 257): (45.557866417667384, 40),
    ("binary_exact", 130, 257): (46.40967814246311, 40),
    ("binary_exact", 140, 257): (47.248622434491466, 40),
    ("binary_exact", 150, 257): (48.02924098595956, 40),
    ("signed_exact", 75, 257): (45.666030612501935, 40),
    ("signed_exact", 80, 257): (46.462194070739216, 40),
    ("signed_exact", 85, 257): (47.04887653389234, 40),
    ("signed_exact", 90, 257): (47.75132368796038, 40),
    ("signed_exact", 100, 257): (49.01305176410212, 40),
    ("signed_exact", 105, 257): (49.602063947465155, 40),
    ("signed_exact", 110, 257): (50.131231450037134, 41),
    ("signed_exact", 120, 257): (51.04723520142814, 40),
    ("signed_exact", 130, 257): (51.99764160533133, 40),
    ("signed_exact", 135, 257): (52.413367381455345, 41),
    ("iid_binary", 70, 769): (48.628189161278286, 40),
    ("iid_binary", 72, 1229): (49.597317681605176, 40),
    ("iid_binary", 74, 2053): (43.454088094403396, 40),
    ("iid_binary", 76, 4093): (45.476740164433934, 44),
    ("iid_binary", 78, 257): (52.640227787372446, 40),
    ("iid_binary", 80, 769): (53.59675490677229, 40),
    ("iid_binary", 82, 1229): (54.56191781848779, 40),
    ("iid_binary", 84, 2053): (55.559922344634415, 40),
    ("iid_binary", 86, 4093): (56.55333622196682, 40),
    ("iid_binary", 88, 257): (57.606695987863674, 40),
}
_FORMAT_TEXT = """# Structured-LWE public corpus format

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
"""


def _easy_target_seconds(family_index: int, easy_bin: int) -> float:
    low, high = _EASY_BOUNDS_SECONDS[easy_bin]
    fraction = ((family_index + easy_bin) % 10 + 0.5) / 10
    return low * (high / low) ** fraction


def _hard_octave(family_index: int, local_index: int) -> int:
    return (family_index + local_index) % 10


def _hard_target_hours(octave: int, position: int) -> float:
    return 2 ** (octave + (position + 0.5) / 14)


def _runtime_bounds_seconds(runtime_bin: str) -> tuple[float, float]:
    if runtime_bin.startswith("E"):
        low, high = _EASY_BOUNDS_SECONDS[int(runtime_bin[1:])]
        return float(low), float(high)
    octave = int(runtime_bin[1:])
    return (
        3600.0 * 2**octave,
        min(3600.0 * 2 ** (octave + 1), _MAX_RUNTIME_SECONDS),
    )


def build_slots() -> list[dict[str, object]]:
    """Return the stable 10-family, 200-instance public slot allocation."""

    slots: list[dict[str, object]] = []
    next_id = 1
    for family_index, family in enumerate(FAMILY_CODES):
        for easy_index in range(6):
            slots.append(
                {
                    "instance_id": f"lwe_{next_id:04d}",
                    "family": family,
                    "tier": "easy",
                    "cohort": "paper",
                    "runtime_bin": f"E{easy_index}",
                    "octave": None,
                    "target_runtime_seconds": _easy_target_seconds(
                        family_index, easy_index
                    ),
                }
            )
            next_id += 1
        for hard_index in range(14):
            octave = _hard_octave(family_index, hard_index)
            slots.append(
                {
                    "instance_id": f"lwe_{next_id:04d}",
                    "family": family,
                    "tier": "hard",
                    "cohort": "ladder",
                    "runtime_bin": f"H{octave}",
                    "octave": octave,
                    "target_runtime_seconds": 3600.0
                    * _hard_target_hours(octave, hard_index),
                }
            )
            next_id += 1
    return slots


def _matrix_seed(instance_id: str) -> str:
    payload = (
        b"FCS-STRUCTURED-LWE-PUBLIC-MATRIX-SEED-v1\x00"
        + instance_id.encode("ascii")
    )
    # The original lwe_0083 realization exposed a reproducible 3.12-second
    # fast tail for the release solver despite its E2 model.  Salt 11 was
    # selected by a bounded public-realization screen: the same solver/seed
    # recovered in 42.262039 seconds, inside E2 and near its 39.422135-second
    # analytical median.  The salt affects only the public matrix seed.
    if instance_id == "lwe_0083":
        payload += b"\x00retune\x0011"
    return hashlib.sha256(payload).hexdigest()


def _matrix_parameters(family: str, n: int) -> dict[str, object]:
    sparse_weight = min(n - 1, math.ceil(2 * math.sqrt(n)))
    if family in {"DS_BIN", "DS_TER", "DS_SMALL"}:
        return {"kind": "uniform", "alphabet": [], "row_weight": None}
    if family in {"SA_Q", "MIX_Q_SPARSE"}:
        return {
            "kind": "sparse_uniform",
            "alphabet": [],
            "row_weight": sparse_weight,
        }
    if family in {"SA_SMALL", "MIX_SMALL_SPARSE"}:
        return {
            "kind": "sparse_small_alphabet",
            "alphabet": [-1, 1],
            "row_weight": sparse_weight,
        }
    if family == "DA_BIN":
        return {"kind": "small_alphabet", "alphabet": [0, 1], "row_weight": None}
    return {
        "kind": "small_alphabet",
        "alphabet": [-1, 0, 1],
        "row_weight": None,
    }


def _exact_secret(
    *, n: int, weight: int, signed: bool
) -> tuple[dict[str, object], dict[str, object]]:
    nonzero_alphabet = [-1, 1] if signed else [1]
    predicate_alphabet = [-1, 0, 1] if signed else [0, 1]
    return (
        {
            "kind": "exact_weight_alphabet",
            "alphabet": nonzero_alphabet,
            "weight": weight,
            "eta": None,
        },
        {
            "kind": "alphabet",
            "alphabet": predicate_alphabet,
            "min_nonzero": weight,
            "max_nonzero": weight,
        },
    )


def _uniform_mod_q_secret(
    n: int,
) -> tuple[dict[str, object], dict[str, object]]:
    return (
        {
            "kind": "uniform_mod_q",
            "alphabet": [],
            "weight": None,
            "eta": None,
        },
        {
            "kind": "mod_q",
            "alphabet": [],
            "min_nonzero": 0,
            "max_nonzero": n,
        },
    )


def _dense_small_secret(
    n: int,
) -> tuple[dict[str, object], dict[str, object]]:
    alphabet = [0, 1]
    return (
        {
            "kind": "iid_alphabet",
            "alphabet": alphabet,
            "weight": None,
            "eta": None,
        },
        {
            "kind": "alphabet",
            "alphabet": alphabet,
            "min_nonzero": 0,
            "max_nonzero": n,
        },
    )


def _nearest_exact_secret_model(
    *,
    family: str,
    local_index: int,
    target_seconds: float,
    runtime_bounds_seconds: tuple[float, float],
) -> tuple[int, int, bool, dict[str, object]]:
    signed = family == "DS_TER" or (
        family not in {"DS_BIN", "DS_TER"} and bool(local_index % 2)
    )
    alphabet_size = 2 if signed else 1
    candidates: list[tuple[float, int, int, int, float]] = []
    for n in range(8, 129):
        rate = _EASY_EXACT_SECRET_RATE_NUMERATOR / n
        for weight in range(2, min(14, n // 3) + 1):
            work = math.comb(n, weight) * alphabet_size**weight
            predicted = work / rate
            if not (
                runtime_bounds_seconds[0]
                <= predicted
                <= runtime_bounds_seconds[1]
            ):
                continue
            distance = abs(math.log(predicted / target_seconds))
            candidates.append((distance, n, weight, work, predicted))
    _, n, weight, work, predicted = min(candidates)
    rate = _EASY_EXACT_SECRET_RATE_NUMERATOR / n
    model = {
        "model_id": "analytical-secret-enumeration-v1",
        "formula": (
            "binomial(n,h)*nonzero_alphabet_size^h/"
            f"({_EASY_EXACT_SECRET_RATE_NUMERATOR:g}/n)"
        ),
        "rate_model": "2*measured_candidate_rate_n_product/n",
        "measured_candidate_rate_n_product": (
            _EASY_EXACT_SECRET_RATE_NUMERATOR / 2.0
        ),
        "assumed_rate_per_second": rate,
        "work_factor": work,
        "nonzero_alphabet_size": alphabet_size,
        "predicted_runtime_seconds": predicted,
    }
    return n, weight, signed, model


def _nearest_mixed_q_screened_exact_model(
    *,
    local_index: int,
    q: int,
    target_seconds: float,
    runtime_bounds_seconds: tuple[float, float],
) -> tuple[int, int, bool, dict[str, object]]:
    """Select an exact-enumeration point with a non-runtime mixed screen."""

    signed = bool(local_index % 2)
    alphabet_size = 2 if signed else 1
    candidates: list[
        tuple[int, float, int, int, float, float, float]
    ] = []
    for n in range(8, 2_049):
        enumeration_rate = _EASY_EXACT_SECRET_RATE_NUMERATOR / n
        sizing_screen_seconds = n**3 / _EASY_MIXED_FILTER_SIZING_DIVISOR
        if sizing_screen_seconds < runtime_bounds_seconds[0]:
            continue
        for weight in range(2, min(14, n // 3) + 1):
            work = math.comb(n, weight) * alphabet_size**weight
            enumeration_runtime = work / enumeration_rate
            if not (
                runtime_bounds_seconds[0]
                <= enumeration_runtime
                <= runtime_bounds_seconds[1]
            ):
                continue
            candidates.append(
                (
                    -weight,
                    abs(math.log(enumeration_runtime / target_seconds)),
                    n,
                    work,
                    enumeration_rate,
                    enumeration_runtime,
                    sizing_screen_seconds,
                )
            )
    (
        negative_weight,
        _,
        n,
        work,
        enumeration_rate,
        enumeration_runtime,
        sizing_screen_seconds,
    ) = min(candidates)
    weight = -negative_weight
    enumeration = {
        "attack_id": "exact-secret-enumeration",
        "formula": (
            "binomial(n,h)*nonzero_alphabet_size^h/"
            f"({_EASY_EXACT_SECRET_RATE_NUMERATOR:g}/n)"
        ),
        "work_factor": work,
        "nonzero_alphabet_size": alphabet_size,
        "rate_model": "2*measured_candidate_rate_n_product/n",
        "measured_candidate_rate_n_product": (
            _EASY_EXACT_SECRET_RATE_NUMERATOR / 2.0
        ),
        "assumed_rate_per_second": enumeration_rate,
        "predicted_runtime_seconds": enumeration_runtime,
    }
    m = 2 * n + 8
    row_weight = min(n - 1, math.ceil(2 * math.sqrt(n)))
    mixed_filter = {
        "attack_id": "mixed-filter-greedy",
        "applicability": (
            "heuristic statistical regime q <= 3^k; release-byte screen "
            "required"
        ),
        "paper_asymptotic_complexity": "O(m*k*3^k)",
        "paper_work_factor": m * row_weight * 3**row_weight,
        "paper_parameters": {
            "m": m,
            "k": row_weight,
            "q": q,
            "q_le_3_pow_k": q <= 3**row_weight,
        },
        "runtime_prediction_status": "not-modeled",
        "release_screen": {
            "required_no_recovery_before_seconds": runtime_bounds_seconds[0],
            "evidence_location": "CALIBRATION.md",
        },
        "candidate_sizing_screen": {
            "formula": f"n^3/{_EASY_MIXED_FILTER_SIZING_DIVISOR:g}",
            "divisor": _EASY_MIXED_FILTER_SIZING_DIVISOR,
            "value_seconds": sizing_screen_seconds,
            "interpretation": (
                "non-runtime dimension-sizing screen; not an attack bound"
            ),
        },
    }
    return n, weight, signed, {
        "model_id": "analytical-easy-exact-secret-with-mixed-screen-v1",
        "formula": "exact_secret_enumeration",
        "selection_rule": (
            "maximize exact secret weight, then minimize log-distance to the "
            "slot target subject to the exact-runtime bin and sizing screen"
        ),
        "attacks": [enumeration, mixed_filter],
        "selected_attack": enumeration["attack_id"],
        "predicted_runtime_seconds": enumeration_runtime,
    }


def _nearest_dense_small_model(
    target_seconds: float,
    runtime_bounds_seconds: tuple[float, float],
) -> tuple[int, dict[str, object]]:
    alphabet_size = 2
    candidates: list[tuple[float, int, int, float]] = []
    for n in range(1, 41):
        work = alphabet_size**n
        predicted = work / _DENSE_SMALL_RATE
        if not (
            runtime_bounds_seconds[0]
            <= predicted
            <= runtime_bounds_seconds[1]
        ):
            continue
        candidates.append(
            (abs(math.log(predicted / target_seconds)), n, work, predicted)
        )
    _, n, work, predicted = min(candidates)
    model = {
        "model_id": "analytical-dense-domain-enumeration-v1",
        "formula": "secret_alphabet_size^n/rate",
        "assumed_rate_per_second": _DENSE_SMALL_RATE,
        "work_factor": work,
        "secret_alphabet_size": alphabet_size,
        "predicted_runtime_seconds": predicted,
    }
    return n, model


def _enumeration_attack(
    *, family: str, n: int, weight: int | None, signed: bool
) -> dict[str, object]:
    if weight is None:
        work = 2**n
        rate = _DENSE_SMALL_RATE
        formula = "secret_alphabet_size^n/rate"
        attack_id = "dense-domain-enumeration"
    else:
        sign_assignment_count = math.comb(weight, weight // 2) if signed else 1
        work = math.comb(n, weight) * sign_assignment_count
        rate = _EXACT_SECRET_RATES[family]
        formula = (
            "binomial(n,h)*binomial(h,h/2)/rate"
            if signed
            else "binomial(n,h)/rate"
        )
        attack_id = "exact-secret-enumeration"
    return {
        "attack_id": attack_id,
        "formula": formula,
        "work_factor": work,
        "sign_assignment_count": (
            sign_assignment_count if weight is not None else None
        ),
        "assumed_rate_per_second": rate,
        "predicted_runtime_seconds": work / rate,
    }


def _normal_lwe_estimator_proxy(
    *,
    family: str,
    n: int,
    q: int,
    signed: bool,
    dense_small: bool,
) -> dict[str, object]:
    secret_kind = "iid_binary" if dense_small else (
        "signed_exact" if signed else "binary_exact"
    )
    result_key = (secret_kind, n, q)
    attack_results = [dict(result) for result in _ESTIMATOR_RESULTS[result_key]]
    mitm_rop_log2, mitm_beta = _ESTIMATOR_MITM_RESULTS[result_key]
    attack_results.append(
        {
            "algorithm": "primal_hybrid_mitm",
            "options": {"mitm": True, "babai": True},
            "rop_log2": mitm_rop_log2,
            "beta": mitm_beta,
        }
    )
    fastest_rop_log2 = min(float(result["rop_log2"]) for result in attack_results)
    if dense_small:
        estimator_secret_distribution = "Uniform(0,1)"
        secret_mapping = "exact iid binary distribution"
    elif signed:
        estimator_secret_distribution = "SparseTernary(7,7)"
        secret_mapping = (
            "exact mapping for the balanced planted distribution; the verifier "
            "predicate also permits unbalanced alternate valid secrets"
        )
    else:
        estimator_secret_distribution = "SparseBinary(14)"
        secret_mapping = "exact fixed-weight binary distribution"
    matrix_model = (
        "uniform public matrix"
        if family in {"DS_BIN", "DS_TER", "DS_SMALL"}
        else "uniform-matrix normal-LWE proxy for a nonuniform public matrix"
    )
    return {
        "attack_id": "normal-lwe-estimator-proxy",
        "applicability": "heuristic proxy, not a reduction or hardness claim",
        "matrix_model": matrix_model,
        "secret_mapping": secret_mapping,
        "attack_results": attack_results,
        "fastest_rop_log2": fastest_rop_log2,
        "normalization": {
            "formula": "2^fastest_rop_log2/rop_per_second",
            "rop_per_second": _ESTIMATOR_ROP_PER_SECOND,
        },
        "predicted_runtime_seconds": (
            2**fastest_rop_log2 / _ESTIMATOR_ROP_PER_SECOND
        ),
        "configuration": {
            "n": n,
            "m": n + 8,
            "q": q,
            "estimator_secret_distribution": estimator_secret_distribution,
            "estimator_error_distribution": (
                f"Uniform(-{(q - 1) // 8},{(q - 1) // 8})"
            ),
            "reduction_cost_model": "ADPS16",
            "reduction_shape_model": "gsa",
        },
        "provenance": {
            "source_archive_sha256": _ESTIMATOR_SOURCE_ARCHIVE_SHA256,
            "cached_image_digest": _ESTIMATOR_CACHED_IMAGE_DIGEST,
        },
    }


def _hard_secret_portfolio_model(
    *,
    family: str,
    n: int,
    q: int,
    signed: bool = False,
    dense_small: bool = False,
) -> dict[str, object]:
    enumeration = _enumeration_attack(
        family=family,
        n=n,
        weight=None if dense_small else _HARD_EXACT_SECRET_WEIGHT,
        signed=signed,
    )
    estimator = _normal_lwe_estimator_proxy(
        family=family,
        n=n,
        q=q,
        signed=signed,
        dense_small=dense_small,
    )
    attacks = [enumeration, estimator]
    selected = min(attacks, key=lambda attack: attack["predicted_runtime_seconds"])
    return {
        "model_id": "analytical-attack-portfolio-min-v1",
        "formula": "min(enumeration_seconds,normal_lwe_proxy_seconds)",
        "attacks": attacks,
        "selected_attack": selected["attack_id"],
        "predicted_runtime_seconds": selected["predicted_runtime_seconds"],
    }


def _nearest_clean_subset_model(
    *,
    target_seconds: float,
    runtime_bounds_seconds: tuple[float, float],
    minimum_n: int = 8,
    baseline_rate_at_n16: float = _CLEAN_SUBSET_RATE_AT_N16,
    minimum_rate: float = _CLEAN_SUBSET_MINIMUM_RATE,
) -> tuple[int, int, int, dict[str, object]]:
    candidates: list[tuple[float, int, int, int, float, float, float]] = []
    for n in range(minimum_n, 129):
        rate = max(
            baseline_rate_at_n16 * (16.0 / n) ** 1.5,
            minimum_rate,
        )
        m = 3 * n
        denominator = math.comb(m, n)
        for error_weight in range(1, 2 * n + 1):
            clean_probability = math.comb(m - error_weight, n) / denominator
            median_attempts = math.log(2.0) / clean_probability
            predicted = median_attempts / rate
            if not (
                runtime_bounds_seconds[0]
                <= predicted
                <= runtime_bounds_seconds[1]
            ):
                continue
            candidates.append(
                (
                    abs(math.log(predicted / target_seconds)),
                    n,
                    m,
                    error_weight,
                    clean_probability,
                    median_attempts,
                    predicted,
                )
            )
    (
        _,
        n,
        m,
        error_weight,
        clean_probability,
        median_attempts,
        predicted,
    ) = min(candidates)
    rate = max(
        baseline_rate_at_n16 * (16.0 / n) ** 1.5,
        minimum_rate,
    )
    model = {
        "model_id": "analytical-clean-subset-v2",
        "formula": (
            "ln(2)/(clean_subset_probability*"
            f"max({baseline_rate_at_n16:g}*(16/n)^1.5,{minimum_rate:g}))"
        ),
        "baseline_rate_at_n16_per_second": baseline_rate_at_n16,
        "minimum_rate_per_second": minimum_rate,
        "assumed_rate_per_second": rate,
        "clean_subset_probability": clean_probability,
        "median_attempts": median_attempts,
        "predicted_runtime_seconds": predicted,
    }
    return n, m, error_weight, model


def _error_parameters(
    m: int,
    q: int,
    local_index: int,
    *,
    forced_sparse_weight: int | None = None,
    widen_to_q_eighth: bool = False,
    varied_wide_distribution: bool = False,
) -> tuple[dict[str, object], dict[str, object]]:
    if widen_to_q_eighth:
        bound = (q - 1) // 8
        if forced_sparse_weight is not None:
            distribution: dict[str, object] = {
                "kind": "sparse_bounded",
                "sigma": None,
                "eta": None,
                "bound": bound,
                "weight": forced_sparse_weight,
            }
        elif varied_wide_distribution and local_index % 2 == 0:
            distribution = {
                "kind": "truncated_discrete_gaussian",
                "sigma": max(1.25, bound / 3.0),
                "eta": None,
                "bound": bound,
                "weight": None,
            }
        else:
            distribution = {
                "kind": "bounded_uniform",
                "sigma": None,
                "eta": None,
                "bound": bound,
                "weight": None,
            }
    else:
        kind = (
            "sparse_bounded"
            if forced_sparse_weight is not None
            else _ERROR_KINDS[local_index % len(_ERROR_KINDS)]
        )
        if kind == "truncated_discrete_gaussian":
            distribution = {
                "kind": kind,
                "sigma": 1.25,
                "eta": None,
                "bound": 3,
                "weight": None,
            }
        elif kind == "centered_binomial":
            distribution = {
                "kind": kind,
                "sigma": None,
                "eta": 2,
                "bound": 2,
                "weight": None,
            }
        elif kind == "bounded_uniform":
            distribution = {
                "kind": kind,
                "sigma": None,
                "eta": None,
                "bound": 1,
                "weight": None,
            }
        else:
            distribution = {
                "kind": kind,
                "sigma": None,
                "eta": None,
                "bound": 1,
                "weight": forced_sparse_weight,
            }
    bound = int(distribution["bound"])
    sparse_weight = distribution["weight"]
    active = int(sparse_weight) if sparse_weight is not None else m
    predicate = {
        "max_abs": bound,
        "max_l1": active * bound,
        "max_l2_squared": active * bound * bound,
        "max_nonzero": active,
    }
    return distribution, predicate


def build_specs() -> list[dict[str, object]]:
    """Build schema-valid, secret-free parameter specifications."""

    specs: list[dict[str, object]] = []
    for slot_index, slot in enumerate(build_slots()):
        family_index, local_index = divmod(slot_index, 20)
        family = str(slot["family"])
        target_runtime_seconds = float(slot["target_runtime_seconds"])
        runtime_bounds_seconds = _runtime_bounds_seconds(str(slot["runtime_bin"]))
        hard = slot["tier"] == "hard"
        octave = None if slot["octave"] is None else int(slot["octave"])
        q = _MODULI[(local_index + family_index) % len(_MODULI)]
        forced_sparse_weight: int | None = None
        if family == "MIX_Q_SPARSE" and not hard:
            n, secret_weight, signed, analytical_model = (
                _nearest_mixed_q_screened_exact_model(
                    local_index=local_index,
                    q=q,
                    target_seconds=target_runtime_seconds,
                    runtime_bounds_seconds=runtime_bounds_seconds,
                )
            )
            m = 2 * n + 8
            secret_distribution, secret = _exact_secret(
                n=n,
                weight=secret_weight,
                signed=signed,
            )
        elif family in _EXACT_SECRET_RATES and (
            hard or family in _EASY_ENUMERATION_FAMILIES
        ):
            signed = family == "DS_TER" or (
                family not in {"DS_BIN", "DS_TER"} and bool(local_index % 2)
            )
            if hard:
                if octave is None:
                    raise AssertionError("hard slots must carry an octave")
                q = 257
                n = (
                    _HARD_SIGNED_N_BY_OCTAVE
                    if signed
                    else _HARD_BINARY_N_BY_OCTAVE
                )[octave]
                secret_weight = _HARD_EXACT_SECRET_WEIGHT
                m = n + 8
                analytical_model = _hard_secret_portfolio_model(
                    family=family,
                    n=n,
                    q=q,
                    signed=signed,
                )
            else:
                n, secret_weight, signed, analytical_model = (
                    _nearest_exact_secret_model(
                        family=family,
                        local_index=local_index,
                        target_seconds=target_runtime_seconds,
                        runtime_bounds_seconds=runtime_bounds_seconds,
                    )
                )
                m = 2 * n + 8
            secret_distribution, secret = _exact_secret(
                n=n,
                weight=secret_weight,
                signed=signed,
            )
            if hard and signed:
                secret_distribution["kind"] = "balanced_exact_weight_signed"
        elif family == "DS_SMALL":
            if hard:
                if octave is None:
                    raise AssertionError("hard slots must carry an octave")
                n = _HARD_DENSE_SMALL_N_BY_OCTAVE[octave]
                m = n + 8
                analytical_model = _hard_secret_portfolio_model(
                    family=family,
                    n=n,
                    q=q,
                    dense_small=True,
                )
            else:
                n, m, forced_sparse_weight, analytical_model = (
                    _nearest_clean_subset_model(
                        target_seconds=target_runtime_seconds,
                        runtime_bounds_seconds=runtime_bounds_seconds,
                        baseline_rate_at_n16=(
                            _EASY_CLEAN_SUBSET_RATE_AT_N16[family]
                        ),
                        minimum_rate=_EASY_CLEAN_SUBSET_MINIMUM_RATE[family],
                    )
                )
            secret_distribution, secret = _dense_small_secret(n)
        elif family in _EASY_CLEAN_SUBSET_MIXED_FAMILIES:
            n, m, forced_sparse_weight, analytical_model = (
                _nearest_clean_subset_model(
                    target_seconds=target_runtime_seconds,
                    runtime_bounds_seconds=runtime_bounds_seconds,
                    minimum_n=40,
                    baseline_rate_at_n16=(
                        _EASY_CLEAN_SUBSET_RATE_AT_N16[family]
                    ),
                    minimum_rate=_EASY_CLEAN_SUBSET_MINIMUM_RATE[family],
                )
            )
            signed = bool(local_index % 2)
            secret_distribution, secret = _exact_secret(
                n=n,
                weight=14,
                signed=signed,
            )
        else:
            n, m, forced_sparse_weight, analytical_model = (
                _nearest_clean_subset_model(
                    target_seconds=target_runtime_seconds,
                    runtime_bounds_seconds=runtime_bounds_seconds,
                    minimum_n=96 if slot["tier"] == "hard" else 8,
                    baseline_rate_at_n16=(
                        _CLEAN_SUBSET_RATE_AT_N16
                        if hard
                        else _EASY_CLEAN_SUBSET_RATE_AT_N16[family]
                    ),
                    minimum_rate=(
                        _CLEAN_SUBSET_MINIMUM_RATE
                        if hard
                        else _EASY_CLEAN_SUBSET_MINIMUM_RATE[family]
                    ),
                )
            )
            secret_distribution, secret = _uniform_mod_q_secret(n)
        matrix = _matrix_parameters(family, n)
        matrix["seed_hex"] = _matrix_seed(str(slot["instance_id"]))
        matrix["expansion_domain"] = MATRIX_EXPANSION_DOMAIN
        error_distribution, error = _error_parameters(
            m,
            q,
            local_index,
            forced_sparse_weight=forced_sparse_weight,
            widen_to_q_eighth=True,
            varied_wide_distribution=not hard,
        )
        model_id = str(analytical_model["model_id"])
        predicted_runtime_seconds = float(
            analytical_model["predicted_runtime_seconds"]
        )
        specs.append(
            {
                **slot,
                "n": n,
                "m": m,
                "q": q,
                "matrix": matrix,
                "secret_distribution": secret_distribution,
                "secret": secret,
                "error_distribution": error_distribution,
                "error": error,
                "analysis_path": f"analyses/{slot['instance_id']}.md",
                "generator_version": "structured-lwe-corpus-v1",
                "calibration_status": "extrapolated",
                "calibration_model_id": model_id,
                "predicted_runtime_seconds": predicted_runtime_seconds,
                "measured_runtime_seconds": None,
                "analytical_model": analytical_model,
            }
        )
    return specs


def spec_to_template(spec: Mapping[str, object]) -> GenerationTemplate:
    """Convert one public parameter specification to the public generator API."""

    matrix = spec["matrix"]
    secret_distribution = spec["secret_distribution"]
    secret = spec["secret"]
    error_distribution = spec["error_distribution"]
    error = spec["error"]
    if not all(
        isinstance(value, Mapping)
        for value in (matrix, secret_distribution, secret, error_distribution, error)
    ):
        raise TypeError("nested parameter specifications must be mappings")
    return GenerationTemplate(
        instance_id=str(spec["instance_id"]),
        n=int(spec["n"]),
        m=int(spec["m"]),
        q=int(spec["q"]),
        matrix=MatrixSpec(
            kind=str(matrix["kind"]),
            seed_hex=str(matrix["seed_hex"]),
            expansion_domain=str(matrix["expansion_domain"]),
            alphabet=tuple(int(value) for value in matrix["alphabet"]),
            row_weight=(
                None if matrix["row_weight"] is None else int(matrix["row_weight"])
            ),
        ),
        secret_distribution=SecretDistributionSpec(
            kind=str(secret_distribution["kind"]),
            alphabet=tuple(int(value) for value in secret_distribution["alphabet"]),
            weight=(
                None
                if secret_distribution["weight"] is None
                else int(secret_distribution["weight"])
            ),
            eta=(
                None
                if secret_distribution["eta"] is None
                else int(secret_distribution["eta"])
            ),
        ),
        secret=SecretPredicateSpec(
            kind=str(secret["kind"]),
            alphabet=tuple(int(value) for value in secret["alphabet"]),
            min_nonzero=int(secret["min_nonzero"]),
            max_nonzero=int(secret["max_nonzero"]),
        ),
        error_distribution=ErrorDistributionSpec(
            kind=str(error_distribution["kind"]),
            sigma=(
                None
                if error_distribution["sigma"] is None
                else float(error_distribution["sigma"])
            ),
            eta=(
                None
                if error_distribution["eta"] is None
                else int(error_distribution["eta"])
            ),
            bound=int(error_distribution["bound"]),
            weight=(
                None
                if error_distribution["weight"] is None
                else int(error_distribution["weight"])
            ),
        ),
        error=ErrorPredicateSpec(
            max_abs=int(error["max_abs"]),
            max_l1=None if error["max_l1"] is None else int(error["max_l1"]),
            max_l2_squared=(
                None
                if error["max_l2_squared"] is None
                else int(error["max_l2_squared"])
            ),
            max_nonzero=(
                None if error["max_nonzero"] is None else int(error["max_nonzero"])
            ),
        ),
        family=str(spec["family"]),
        tier=str(spec["tier"]),
        cohort=str(spec["cohort"]),
        octave=None if spec["octave"] is None else int(spec["octave"]),
        runtime_bin=str(spec["runtime_bin"]),
        analysis_path=str(spec["analysis_path"]),
        generator_version=str(spec["generator_version"]),
        calibration_status=str(spec["calibration_status"]),
        calibration_model_id=str(spec["calibration_model_id"]),
        predicted_runtime_seconds=float(spec["predicted_runtime_seconds"]),
        measured_runtime_seconds=(
            None
            if spec["measured_runtime_seconds"] is None
            else float(spec["measured_runtime_seconds"])
        ),
    )


_COMPATIBILITY_FIELDS = (
    "schema_version",
    "instance_id",
    "n",
    "m",
    "q",
    "matrix",
    "secret_distribution",
    "secret",
    "error_distribution",
    "error",
    "family",
    "tier",
    "cohort",
    "octave",
    "runtime_bin",
    "generator_version",
)
_REUSABLE_METADATA_FIELDS = (
    "analysis_path",
    "calibration_status",
    "calibration_model_id",
    "predicted_runtime_seconds",
    "measured_runtime_seconds",
)


def _expected_compatibility_fields(
    spec: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema_version": 1,
        **{field: spec[field] for field in _COMPATIBILITY_FIELDS[1:]},
    }


def reuse_compatible_record(
    existing_record: Mapping[str, object],
    spec: Mapping[str, object],
) -> dict[str, object] | None:
    """Reuse a valid public record only when every bound field is unchanged."""

    existing = dict(existing_record)
    try:
        _parse_instance(existing)
        actual = {field: existing[field] for field in _COMPATIBILITY_FIELDS}
        expected = _expected_compatibility_fields(spec)
    except (KeyError, TypeError, ValueError):
        return None
    if actual != expected:
        return None
    updated = dict(existing)
    for field in _REUSABLE_METADATA_FIELDS:
        updated[field] = spec[field]
    try:
        _parse_instance(updated)
    except (TypeError, ValueError):
        return None
    return updated


def _load_reusable_records(path: Path) -> dict[str, dict[str, object]]:
    catalog = Catalog.load(path)
    raw_records = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    if len(raw_records) != len(catalog.instances):
        raise ValueError("reusable catalog record count changed while loading")
    reusable: dict[str, dict[str, object]] = {}
    for instance, raw_record in zip(catalog.instances, raw_records):
        if type(raw_record) is not dict or raw_record.get("instance_id") != (
            instance.instance_id
        ):
            raise ValueError("reusable catalog record order is inconsistent")
        reusable[instance.instance_id] = raw_record
    return reusable


def build_public_records(
    specs: list[dict[str, object]] | None = None,
    *,
    reusable_records: Mapping[str, Mapping[str, object]] | None = None,
) -> tuple[
    list[dict[str, object]],
    tuple[str, ...],
    tuple[str, ...],
]:
    """Reuse compatible records and freshly generate every changed record."""

    selected_specs = build_specs() if specs is None else specs
    reusable_records = {} if reusable_records is None else reusable_records
    records: list[dict[str, object]] = []
    generated_ids: list[str] = []
    reused_ids: list[str] = []
    for spec in selected_specs:
        instance_id = str(spec["instance_id"])
        existing = reusable_records.get(instance_id)
        reused = (
            None
            if existing is None
            else reuse_compatible_record(existing, spec)
        )
        if reused is not None:
            records.append(reused)
            reused_ids.append(instance_id)
            continue
        generated = generate_production_instance(template=spec_to_template(spec))
        public_record = generated.public_json()
        del generated
        records.append(public_record)
        generated_ids.append(instance_id)
    records.sort(key=lambda record: str(record["instance_id"]))
    return records, tuple(generated_ids), tuple(reused_ids)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_bytes(payload)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_public_assets(
    output_dir: Path,
    *,
    reuse_compatible_catalog: Path | None = None,
    force_regenerate: frozenset[str] = frozenset(),
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    """Write public assets, reusing only cryptographically compatible records."""

    output_dir = output_dir.resolve()
    slots = build_slots()
    specs = build_specs()
    reusable_records = (
        {}
        if reuse_compatible_catalog is None
        else _load_reusable_records(reuse_compatible_catalog.resolve())
    )
    known_ids = {str(spec["instance_id"]) for spec in specs}
    unknown_forced = force_regenerate - known_ids
    if unknown_forced:
        raise ValueError(
            "unknown forced instance IDs: " + ",".join(sorted(unknown_forced))
        )
    for instance_id in force_regenerate:
        reusable_records.pop(instance_id, None)
    records, generated_ids, reused_ids = build_public_records(
        specs,
        reusable_records=reusable_records,
    )

    slots_bytes = (
        json.dumps(
            slots,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    _atomic_write(output_dir / "slots.json", slots_bytes)

    specs_dir = output_dir / "specs"
    specs_dir.mkdir(parents=True, exist_ok=True)
    expected_names: set[str] = set()
    for spec in specs:
        name = f"{spec['instance_id']}.json"
        expected_names.add(name)
        spec_bytes = (
            json.dumps(
                spec,
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        _atomic_write(specs_dir / name, spec_bytes)
    for stale in specs_dir.glob("lwe_*.json"):
        if stale.name not in expected_names:
            stale.unlink()

    catalog_bytes = b"".join(
        canonical_record_bytes(record) + b"\n" for record in records
    )
    digest = hashlib.sha256(catalog_bytes).hexdigest()
    _atomic_write(output_dir / "catalog.jsonl", catalog_bytes)
    _atomic_write(
        output_dir / "catalog.sha256",
        f"{digest}  catalog.jsonl\n".encode("ascii"),
    )
    _atomic_write(output_dir / "format.md", _FORMAT_TEXT.encode("utf-8"))
    return digest, generated_ids, reused_ids


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument(
        "--reuse-compatible-catalog",
        type=Path,
        help=(
            "reuse b and instance_digest only for records whose complete "
            "cryptographic/specification fields still match"
        ),
    )
    parser.add_argument(
        "--force-regenerate",
        action="append",
        default=[],
        metavar="INSTANCE_ID",
        help=(
            "generate this instance from fresh entropy even when compatible "
            "with the reuse catalog; may be repeated"
        ),
    )
    args = parser.parse_args(argv)
    digest, generated_ids, reused_ids = write_public_assets(
        args.output_dir,
        reuse_compatible_catalog=args.reuse_compatible_catalog,
        force_regenerate=frozenset(args.force_regenerate),
    )
    print(f"wrote 200 public instances; catalog sha256={digest}")
    print(f"generated {len(generated_ids)}: {','.join(generated_ids)}")
    print(f"reused {len(reused_ids)}: {','.join(reused_ids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
