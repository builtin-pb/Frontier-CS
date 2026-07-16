from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import pytest


TASK_DIR = Path(__file__).resolve().parents[1]
APP_DIR = TASK_DIR / "harbor" / "app"
CATALOG_PATH = APP_DIR / "public" / "catalog.jsonl"
NORMAL_LWE_PATH = APP_DIR / "analyses" / "normal_lwe.jsonl"

CATALOG_SHA256 = (
    "bb24a596e43f781c4824c94292cd0093bb3f8da2b3fdd895337281df89d94081"
)
SOURCE_COMMIT = "3e48ef421ec256afddb3e7d2249a77eab6e9ba12"
SOURCE_REPOSITORY = "https://github.com/malb/lattice-estimator"
SOURCE_ARCHIVE_SHA256 = (
    "aab320966fe4dc496a44e9223ab67d622e581d9ed052697e758907b0e437d539"
)
IMAGE_DIGEST = (
    "725595ce2bb23a86890808074388c24b01903c46f2a78f9aa5ca57412a7cbfee"
)
IMAGE_REFERENCE = "lwe-estimator-phase3:latest"
BASE_IMAGE = (
    "sagemath/sagemath:10.6@sha256:"
    "19995db6194f4a4bab18ce9a88556fd15b9ed5e916b4504fefe618a7796ddbdb"
)
ATTACK_ALGORITHMS = {
    "usvp": "primal_usvp",
    "bdd": "primal_bdd",
    "bdd_hybrid": "primal_hybrid",
    "bdd_mitm_hybrid": "primal_mitm_hybrid",
}
DOSSIER_HEADING = "## All-record normal-LWE cross-check"


def _load_jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def _assert_finite_numbers(value: object) -> None:
    if isinstance(value, dict):
        for nested in value.values():
            _assert_finite_numbers(nested)
    elif isinstance(value, list):
        for nested in value:
            _assert_finite_numbers(nested)
    elif isinstance(value, float):
        assert math.isfinite(value)


def test_normal_lwe_sweep_is_complete_sorted_and_bound_to_catalog() -> None:
    catalog = _load_jsonl(CATALOG_PATH)
    rows = _load_jsonl(NORMAL_LWE_PATH)

    assert len(catalog) == len(rows) == 200
    encoded_lines = NORMAL_LWE_PATH.read_text(encoding="utf-8").splitlines()
    assert encoded_lines == [
        json.dumps(
            row,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        for row in rows
    ]
    assert hashlib.sha256(CATALOG_PATH.read_bytes()).hexdigest() == CATALOG_SHA256
    instance_ids = [row["instance_id"] for row in rows]
    assert instance_ids == sorted(instance_ids)
    assert len(set(instance_ids)) == 200

    by_id = {record["instance_id"]: record for record in catalog}
    assert set(instance_ids) == set(by_id)
    for row in rows:
        instance_id = row["instance_id"]
        record = by_id[instance_id]
        assert row["schema_version"] == 1
        assert row["catalog_sha256"] == CATALOG_SHA256
        assert row["instance_digest"] == record["instance_digest"]
        assert row["configuration"]["n"] == record["n"]
        assert row["configuration"]["m"] == record["m"]
        assert row["configuration"]["q"] == record["q"]


def test_normal_lwe_sweep_retains_pinned_primal_results_and_finite_ceiling() -> None:
    rows = _load_jsonl(NORMAL_LWE_PATH)

    for row in rows:
        provenance = row["provenance"]
        assert provenance["source_repository"] == SOURCE_REPOSITORY
        assert provenance["source_commit"] == SOURCE_COMMIT
        assert provenance["source_archive_sha256"] == SOURCE_ARCHIVE_SHA256
        assert provenance["image_reference"] == IMAGE_REFERENCE
        assert provenance["image_digest"] == IMAGE_DIGEST
        assert provenance["base_image"] == BASE_IMAGE

        configuration = row["configuration"]
        assert configuration["reduction_cost_model"] == "ADPS16"
        assert configuration["reduction_shape_model"] == "gsa"

        result = row["result"]
        attacks = result["attacks"]
        assert len(attacks) == 4
        assert {
            attack["upstream_key"]: attack["algorithm"] for attack in attacks
        } == ATTACK_ALGORITHMS
        finite_attacks = [
            attack for attack in attacks if attack["status"] == "finite"
        ]
        for attack in attacks:
            assert attack["optimizer_floor_hit"] == (attack["beta"] == 40)
            if attack["status"] == "finite":
                assert attack["rop_log2"] is not None
                assert attack["failure_type"] is None
            elif attack["status"] == "unavailable":
                assert attack["rop_log2"] is None
                assert attack["failure_type"]
            else:
                assert attack["status"] == "infinite_or_nonfinite"
                assert attack["rop_log2"] is None
        fallback = result["generic_fallback"]
        n = configuration["n"]
        m = configuration["m"]
        q = configuration["q"]
        candidate_count_log2 = n * math.log2(q)
        operations_per_candidate = m * (2 * n + 8)
        assert fallback == {
            "upstream_key": "generic_full_secret_enumeration",
            "algorithm": "full_secret_enumeration",
            "status": "finite",
            "failure_type": None,
            "rop_log2": pytest.approx(
                candidate_count_log2 + math.log2(operations_per_candidate)
            ),
            "candidate_count_log2": pytest.approx(candidate_count_log2),
            "operations_per_candidate": operations_per_candidate,
            "beta": None,
            "lattice_dimension": None,
            "optimizer_floor_hit": False,
            "interpretation": (
                "q^n exhaustive secrets with m*(2*n+8) conservative abstract "
                "modular operations per candidate"
            ),
        }
        finite_candidates = [*finite_attacks, fallback]
        assert result["upstream_key"] in {
            attack["upstream_key"] for attack in finite_candidates
        }
        selected = next(
            attack
            for attack in finite_candidates
            if attack["upstream_key"] == result["upstream_key"]
        )
        assert result["rop_log2"] == selected["rop_log2"]
        assert result["rop_log2"] == min(
            attack["rop_log2"] for attack in finite_candidates
        )
        assert result["algorithm"] == selected["algorithm"]
        assert result["normalization_rop_per_second"] == 1_000_000.0
        assert (
            result["normalization_interpretation"]
            == "reporting_convention_not_wall_clock"
        )
        assert result["selection_scope"] == "non_selecting_cross_check"
        _assert_finite_numbers(row)


def test_normal_lwe_mapping_labels_track_exact_and_proxy_inputs() -> None:
    catalog = {
        record["instance_id"]: record for record in _load_jsonl(CATALOG_PATH)
    }
    rows = _load_jsonl(NORMAL_LWE_PATH)

    for row in rows:
        record = catalog[row["instance_id"]]
        matrix_is_exact = row["matrix_mapping"].startswith("exact ")
        error_is_exact = row["error_mapping"].startswith("exact ")
        assert matrix_is_exact == (record["matrix"]["kind"] == "uniform")
        assert error_is_exact == (
            record["error_distribution"]["kind"]
            in {"bounded_uniform", "centered_binomial"}
        )
        assert row["secret_mapping"].startswith("exact ")


def test_every_dossier_has_one_bound_normal_lwe_cross_check() -> None:
    catalog = {
        record["instance_id"]: record for record in _load_jsonl(CATALOG_PATH)
    }
    for row in _load_jsonl(NORMAL_LWE_PATH):
        dossier_path = APP_DIR / "analyses" / f"{row['instance_id']}.md"
        dossier = dossier_path.read_text(encoding="utf-8")
        record = catalog[row["instance_id"]]
        assert dossier.splitlines()[0] == (
            f"# `{row['instance_id']}` — "
            f"{record['family']} / {record['runtime_bin']}"
        )
        assert dossier.count(DOSSIER_HEADING) == 1
        assert "`normal_lwe.jsonl`" in dossier
        assert dossier.count("generic full-secret enumeration ceiling") == 1
        assert "smallest abstract cross-check entry" in dossier
        assert "catalog ladder remains authoritative" in dossier
        assert "the two units are not interchangeable" in dossier
        if record["tier"] == "easy":
            assert "empirical two-second screen applies only" in dossier
        elif record["calibration_model_id"] == "analytical-attack-portfolio-min-v1":
            assert "separately registered provisional estimator coordinate" in dossier
        else:
            assert "non-estimator registered catalog model" in dossier
        floor_hit = any(
            attack["optimizer_floor_hit"] for attack in row["result"]["attacks"]
        )
        assert ("mechanical model floor before overhead" in dossier) == floor_hit


def test_hard_registered_estimator_coordinates_match_all_record_sweep() -> None:
    catalog = {
        record["instance_id"]: record for record in _load_jsonl(CATALOG_PATH)
    }
    rows = {
        row["instance_id"]: row for row in _load_jsonl(NORMAL_LWE_PATH)
    }
    registered = [
        record
        for record in catalog.values()
        if record["tier"] == "hard"
        and record["calibration_model_id"]
        == "analytical-attack-portfolio-min-v1"
    ]
    assert len(registered) == 84
    for record in registered:
        assert rows[record["instance_id"]]["result"][
            "normalized_seconds"
        ] == pytest.approx(record["predicted_runtime_seconds"], rel=1e-12)


def test_normal_lwe_known_n80_primal_receipt_is_reproduced() -> None:
    rows = {
        row["instance_id"]: row for row in _load_jsonl(NORMAL_LWE_PATH)
    }
    row = rows["lwe_0007"]
    assert row["configuration"]["n"] == 80
    attacks = {
        attack["upstream_key"]: attack for attack in row["result"]["attacks"]
    }
    expected = {
        "usvp": (31.828000, 109),
        "bdd": (32.120087, 62),
        "bdd_hybrid": (31.982947, 54),
        "bdd_mitm_hybrid": (40.906378, 40),
    }
    for upstream_key, (rop_log2, beta) in expected.items():
        assert attacks[upstream_key]["status"] == "finite"
        assert attacks[upstream_key]["rop_log2"] == pytest.approx(
            rop_log2, abs=1e-6
        )
        assert attacks[upstream_key]["beta"] == beta
