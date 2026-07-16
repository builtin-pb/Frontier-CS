from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from math import comb
from pathlib import Path

import pytest

from lwe_challenge.generator import _validated_template_instance
from lwe_challenge.schema import Catalog


TASK_DIR = Path(__file__).resolve().parents[1]
PUBLIC_DIR = TASK_DIR / "harbor" / "app" / "public"


def test_slot_builder_has_exact_public_ladder_shape() -> None:
    from tools.corpus.build_catalog import FAMILY_CODES, build_slots

    slots = build_slots()

    assert len(slots) == 200
    assert [slot["instance_id"] for slot in slots] == [
        f"lwe_{index:04d}" for index in range(1, 201)
    ]
    assert Counter(slot["family"] for slot in slots) == {
        family: 20 for family in FAMILY_CODES
    }
    assert Counter(slot["tier"] for slot in slots) == {
        "easy": 60,
        "hard": 140,
    }
    for family in FAMILY_CODES:
        family_slots = [slot for slot in slots if slot["family"] == family]
        assert [slot["runtime_bin"] for slot in family_slots[:6]] == [
            f"E{index}" for index in range(6)
        ]
        assert all(slot["tier"] == "easy" for slot in family_slots[:6])
        assert all(slot["tier"] == "hard" for slot in family_slots[6:])
    assert Counter(
        slot["runtime_bin"] for slot in slots if slot["tier"] == "hard"
    ) == {f"H{index}": 14 for index in range(10)}


def test_easy_literature_route_accounting_is_exact_and_disjoint() -> None:
    from tools.corpus.build_catalog import build_slots

    easy = [slot for slot in build_slots() if slot["tier"] == "easy"]
    son_cheon_full_guess = [
        slot
        for slot in easy
        if slot["family"] in {"DS_BIN", "DS_TER", "MIX_Q_SPARSE"}
    ]
    sun_tibouchi_abe_clean_subset = [
        slot
        for slot in easy
        if slot["family"] not in {"DS_BIN", "DS_TER", "MIX_Q_SPARSE"}
    ]

    assert len(son_cheon_full_guess) == 18
    assert len(sun_tibouchi_abe_clean_subset) == 42
    assert {slot["instance_id"] for slot in son_cheon_full_guess}.isdisjoint(
        slot["instance_id"] for slot in sun_tibouchi_abe_clean_subset
    )
    assert len(son_cheon_full_guess) + len(sun_tibouchi_abe_clean_subset) == len(
        easy
    ) == 60


def test_parameter_specs_cover_every_family_with_schema_valid_templates() -> None:
    from tools.corpus.build_catalog import build_specs, spec_to_template

    specs = build_specs()
    assert max(spec["predicted_runtime_seconds"] for spec in specs) <= (
        1024 * 3600
    )

    assert len(specs) == 200
    assert len({spec["instance_id"] for spec in specs}) == 200
    for spec in specs:
        assert not ({"private_seed", "private_secret", "private_error"} & set(spec))
        instance = _validated_template_instance(spec_to_template(spec))
        assert instance.instance_id == spec["instance_id"]
        assert instance.family == spec["family"]
        assert instance.runtime_bin == spec["runtime_bin"]

    by_family = {
        family: [spec for spec in specs if spec["family"] == family]
        for family in {spec["family"] for spec in specs}
    }
    assert {spec["matrix"]["kind"] for spec in by_family["DS_BIN"]} == {
        "uniform"
    }
    assert {
        spec["secret_distribution"]["kind"] for spec in by_family["DS_BIN"]
    } == {"exact_weight_alphabet"}
    assert {spec["matrix"]["kind"] for spec in by_family["SA_Q"]} == {
        "sparse_uniform"
    }
    assert {
        spec["secret_distribution"]["kind"] for spec in by_family["SA_Q"]
    } == {"uniform_mod_q"}
    assert {spec["matrix"]["kind"] for spec in by_family["DA_BIN"]} == {
        "small_alphabet"
    }
    assert {
        spec["secret_distribution"]["kind"] for spec in by_family["DA_BIN"]
    } == {"uniform_mod_q"}
    assert {
        spec["matrix"]["kind"] for spec in by_family["MIX_SMALL_SPARSE"]
    } == {"sparse_small_alphabet"}


def test_checked_in_public_catalog_is_complete_bound_and_secret_free() -> None:
    from tools.corpus.build_catalog import build_slots, build_specs, spec_to_template

    catalog_path = PUBLIC_DIR / "catalog.jsonl"
    catalog_bytes = catalog_path.read_bytes()
    catalog = Catalog.load(catalog_path)

    assert len(catalog.instances) == 200
    assert [instance.instance_id for instance in catalog.instances] == [
        f"lwe_{index:04d}" for index in range(1, 201)
    ]
    assert Counter(instance.family for instance in catalog.instances) == {
        family: 20
        for family in (
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
    }
    assert Counter(instance.tier for instance in catalog.instances) == {
        "easy": 60,
        "hard": 140,
    }
    digest = hashlib.sha256(catalog_bytes).hexdigest()
    assert (PUBLIC_DIR / "catalog.sha256").read_text(encoding="ascii") == (
        f"{digest}  catalog.jsonl\n"
    )

    slots = json.loads((PUBLIC_DIR / "slots.json").read_text(encoding="utf-8"))
    spec_paths = sorted((PUBLIC_DIR / "specs").glob("lwe_*.json"))
    assert len(slots) == len(spec_paths) == 200
    assert slots == build_slots()
    for instance, slot, spec_path, expected_spec in zip(
        catalog.instances, slots, spec_paths, build_specs()
    ):
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        assert spec == expected_spec
        template = spec_to_template(spec)
        assert instance.instance_id == slot["instance_id"] == spec["instance_id"]
        assert instance.family == slot["family"] == spec["family"]
        assert instance.runtime_bin == slot["runtime_bin"] == spec["runtime_bin"]
        assert instance.predicted_runtime_seconds == spec[
            "predicted_runtime_seconds"
        ]
        assert (instance.n, instance.m, instance.q) == (
            template.n,
            template.m,
            template.q,
        )
        assert instance.matrix == template.matrix
        assert instance.secret_distribution == template.secret_distribution
        assert instance.secret == template.secret
        assert instance.error_distribution == template.error_distribution
        assert instance.error == template.error
        forbidden = {
            "private_seed",
            "private_secret",
            "private_error",
            "private_attestation",
        }
        assert forbidden.isdisjoint(spec)

    lowered = catalog_bytes.lower()
    for forbidden_token in (
        b"private_seed",
        b"private_secret",
        b"private_error",
        b"private_attestation",
    ):
        assert forbidden_token not in lowered
    format_text = (PUBLIC_DIR / "format.md").read_text(encoding="utf-8")
    assert "intentionally excludes analysis, calibration, and runtime" in format_text
    assert "complete exact JSONL record bytes" in format_text
    assert "normalized analytical design rates" in format_text

    for instance in catalog.instances:
        analysis_path = TASK_DIR / "harbor" / "app" / instance.analysis_path
        analysis_text = analysis_path.read_text(encoding="utf-8")
        assert analysis_text.strip()
        embedded_digest = re.search(
            r"(?:instance|record)[ _-]digest\s*[:=]\s*`?([0-9a-f]{64})`?",
            analysis_text,
            flags=re.IGNORECASE,
        )
        assert embedded_digest is not None
        assert embedded_digest.group(1) == instance.instance_digest


def test_specs_preserve_sparse_lwe_and_low_entropy_safety_margins() -> None:
    from tools.corpus.build_catalog import build_specs

    for spec in build_specs():
        matrix = spec["matrix"]
        distribution = spec["secret_distribution"]
        if matrix["kind"] in {"sparse_uniform", "sparse_small_alphabet"}:
            assert matrix["row_weight"] == math.ceil(2 * math.sqrt(spec["n"]))
        if spec["tier"] == "hard" and spec["family"] in {
            "SA_Q",
            "SA_SMALL",
            "DA_BIN",
            "DA_TER",
        }:
            assert spec["n"] >= 96
        if distribution["kind"] in {
            "exact_weight_alphabet",
            "balanced_exact_weight_signed",
        }:
            assert 1 <= distribution["weight"] <= 14
        if spec["family"] == "MIX_DENSE_SMALL":
            assert distribution["kind"] in {
                "exact_weight_alphabet",
                "balanced_exact_weight_signed",
            }


def test_hard_secret_governed_specs_use_pinned_estimator_schedules() -> None:
    from tools.corpus.build_catalog import build_specs

    binary_schedule = [80, 85, 90, 100, 105, 110, 120, 130, 140, 150]
    signed_schedule = [75, 80, 85, 90, 100, 105, 110, 120, 130, 135]
    dense_schedule = [70, 72, 74, 76, 78, 80, 82, 84, 86, 88]
    exact_families = {
        "DS_BIN",
        "DS_TER",
        "MIX_Q_SPARSE",
        "MIX_SMALL_SPARSE",
        "MIX_DENSE_SMALL",
    }
    archive_hash = (
        "aab320966fe4dc496a44e9223ab67d622e581d9ed052697e758907b0e437d539"
    )
    image_digest = (
        "725595ce2bb23a86890808074388c24b01903c46f2a78f9aa5ca57412a7cbfee"
    )

    specs = build_specs()
    for spec in specs:
        if spec["tier"] == "easy":
            checked_in = json.loads(
                (PUBLIC_DIR / "specs" / f"{spec['instance_id']}.json").read_text(
                    encoding="utf-8"
                )
            )
            assert spec == checked_in

    for spec in specs:
        if spec["tier"] != "hard" or spec["family"] not in (
            exact_families | {"DS_SMALL"}
        ):
            continue
        octave = int(spec["runtime_bin"][1:])
        distribution = spec["secret_distribution"]
        if spec["family"] == "DS_SMALL":
            assert spec["n"] == dense_schedule[octave]
        else:
            assert spec["q"] == 257
            assert distribution["weight"] == 14
            signed = distribution["alphabet"] == [-1, 1]
            assert spec["n"] == (signed_schedule if signed else binary_schedule)[
                octave
            ]
            assert distribution["kind"] == (
                "balanced_exact_weight_signed"
                if signed
                else "exact_weight_alphabet"
            )
        assert spec["m"] == spec["n"] + 8

        model = spec["analytical_model"]
        assert model["model_id"] == "analytical-attack-portfolio-min-v1"
        assert model["formula"] == "min(enumeration_seconds,normal_lwe_proxy_seconds)"
        assert model["predicted_runtime_seconds"] == min(
            attack["predicted_runtime_seconds"]
            for attack in model["attacks"]
        )
        estimator = next(
            attack
            for attack in model["attacks"]
            if attack["attack_id"] == "normal-lwe-estimator-proxy"
        )
        assert estimator["applicability"] == (
            "heuristic proxy, not a reduction or hardness claim"
        )
        assert estimator["normalization"]["rop_per_second"] == 1_000_000.0
        assert estimator["fastest_rop_log2"] == min(
            attack["rop_log2"] for attack in estimator["attack_results"]
        )
        assert {
            attack["algorithm"] for attack in estimator["attack_results"]
        } == {
            "primal_usvp",
            "primal_bdd",
            "primal_hybrid",
            "primal_hybrid_mitm",
        }
        assert estimator["predicted_runtime_seconds"] == (
            2 ** estimator["fastest_rop_log2"] / 1_000_000.0
        )
        assert estimator["configuration"] == {
            "n": spec["n"],
            "m": spec["m"],
            "q": spec["q"],
            "estimator_secret_distribution": (
                "Uniform(0,1)"
                if spec["family"] == "DS_SMALL"
                else (
                    "SparseTernary(7,7)"
                    if distribution["alphabet"] == [-1, 1]
                    else "SparseBinary(14)"
                )
            ),
            "estimator_error_distribution": (
                f"Uniform(-{(spec['q'] - 1) // 8},{(spec['q'] - 1) // 8})"
            ),
            "reduction_cost_model": "ADPS16",
            "reduction_shape_model": "gsa",
        }
        assert estimator["provenance"]["source_archive_sha256"] == archive_hash
        assert estimator["provenance"]["cached_image_digest"] == image_digest
        if spec["matrix"]["kind"] != "uniform":
            assert estimator["matrix_model"] == (
                "uniform-matrix normal-LWE proxy for a nonuniform public matrix"
            )


def test_error_parameters_match_selected_easy_and_hard_attack_models() -> None:
    from tools.corpus.build_catalog import build_specs

    matrix_clean_subset_families = {"SA_Q", "SA_SMALL", "DA_BIN", "DA_TER"}
    easy_clean_subset_families = matrix_clean_subset_families | {
        "DS_SMALL",
        "MIX_SMALL_SPARSE",
        "MIX_DENSE_SMALL",
    }
    for spec in build_specs():
        distribution = spec["error_distribution"]
        predicate = spec["error"]
        clean_subset = spec["family"] in matrix_clean_subset_families or (
            spec["tier"] == "easy"
            and spec["family"] in easy_clean_subset_families
        )
        if clean_subset:
            assert distribution["kind"] == "sparse_bounded"
            active = distribution["weight"]
            assert active is not None
        else:
            assert distribution["weight"] is None
            active = spec["m"]
        if spec["tier"] == "hard":
            bound = (spec["q"] - 1) // 8
            assert distribution["kind"] in {"sparse_bounded", "bounded_uniform"}
        else:
            local_index = (int(spec["instance_id"].split("_")[1]) - 1) % 20
            bound = (spec["q"] - 1) // 8
            if clean_subset:
                assert distribution["kind"] == "sparse_bounded"
            else:
                assert distribution["kind"] == (
                    "truncated_discrete_gaussian"
                    if local_index % 2 == 0
                    else "bounded_uniform"
                )
        assert predicate["max_abs"] == bound
        assert predicate == {
            "max_abs": bound,
            "max_l1": active * bound,
            "max_l2_squared": active * bound * bound,
            "max_nonzero": active,
        }


def test_analytical_models_derive_parameters_and_track_every_slot_target() -> None:
    from tools.corpus.build_catalog import build_specs

    exact_rates = {
        "DS_BIN": 10_000.0,
        "DS_TER": 12_000.0,
        "MIX_Q_SPARSE": 15_000.0,
        "MIX_SMALL_SPARSE": 7_000.0,
        "MIX_DENSE_SMALL": 10_000.0,
    }
    specs = build_specs()
    matrix_clean_subset_families = {"SA_Q", "SA_SMALL", "DA_BIN", "DA_TER"}
    easy_clean_subset_rates = {
        "DS_SMALL": (130.0, 5.0),
        "SA_Q": (100.0, 5.0),
        "SA_SMALL": (100.0, 5.0),
        "DA_BIN": (100.0, 5.0),
        "DA_TER": (80.0, 2.0),
        "MIX_SMALL_SPARSE": (125.0, 5.0),
        "MIX_DENSE_SMALL": (80.0, 5.0),
    }
    exact_secret_families = {
        "DS_BIN",
        "DS_TER",
        "MIX_Q_SPARSE",
        "MIX_SMALL_SPARSE",
        "MIX_DENSE_SMALL",
    }
    for spec in specs:
        target = spec["target_runtime_seconds"]
        predicted = spec["predicted_runtime_seconds"]
        assert max(predicted / target, target / predicted) <= 2.0
        if spec["runtime_bin"].startswith("E"):
            easy_index = int(spec["runtime_bin"][1:])
            bounds = (
                (1, 4),
                (4, 16),
                (16, 64),
                (64, 256),
                (256, 1024),
                (1024, 3600),
            )[easy_index]
        else:
            octave = int(spec["runtime_bin"][1:])
            bounds = (3600 * 2**octave, 3600 * 2 ** (octave + 1))
        assert bounds[0] <= predicted <= bounds[1]
        assert spec["calibration_status"] == "extrapolated"
        assert spec["calibration_model_id"].startswith("analytical-")
        model = spec["analytical_model"]
        assert predicted == model["predicted_runtime_seconds"]

        if spec["family"] in {"DA_BIN", "DA_TER"}:
            assert spec["secret_distribution"] == {
                "kind": "uniform_mod_q",
                "alphabet": [],
                "weight": None,
                "eta": None,
            }
            assert spec["secret"] == {
                "kind": "mod_q",
                "alphabet": [],
                "min_nonzero": 0,
                "max_nonzero": spec["n"],
            }

        clean_subset = spec["family"] in matrix_clean_subset_families or (
            spec["tier"] == "easy"
            and spec["family"] in easy_clean_subset_rates
        )
        if clean_subset:
            assert spec["m"] == 3 * spec["n"]
            assert spec["error_distribution"]["kind"] == "sparse_bounded"
            weight = spec["error_distribution"]["weight"]
            clean_probability = comb(
                spec["m"] - weight, spec["n"]
            ) / comb(spec["m"], spec["n"])
            median_attempts = math.log(2.0) / clean_probability
            baseline_rate, minimum_rate = (
                (100.0, 10.0)
                if spec["tier"] == "hard"
                else easy_clean_subset_rates[spec["family"]]
            )
            expected_rate = max(
                baseline_rate * (16 / spec["n"]) ** 1.5,
                minimum_rate,
            )
            assert model["model_id"] == "analytical-clean-subset-v2"
            assert model["baseline_rate_at_n16_per_second"] == baseline_rate
            assert model["minimum_rate_per_second"] == minimum_rate
            assert math.isclose(
                model["assumed_rate_per_second"],
                expected_rate,
                rel_tol=1e-12,
            )
            assert math.isclose(
                predicted,
                median_attempts / model["assumed_rate_per_second"],
                rel_tol=1e-12,
            )
        elif spec["family"] in exact_secret_families:
            weight = spec["secret_distribution"]["weight"]
            nonzero_alphabet_size = len(
                spec["secret_distribution"]["alphabet"]
            )
            assignment_count = (
                comb(weight, weight // 2)
                if spec["secret_distribution"]["kind"]
                == "balanced_exact_weight_signed"
                else nonzero_alphabet_size**weight
            )
            work = comb(spec["n"], weight) * assignment_count
            enumeration = (
                next(
                    attack
                    for attack in model["attacks"]
                    if attack["attack_id"] == "exact-secret-enumeration"
                )
                if "attacks" in model
                else model
            )
            assert enumeration["work_factor"] == work
            expected_enumeration_rate = (
                exact_rates[spec["family"]]
                if spec["tier"] == "hard"
                else 2_400_000.0 / spec["n"]
            )
            assert math.isclose(
                enumeration["assumed_rate_per_second"],
                expected_enumeration_rate,
                rel_tol=1e-12,
            )
            assert enumeration["predicted_runtime_seconds"] == (
                work / enumeration["assumed_rate_per_second"]
            )
            if spec["tier"] == "easy" and spec["family"] == "MIX_Q_SPARSE":
                mixed_filter = next(
                    attack
                    for attack in model["attacks"]
                    if attack["attack_id"] == "mixed-filter-greedy"
                )
                assert model["model_id"] == (
                    "analytical-easy-exact-secret-with-mixed-screen-v1"
                )
                assert model["formula"] == "exact_secret_enumeration"
                assert model["selected_attack"] == "exact-secret-enumeration"
                assert predicted == enumeration["predicted_runtime_seconds"]
                assert "predicted_runtime_seconds" not in mixed_filter
                assert mixed_filter["paper_asymptotic_complexity"] == (
                    "O(m*k*3^k)"
                )
                paper_parameters = mixed_filter["paper_parameters"]
                assert paper_parameters == {
                    "m": spec["m"],
                    "k": spec["matrix"]["row_weight"],
                    "q": spec["q"],
                    "q_le_3_pow_k": True,
                }
                assert mixed_filter["paper_work_factor"] == (
                    spec["m"]
                    * spec["matrix"]["row_weight"]
                    * 3 ** spec["matrix"]["row_weight"]
                )
                sizing_screen = mixed_filter["candidate_sizing_screen"]
                assert sizing_screen == {
                    "formula": "n^3/60000",
                    "divisor": 60_000.0,
                    "value_seconds": spec["n"] ** 3 / 60_000.0,
                    "interpretation": (
                        "non-runtime dimension-sizing screen; not an attack bound"
                    ),
                }
                assert sizing_screen["value_seconds"] >= bounds[0]
                assert mixed_filter["release_screen"] == {
                    "required_no_recovery_before_seconds": float(bounds[0]),
                    "evidence_location": "CALIBRATION.md",
                }
        else:
            alphabet_size = len(spec["secret_distribution"]["alphabet"])
            work = alphabet_size ** spec["n"]
            assert spec["family"] == "DS_SMALL"
            assert spec["secret_distribution"]["kind"] == "iid_alphabet"
            assert spec["secret_distribution"]["alphabet"] == [0, 1]
            assert spec["error_distribution"]["kind"] != "sparse_bounded"
            enumeration = (
                next(
                    attack
                    for attack in model["attacks"]
                    if attack["attack_id"] == "dense-domain-enumeration"
                )
                if spec["tier"] == "hard"
                else model
            )
            assert enumeration["work_factor"] == work
            assert enumeration["predicted_runtime_seconds"] == (
                work / enumeration["assumed_rate_per_second"]
            )

    hard_enumeration_specs = [
        spec
        for spec in specs
        if spec["tier"] == "hard" and spec["family"] in exact_secret_families
    ]
    assert {
        spec["error_distribution"]["kind"] for spec in hard_enumeration_specs
    } == {"bounded_uniform"}
    assert "sparse_bounded" in {
        spec["error_distribution"]["kind"] for spec in specs
    }
    for family in {spec["family"] for spec in specs}:
        hard = [
            spec
            for spec in specs
            if spec["family"] == family and spec["tier"] == "hard"
        ]
        for previous, current in zip(hard, hard[1:]):
            if previous["runtime_bin"] == "H9" and current["runtime_bin"] == "H0":
                assert previous["predicted_runtime_seconds"] > (
                    100 * current["predicted_runtime_seconds"]
                )


def test_easy_mixed_q_schedule_uses_exact_runtime_and_nonruntime_screen() -> None:
    from tools.corpus.build_catalog import build_specs

    specs = [
        spec
        for spec in build_specs()
        if spec["tier"] == "easy" and spec["family"] == "MIX_Q_SPARSE"
    ]
    expected = (
        ("lwe_0141", 45, 98, 4, 14, 2.79365625),
        ("lwe_0142", 70, 148, 3, 17, 12.772666666666666),
        ("lwe_0143", 172, 352, 3, 27, 59.7227),
        ("lwe_0144", 435, 878, 2, 42, 68.436375),
        ("lwe_0145", 260, 528, 3, 33, 313.69216666666665),
        ("lwe_0146", 1190, 2388, 2, 69, 1403.1190833333333),
    )

    assert len(specs) == len(expected)
    for spec, (instance_id, n, m, weight, row_weight, predicted) in zip(
        specs, expected, strict=True
    ):
        assert (
            spec["instance_id"],
            spec["n"],
            spec["m"],
            spec["secret_distribution"]["weight"],
            spec["matrix"]["row_weight"],
        ) == (instance_id, n, m, weight, row_weight)
        assert math.isclose(
            spec["predicted_runtime_seconds"], predicted, rel_tol=1e-15
        )


def test_reuse_requires_exact_cryptographic_compatibility() -> None:
    from tools.corpus.build_catalog import (
        build_specs,
        reuse_compatible_record,
    )

    existing = json.loads(
        (PUBLIC_DIR / "catalog.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    spec = build_specs()[0]

    reused = reuse_compatible_record(existing, spec)
    assert reused is not None
    assert reused["b"] == existing["b"]
    assert reused["instance_digest"] == existing["instance_digest"]

    metadata_only = dict(spec)
    metadata_only["analysis_path"] = "analyses/reviewed-lwe_0001.md"
    metadata_only["predicted_runtime_seconds"] *= 1.01
    metadata_only["analytical_model"] = dict(metadata_only["analytical_model"])
    metadata_only["analytical_model"]["predicted_runtime_seconds"] *= 1.01
    reused_with_new_metadata = reuse_compatible_record(existing, metadata_only)
    assert reused_with_new_metadata is not None
    assert reused_with_new_metadata["analysis_path"] == metadata_only["analysis_path"]
    assert reused_with_new_metadata["predicted_runtime_seconds"] == (
        metadata_only["predicted_runtime_seconds"]
    )
    assert reused_with_new_metadata["instance_digest"] == existing["instance_digest"]

    changed_crypto = json.loads(json.dumps(spec))
    changed_crypto["q"] = 769 if spec["q"] != 769 else 1229
    assert reuse_compatible_record(existing, changed_crypto) is None


def test_force_regenerate_replaces_only_selected_compatible_record(
    tmp_path: Path,
) -> None:
    from tools.corpus.build_catalog import write_public_assets

    digest, generated, reused = write_public_assets(
        tmp_path,
        reuse_compatible_catalog=PUBLIC_DIR / "catalog.jsonl",
        force_regenerate=frozenset({"lwe_0001"}),
    )

    assert generated == ("lwe_0001",)
    assert len(reused) == 199
    assert "lwe_0001" not in reused
    assert digest != Catalog.load(PUBLIC_DIR / "catalog.jsonl").catalog_id
    assert Catalog.load(tmp_path / "catalog.jsonl").catalog_id == digest

    with pytest.raises(ValueError, match="unknown forced instance IDs"):
        write_public_assets(
            tmp_path / "unknown",
            reuse_compatible_catalog=PUBLIC_DIR / "catalog.jsonl",
            force_regenerate=frozenset({"lwe_9999"}),
        )
