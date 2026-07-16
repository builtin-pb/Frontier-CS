from __future__ import annotations

import hashlib
import json
from pathlib import Path

from tools.solvers.registry import (
    canonical_solver_implementation_receipt,
    load_registry,
)


TASK_DIR = Path(__file__).resolve().parents[1]
APP_DIR = TASK_DIR / "harbor" / "app"
CATALOG_PATH = APP_DIR / "public" / "catalog.jsonl"
RECEIPTS_PATH = APP_DIR / "analyses" / "calibration_runs.jsonl"
CATALOG_SHA256 = (
    "bb24a596e43f781c4824c94292cd0093bb3f8da2b3fdd895337281df89d94081"
)
SPARSE_SECRET_REVISION = (
    "f488f140edffa610e76755e005e8fd0ec91e9ba856e6250ec3102a045f9909ec"
)
BOUNDED_ERROR_REVISION = (
    "7402fd4e720b8763c0fd24aceaa7c374fe758df7ee5459abf39fa31cbc0f8544"
)
MIXED_FILTER_REVISION = (
    "27ddaef678be426ef51feb73d8f66f6146bcba3106acbc661ba83d0bdd66e119"
)


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_final_calibration_receipts_are_canonical_and_bound() -> None:
    raw_lines = RECEIPTS_PATH.read_text(encoding="utf-8").splitlines()
    receipts = [json.loads(line) for line in raw_lines]
    catalog = {row["instance_id"]: row for row in _jsonl(CATALOG_PATH)}

    assert len(receipts) == 37
    assert hashlib.sha256(CATALOG_PATH.read_bytes()).hexdigest() == CATALOG_SHA256
    assert raw_lines == [
        json.dumps(row, allow_nan=False, sort_keys=True, separators=(",", ":"))
        for row in receipts
    ]
    for receipt in receipts:
        instance_id = receipt["instance_id"]
        assert receipt["catalog_sha256"] == CATALOG_SHA256
        assert receipt["instance_digest"] == catalog[instance_id]["instance_digest"]
        assert receipt["threads"] == 1
        assert isinstance(receipt["seed"], int)
        assert "secret" not in receipt

    assert [(row["instance_id"], row["solver_id"]) for row in receipts] == sorted(
        (row["instance_id"], row["solver_id"]) for row in receipts
    )


def test_final_reference_runs_are_scoped_honestly() -> None:
    receipts = _jsonl(RECEIPTS_PATH)
    mixed = {
        row["instance_id"]: row
        for row in receipts
        if row["solver_id"] == "mixed_filter_greedy"
    }
    assert {
        instance_id: row["censor_cap_seconds"] for instance_id, row in mixed.items()
    } == {
        "lwe_0141": 1.0,
        "lwe_0142": 4.0,
        "lwe_0143": 16.0,
        "lwe_0144": 64.0,
        "lwe_0145": 256.0,
        "lwe_0146": 1024.0,
    }
    assert all(row["outcome"] == "censored" for row in mixed.values())
    assert all(row["solver_revision"] == MIXED_FILTER_REVISION for row in mixed.values())
    assert all(row["validation"] == "no-witness-to-validate" for row in mixed.values())

    sparse = {
        row["instance_id"]: row
        for row in receipts
        if row["solver_id"] == "sparse_secret_enum"
    }
    assert set(sparse) == {
        "lwe_0001",
        "lwe_0002",
        "lwe_0003",
        "lwe_0021",
        "lwe_0022",
        "lwe_0023",
        "lwe_0141",
        "lwe_0142",
        "lwe_0143",
        "lwe_0144",
    }
    assert {
        instance_id for instance_id, row in sparse.items() if row["outcome"] == "success"
    } == {
        "lwe_0001",
        "lwe_0002",
        "lwe_0021",
        "lwe_0022",
        "lwe_0141",
        "lwe_0142",
        "lwe_0144",
    }
    assert all(
        row["solver_revision"] == SPARSE_SECRET_REVISION for row in sparse.values()
    )
    assert sparse["lwe_0142"]["internal_seconds"] < 16.0
    assert sparse["lwe_0142"]["candidate_domain_size"] == 437_920
    assert sparse["lwe_0142"]["terminal_ordinal"] == 268_022
    assert sparse["lwe_0142"]["work_units"] == 31_796_781
    assert 64.0 <= sparse["lwe_0144"]["internal_seconds"] < 256.0
    assert sparse["lwe_0144"]["censor_cap_seconds"] == 256.0
    assert sparse["lwe_0144"]["work_units"] == 261_076_643
    assert sparse["lwe_0144"]["validation"] == "public-verifier-ok"

    bounded = {
        row["instance_id"]: row
        for row in receipts
        if row["solver_id"] == "bounded_error"
    }
    assert len(bounded) == 21
    assert all(
        row["solver_revision"] == BOUNDED_ERROR_REVISION
        for row in bounded.values()
    )
    e2_ids = {
        "lwe_0043",
        "lwe_0063",
        "lwe_0083",
        "lwe_0103",
        "lwe_0123",
        "lwe_0163",
        "lwe_0183",
    }
    assert {instance_id for instance_id in bounded if instance_id.endswith("3")} == e2_ids
    assert bounded["lwe_0083"]["outcome"] == "success"
    assert 16.0 <= bounded["lwe_0083"]["internal_seconds"] < 64.0
    assert bounded["lwe_0083"]["censor_cap_seconds"] == 64.0
    assert bounded["lwe_0083"]["work_units"] == 388
    assert bounded["lwe_0083"]["validation"] == "public-verifier-ok"
    assert all(
        bounded[instance_id]["outcome"] == "censored"
        for instance_id in e2_ids - {"lwe_0083"}
    )


def test_documented_solver_revisions_match_current_canonical_receipts() -> None:
    revisions = {
        record.solver_id: canonical_solver_implementation_receipt(
            record
        ).implementation_digest
        for record in load_registry()
    }
    calibration = (APP_DIR / "CALIBRATION.md").read_text(encoding="utf-8")
    expected = {
        "sparse_secret_enum": SPARSE_SECRET_REVISION,
        "mixed_filter_greedy": MIXED_FILTER_REVISION,
        "bounded_error": BOUNDED_ERROR_REVISION,
        "primal_bdd": revisions["primal_bdd"],
    }
    for solver_id, revision in expected.items():
        assert revisions[solver_id] == revision
        assert f"| `{solver_id}` | `{revision}` |" in calibration
