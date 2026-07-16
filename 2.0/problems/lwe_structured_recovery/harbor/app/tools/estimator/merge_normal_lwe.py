#!/usr/bin/env python3
"""Validate and canonically merge normal-LWE sweep shards."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("inputs", nargs="+", type=Path)
    return parser.parse_args()


def _jsonl(path: Path) -> list[dict[str, object]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError(f"empty shard: {path}")
    return [json.loads(line) for line in lines]


def _canonical_line(row: dict[str, object]) -> str:
    return json.dumps(
        row,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _attach_generic_fallback(row: dict[str, object]) -> None:
    """Normalize old shard rows to the current fail-closed runner schema."""

    result = row["result"]
    configuration = row["configuration"]
    n = int(configuration["n"])
    m = int(configuration["m"])
    q = int(configuration["q"])
    candidate_log2 = n * math.log2(q)
    operations_per_candidate = m * (2 * n + 8)
    fallback = {
        "upstream_key": "generic_full_secret_enumeration",
        "algorithm": "full_secret_enumeration",
        "status": "finite",
        "failure_type": None,
        "rop_log2": candidate_log2 + math.log2(operations_per_candidate),
        "candidate_count_log2": candidate_log2,
        "operations_per_candidate": operations_per_candidate,
        "beta": None,
        "lattice_dimension": None,
        "optimizer_floor_hit": False,
        "interpretation": (
            "q^n exhaustive secrets with m*(2*n+8) conservative abstract "
            "modular operations per candidate"
        ),
    }
    result["generic_fallback"] = fallback
    for attack in result["attacks"]:
        attack["optimizer_floor_hit"] = attack["beta"] == 40
    finite = [
        attack for attack in result["attacks"] if attack["rop_log2"] is not None
    ]
    selected = min(
        [*finite, fallback],
        key=lambda attack: (attack["rop_log2"], attack["upstream_key"]),
    )
    result["algorithm"] = selected["algorithm"]
    result["upstream_key"] = selected["upstream_key"]
    result["rop_log2"] = selected["rop_log2"]
    result["beta"] = selected["beta"]
    result["lattice_dimension"] = selected["lattice_dimension"]
    seconds_log2 = selected["rop_log2"] - math.log2(
        result["normalization_rop_per_second"]
    )
    result["normalized_seconds_log2"] = seconds_log2
    result["normalized_seconds"] = 2**seconds_log2 if seconds_log2 < 1023 else None
    result["normalization_interpretation"] = (
        "reporting_convention_not_wall_clock"
    )
    result["selection_scope"] = "non_selecting_cross_check"
    row["status"] = (
        "heuristic normal-LWE proxy plus generic exact enumeration ceiling; "
        "not a reduction, measurement, or hardness claim"
    )


def main() -> int:
    args = _arguments()
    catalog_bytes = args.catalog.read_bytes()
    catalog_sha256 = hashlib.sha256(catalog_bytes).hexdigest()
    catalog_rows = [
        json.loads(line) for line in catalog_bytes.splitlines() if line
    ]
    if len(catalog_rows) != 200:
        raise ValueError("merge requires the 200-record production catalog")
    catalog = {row["instance_id"]: row for row in catalog_rows}
    if len(catalog) != 200:
        raise ValueError("catalog instance IDs are not unique")

    merged: dict[str, dict[str, object]] = {}
    expected_provenance: object | None = None
    for path in args.inputs:
        shard = _jsonl(path)
        shard_ids = [row["instance_id"] for row in shard]
        if shard_ids != sorted(shard_ids) or len(set(shard_ids)) != len(shard_ids):
            raise ValueError(f"shard is not sorted and unique: {path}")
        for row in shard:
            _attach_generic_fallback(row)
            instance_id = row["instance_id"]
            if instance_id in merged:
                raise ValueError(f"duplicate instance across shards: {instance_id}")
            if instance_id not in catalog:
                raise ValueError(f"unknown instance in shard: {instance_id}")
            record = catalog[instance_id]
            if row["catalog_sha256"] != catalog_sha256:
                raise ValueError(f"stale catalog binding: {instance_id}")
            if row["instance_digest"] != record["instance_digest"]:
                raise ValueError(f"stale instance binding: {instance_id}")
            configuration = row["configuration"]
            if (
                configuration["n"],
                configuration["m"],
                configuration["q"],
            ) != (record["n"], record["m"], record["q"]):
                raise ValueError(f"stale parameter binding: {instance_id}")
            if expected_provenance is None:
                expected_provenance = row["provenance"]
            elif row["provenance"] != expected_provenance:
                raise ValueError(f"inconsistent provenance: {instance_id}")
            merged[instance_id] = row

    if set(merged) != set(catalog):
        missing = sorted(set(catalog) - set(merged))
        raise ValueError(f"shards do not cover the catalog: missing {missing[:3]}")

    lines = [_canonical_line(merged[instance_id]) for instance_id in sorted(merged)]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} merged normal-LWE proxy rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
