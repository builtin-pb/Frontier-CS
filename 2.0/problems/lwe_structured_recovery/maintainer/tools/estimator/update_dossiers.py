#!/usr/bin/env python3
"""Append the pinned all-record normal-LWE cross-check to every dossier."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


HEADING = "## All-record normal-LWE cross-check"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    parser.add_argument("--analyses", required=True, type=Path)
    return parser.parse_args()


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _number(value: object) -> str:
    return "unavailable" if value is None else f"{float(value):.6f}"


def _section(row: dict[str, object], record: dict[str, object]) -> str:
    result = row["result"]
    attacks = result["attacks"]
    summaries = []
    for attack in attacks:
        if attack["status"] == "finite":
            summaries.append(
                f"`{attack['upstream_key']}` log2(rop)={_number(attack['rop_log2'])}"
            )
        else:
            reason = attack.get("failure_type") or attack["status"]
            summaries.append(f"`{attack['upstream_key']}` unavailable ({reason})")
    fallback = result["generic_fallback"]
    fallback_summary = (
        "The separate generic full-secret enumeration ceiling has "
        f"log2(rop)={_number(fallback['rop_log2'])} "
        f"(log2(candidate count)={_number(fallback['candidate_count_log2'])}, "
        f"{fallback['operations_per_candidate']} conservative abstract modular "
        "operations per candidate).  "
    )
    floor_note = ""
    if any(attack["optimizer_floor_hit"] for attack in attacks):
        floor_note = (
            "At least one estimator route hits the pinned optimizer floor "
            "`beta=40`; `2^(0.292*40) / 10^6 = 0.00328` seconds is therefore "
            "a mechanical model floor before overhead, not wall time or a "
            "portable runtime upper bound.  "
        )

    beta = result["beta"]
    dimension = result["lattice_dimension"]
    selected_parameters = []
    if beta is not None:
        selected_parameters.append(f"beta={beta}")
    if dimension is not None:
        selected_parameters.append(f"d={dimension}")
    suffix = f" ({', '.join(selected_parameters)})" if selected_parameters else ""
    catalog_runtime = _number(record["predicted_runtime_seconds"])
    model_id = record["calibration_model_id"]
    if record["tier"] == "easy":
        ladder_context = (
            "This easy record is placed by its runnable structured route; the "
            "normal-LWE inventory is screening-only, non-selecting, and cannot "
            "relabel the bin.  The empirical two-second screen applies only to "
            "the local `primal_bdd` implementation, not optimized uSVP/hybrid "
            "entries in this artifact.  "
        )
    elif model_id == "analytical-attack-portfolio-min-v1":
        ladder_context = (
            "This hard placement uses the separately registered provisional "
            "estimator coordinate when that route wins and no validated runtime "
            "exists; this all-record inventory is not a new portfolio input and "
            "cannot relabel the bin.  "
        )
    else:
        ladder_context = (
            "This hard record uses a non-estimator registered catalog model; "
            "the all-record calculation remains non-selecting.  "
        )

    return (
        f"{HEADING}\n\n"
        "The pinned ADPS16/GSA sweep retains "
        + "; ".join(summaries)
        + ".  "
        + fallback_summary
        + "The smallest abstract cross-check entry is "
        f"`{result['upstream_key']}` at log2(rop)={_number(result['rop_log2'])}"
        f"{suffix}; under the explicit `10^6` rop/second convention this is "
        f"log2(seconds)={_number(result['normalized_seconds_log2'])}.\n\n"
        f"The catalog ladder remains authoritative at {catalog_runtime} seconds "
        f"under `{model_id}`.  "
        + ladder_context
        + floor_note
        + "The canonical generic ceiling is not the earlier toy `q^n / 10^6` "
        "candidates-per-second illustration: it multiplies `q^n` by "
        "`m*(2*n+8)` abstract modular operations per candidate before applying "
        "the `10^6` rop/second convention, so the two units are not "
        "interchangeable.\n\n"
        f"Matrix mapping: {row['matrix_mapping']}.  Secret mapping: "
        f"{row['secret_mapping']}.  Error mapping: {row['error_mapping']}.  "
        "The estimator entries are non-selecting heuristic cross-checks; the "
        "generic enumeration entry is an exact finite-domain ceiling, not an "
        "estimator result.  Neither is a measurement or hardness claim.  The "
        "canonical reproducible row is in `normal_lwe.jsonl` and binds this "
        "instance digest and the catalog SHA-256.\n"
    )


def main() -> int:
    args = _arguments()
    catalog_bytes = args.catalog.read_bytes()
    catalog_sha256 = hashlib.sha256(catalog_bytes).hexdigest()
    catalog = {row["instance_id"]: row for row in _jsonl(args.catalog)}
    results = _jsonl(args.results)
    if len(catalog) != 200 or len(results) != 200:
        raise ValueError("dossier update requires exactly 200 catalog and result rows")
    if [row["instance_id"] for row in results] != sorted(catalog):
        raise ValueError("normal-LWE rows must exactly match sorted catalog IDs")
    for row in results:
        instance_id = row["instance_id"]
        record = catalog[instance_id]
        if row["catalog_sha256"] != catalog_sha256:
            raise ValueError(f"stale catalog binding for {instance_id}")
        if row["instance_digest"] != record["instance_digest"]:
            raise ValueError(f"stale instance binding for {instance_id}")
        dossier = args.analyses / f"{instance_id}.md"
        text = dossier.read_text(encoding="utf-8")
        lines = text.splitlines()
        if not lines or not lines[0].startswith("# "):
            raise ValueError(f"dossier has no title: {instance_id}")
        lines[0] = (
            f"# `{instance_id}` — {record['family']} / {record['runtime_bin']}"
        )
        text = "\n".join(lines) + "\n"
        if HEADING in text:
            text = text[: text.index(HEADING)].rstrip() + "\n\n"
        else:
            text = text.rstrip() + "\n\n"
        dossier.write_text(text + _section(row, record), encoding="utf-8")

    print(f"updated {len(results)} dossiers from {args.results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
