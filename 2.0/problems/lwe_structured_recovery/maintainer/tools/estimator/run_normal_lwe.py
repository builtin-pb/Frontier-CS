#!/usr/bin/env sage -python
"""Emit one pinned normal-LWE primal-recovery proxy for every public record.

Run this inside the image documented in ``README.md``.  The script deliberately
uses the actual public ``(n,m,q)`` but replaces every nonuniform public matrix by
the estimator's uniform-matrix model.  Distribution substitutions are serialized
next to every result and are estimates, not reductions or hardness claims.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections.abc import Mapping
from pathlib import Path

from estimator import LWE, ND, RC


SOURCE_REPOSITORY = "https://github.com/malb/lattice-estimator"
SOURCE_COMMIT = "3e48ef421ec256afddb3e7d2249a77eab6e9ba12"
SOURCE_ARCHIVE_SHA256 = (
    "aab320966fe4dc496a44e9223ab67d622e581d9ed052697e758907b0e437d539"
)
IMAGE_REFERENCE = "lwe-estimator-phase3:latest"
IMAGE_DIGEST = (
    "725595ce2bb23a86890808074388c24b01903c46f2a78f9aa5ca57412a7cbfee"
)
BASE_IMAGE = (
    "sagemath/sagemath:10.6@sha256:"
    "19995db6194f4a4bab18ce9a88556fd15b9ed5e916b4504fefe618a7796ddbdb"
)
ROP_PER_SECOND = 1_000_000.0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    return parser.parse_args()


def _secret_distribution(record: dict[str, object]):
    distribution = record["secret_distribution"]
    if not isinstance(distribution, dict):
        raise TypeError("secret_distribution must be an object")
    kind = distribution["kind"]
    alphabet = tuple(distribution["alphabet"])
    weight = distribution["weight"]
    q = int(record["q"])

    if kind == "uniform_mod_q":
        return ND.UniformMod(q), "exact uniform modular secret"
    if kind == "iid_alphabet":
        if not alphabet or tuple(range(int(alphabet[0]), int(alphabet[-1]) + 1)) != alphabet:
            raise ValueError("estimator mapping requires a contiguous iid alphabet")
        return ND.Uniform(int(alphabet[0]), int(alphabet[-1])), "exact iid uniform alphabet"
    if kind == "centered_binomial":
        return ND.CenteredBinomial(int(distribution["eta"])), "exact centered-binomial secret"
    if kind == "balanced_exact_weight_signed":
        half = int(weight) // 2
        return ND.SparseTernary(half, half), "exact balanced fixed-weight signed plant"
    if kind == "exact_weight_alphabet" and alphabet == (1,):
        return ND.SparseBinary(int(weight)), "exact fixed-weight binary plant"
    if kind == "exact_weight_alphabet" and alphabet == (-1, 1):
        return (
            ND.SparseBinomial(1, int(weight), n=int(record["n"])),
            "exact independently signed fixed-weight plant",
        )
    raise ValueError(f"unsupported secret distribution: {kind!r} {alphabet!r}")


def _error_distribution(record: dict[str, object]):
    distribution = record["error_distribution"]
    if not isinstance(distribution, dict):
        raise TypeError("error_distribution must be an object")
    kind = distribution["kind"]
    bound = int(distribution["bound"])
    if kind == "bounded_uniform":
        return ND.Uniform(-bound, bound), "exact iid bounded-uniform error"
    if kind == "centered_binomial":
        return ND.CenteredBinomial(int(distribution["eta"])), "exact centered-binomial error"
    if kind == "truncated_discrete_gaussian":
        return (
            ND.DiscreteGaussian(float(distribution["sigma"])),
            "untruncated same-standard-deviation Gaussian proxy",
        )
    if kind == "sparse_bounded":
        m = int(record["m"])
        weight = int(distribution["weight"])
        conditional_second_moment = (bound + 1) * (2 * bound + 1) / 6.0
        marginal_variance = weight * conditional_second_moment / m
        return (
            ND.DiscreteGaussian(math.sqrt(marginal_variance)),
            "variance-matched iid Gaussian proxy for dependent exact-global-weight sparse-bounded error",
        )
    raise ValueError(f"unsupported error distribution: {kind!r}")


def _canonical_line(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _log2_or_none(value: object) -> float | None:
    """Return a finite binary logarithm without overflowing huge Sage reals."""

    try:
        logarithm = value.log(2) if hasattr(value, "log") else math.log2(value)
        result = float(logarithm)
    except (ArithmeticError, TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)
    except (ArithmeticError, TypeError, ValueError):
        return None


def _generic_fallback(record: dict[str, object]) -> dict[str, object]:
    """Return a conservative generic recovery ceiling for every record."""

    n = int(record["n"])
    m = int(record["m"])
    q = int(record["q"])
    candidate_log2 = n * math.log2(q)
    operations_per_candidate = m * (2 * n + 8)
    return {
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


def main() -> int:
    args = _parse_args()
    catalog_bytes = args.catalog.read_bytes()
    catalog_sha256 = hashlib.sha256(catalog_bytes).hexdigest()
    records = [json.loads(line) for line in catalog_bytes.splitlines() if line]
    if len(records) != 200:
        raise ValueError("normal-LWE sweep requires the 200-record production catalog")
    if not 1 <= args.shard_count <= len(records):
        raise ValueError("shard-count must be between 1 and the catalog size")
    if not 0 <= args.shard_index < args.shard_count:
        raise ValueError("shard-index must be in [0, shard-count)")
    shard_records = [
        record
        for index, record in enumerate(records)
        if index % args.shard_count == args.shard_index
    ]

    output_lines: list[bytes] = []
    for record in shard_records:
        secret, secret_mapping = _secret_distribution(record)
        error, error_mapping = _error_distribution(record)
        params = LWE.Parameters(
            n=int(record["n"]),
            m=int(record["m"]),
            q=int(record["q"]),
            Xs=secret,
            Xe=error,
        )
        attacks = []
        for upstream_key, algorithm, function, extra_arguments in (
            ("usvp", "primal_usvp", LWE.primal_usvp, {}),
            ("bdd", "primal_bdd", LWE.primal_bdd, {}),
            (
                "bdd_hybrid",
                "primal_hybrid",
                LWE.primal_hybrid,
                {"mitm": False, "babai": False},
            ),
            (
                "bdd_mitm_hybrid",
                "primal_mitm_hybrid",
                LWE.primal_hybrid,
                {"mitm": True, "babai": True},
            ),
        ):
            try:
                attack = function(
                    params,
                    red_cost_model=RC.ADPS16,
                    red_shape_model="gsa",
                    log_level=0,
                    **extra_arguments,
                )
            except Exception as exc:  # upstream numerical/applicability failure
                attacks.append(
                    {
                        "upstream_key": upstream_key,
                        "algorithm": algorithm,
                        "status": "unavailable",
                        "failure_type": type(exc).__name__,
                        "rop_log2": None,
                        "beta": None,
                        "lattice_dimension": None,
                        "optimizer_floor_hit": False,
                    }
                )
                continue
            if not isinstance(attack, Mapping) or "rop" not in attack:
                attacks.append(
                    {
                        "upstream_key": upstream_key,
                        "algorithm": algorithm,
                        "status": "unavailable",
                        "failure_type": "MalformedUpstreamResult",
                        "rop_log2": None,
                        "beta": None,
                        "lattice_dimension": None,
                        "optimizer_floor_hit": False,
                    }
                )
                continue
            attack_log2 = _log2_or_none(attack["rop"])
            beta = _int_or_none(attack.get("beta"))
            attacks.append(
                {
                    "upstream_key": upstream_key,
                    "algorithm": algorithm,
                    "status": "finite" if attack_log2 is not None else "infinite_or_nonfinite",
                    "failure_type": None,
                    "rop_log2": attack_log2,
                    "beta": beta,
                    "lattice_dimension": _int_or_none(attack.get("d")),
                    "optimizer_floor_hit": beta == 40,
                }
            )
        finite_attacks = [attack for attack in attacks if attack["rop_log2"] is not None]
        generic_fallback = _generic_fallback(record)
        selected = min(
            [*finite_attacks, generic_fallback],
            key=lambda attack: (attack["rop_log2"], attack["upstream_key"]),
        )
        rop_log2 = selected["rop_log2"]
        seconds_log2 = rop_log2 - math.log2(ROP_PER_SECOND)
        row = {
            "schema_version": 1,
            "instance_id": record["instance_id"],
            "instance_digest": record["instance_digest"],
            "catalog_sha256": catalog_sha256,
            "matrix_mapping": (
                "exact uniform public matrix"
                if record["matrix"]["kind"] == "uniform"
                else "uniform-matrix heuristic proxy for nonuniform public matrix"
            ),
            "secret_mapping": secret_mapping,
            "error_mapping": error_mapping,
            "configuration": {
                "n": record["n"],
                "m": record["m"],
                "q": record["q"],
                "secret_distribution": repr(secret),
                "error_distribution": repr(error),
                "reduction_cost_model": "ADPS16",
                "reduction_shape_model": "gsa",
            },
            "result": {
                "algorithm": selected["algorithm"] if selected is not None else None,
                "upstream_key": selected["upstream_key"] if selected is not None else None,
                "rop_log2": rop_log2,
                "beta": selected["beta"] if selected is not None else None,
                "lattice_dimension": selected["lattice_dimension"] if selected is not None else None,
                "attacks": attacks,
                "generic_fallback": generic_fallback,
                "normalized_seconds": 2**seconds_log2 if seconds_log2 is not None and seconds_log2 < 1023 else None,
                "normalized_seconds_log2": seconds_log2,
                "normalization_rop_per_second": ROP_PER_SECOND,
                "normalization_interpretation": (
                    "reporting_convention_not_wall_clock"
                ),
                "selection_scope": "non_selecting_cross_check",
            },
            "status": (
                "heuristic normal-LWE proxy plus generic exact enumeration "
                "ceiling; not a reduction, measurement, or hardness claim"
            ),
            "provenance": {
                "source_repository": SOURCE_REPOSITORY,
                "source_commit": SOURCE_COMMIT,
                "source_archive_sha256": SOURCE_ARCHIVE_SHA256,
                "image_reference": IMAGE_REFERENCE,
                "image_digest": IMAGE_DIGEST,
                "base_image": BASE_IMAGE,
            },
        }
        output_lines.append(_canonical_line(row))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(b"".join(output_lines))

    print(
        f"wrote {len(output_lines)} normal-LWE proxy rows "
        f"for shard {args.shard_index}/{args.shard_count} to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
