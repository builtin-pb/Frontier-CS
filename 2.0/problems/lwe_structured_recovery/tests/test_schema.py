import copy
import hashlib
import json
import os
from pathlib import Path

import pytest

import lwe_challenge.schema as schema
from lwe_challenge.schema import (
    Catalog,
    canonical_record_bytes,
    compute_instance_digest,
)


FIXTURE_PATH = Path(__file__).parent / "fixtures/catalog_two_instances.json"


def _catalog_document() -> dict[str, object]:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _write_json_catalog(tmp_path: Path, document: dict[str, object]) -> Path:
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _refresh_digest(document: dict[str, object], index: int = 0) -> None:
    record = document["instances"][index]
    record["instance_digest"] = compute_instance_digest(record)


def test_catalog_loads_dimensions_and_public_predicates() -> None:
    catalog = Catalog.load(FIXTURE_PATH)
    toy = catalog.get("toy-uniform")
    assert (toy.n, toy.m, toy.q) == (3, 4, 17)
    assert toy.secret.alphabet == (-1, 0, 1)
    assert toy.error.max_abs == 1


def test_catalog_rejects_unknown_nested_fields(tmp_path: Path) -> None:
    document = _catalog_document()
    document["instances"][0]["matrix"]["surprise"] = True
    _refresh_digest(document)

    with pytest.raises(ValueError, match="unknown.*matrix"):
        Catalog.load(_write_json_catalog(tmp_path, document))

    document = _catalog_document()
    document["instances"][0]["analysis_path"] = "analysis/\ud800.md"
    _refresh_digest(document)
    with pytest.raises(ValueError, match="Unicode surrogate in JSON string"):
        Catalog.load(_write_json_catalog(tmp_path, document))


def test_catalog_rejects_duplicate_instance_ids(tmp_path: Path) -> None:
    document = _catalog_document()
    document["instances"][1]["instance_id"] = document["instances"][0][
        "instance_id"
    ]
    _refresh_digest(document, 1)

    with pytest.raises(ValueError, match="duplicate instance_id"):
        Catalog.load(_write_json_catalog(tmp_path, document))

    valid_boundary_id = "A" + "x" * 63
    document = _catalog_document()
    document["instances"][0]["instance_id"] = valid_boundary_id
    _refresh_digest(document)
    assert Catalog.load(_write_json_catalog(tmp_path, document)).get(
        valid_boundary_id
    ).instance_id == valid_boundary_id

    for invalid_id in (
        "a" * 65,
        "_leading",
        "contains space",
        "café",
        "line\nbreak",
        "semi;colon",
        "",
    ):
        document = _catalog_document()
        document["instances"][0]["instance_id"] = invalid_id
        _refresh_digest(document)
        with pytest.raises(ValueError, match="instance_id.*1.*64.*ASCII"):
            Catalog.load(_write_json_catalog(tmp_path, document))


def test_catalog_rejects_wrong_b_length(tmp_path: Path) -> None:
    document = _catalog_document()
    document["instances"][0]["b"] = [1, 2, 3]
    _refresh_digest(document)

    with pytest.raises(ValueError, match=r"len\(b\).*m"):
        Catalog.load(_write_json_catalog(tmp_path, document))

    assert (
        schema.MAX_N,
        schema.MAX_M,
        schema.MAX_Q,
        schema.MAX_MATRIX_ENTRIES,
    ) == (4096, 65536, 2**32 - 1, 2**26)

    exact_boundary_documents = []

    document = _catalog_document()
    document["instances"][0]["n"] = schema.MAX_N
    exact_boundary_documents.append(document)

    document = _catalog_document()
    document["instances"][0]["m"] = schema.MAX_M
    document["instances"][0]["b"] = [0] * schema.MAX_M
    exact_boundary_documents.append(document)

    document = _catalog_document()
    document["instances"][0]["q"] = schema.MAX_Q
    exact_boundary_documents.append(document)

    document = _catalog_document()
    record = document["instances"][0]
    record["n"] = schema.MAX_N
    record["m"] = schema.MAX_MATRIX_ENTRIES // schema.MAX_N
    record["b"] = [0] * record["m"]
    exact_boundary_documents.append(document)

    for document in exact_boundary_documents:
        _refresh_digest(document)
        Catalog.load(_write_json_catalog(tmp_path, document))

    over_boundary_cases = (
        ({"n": schema.MAX_N + 1}, "n.*MAX_N"),
        ({"m": schema.MAX_M + 1}, "m.*MAX_M"),
        ({"q": schema.MAX_Q + 1}, "q.*MAX_Q"),
        (
            {
                "n": schema.MAX_N,
                "m": schema.MAX_MATRIX_ENTRIES // schema.MAX_N + 1,
            },
            "matrix.*MAX_MATRIX_ENTRIES",
        ),
    )
    for updates, message in over_boundary_cases:
        document = _catalog_document()
        record = document["instances"][0]
        record.update(updates)
        if "m" in updates:
            record["b"] = [0] * record["m"]
        _refresh_digest(document)
        with pytest.raises(ValueError, match=message):
            Catalog.load(_write_json_catalog(tmp_path, document))


def test_catalog_rejects_invalid_sparse_matrix_weight(tmp_path: Path) -> None:
    document = _catalog_document()
    document["instances"][1]["matrix"]["row_weight"] = 0
    _refresh_digest(document, 1)

    with pytest.raises(ValueError, match="row_weight"):
        Catalog.load(_write_json_catalog(tmp_path, document))


def test_catalog_rejects_secret_distribution_predicate_mismatch(
    tmp_path: Path,
) -> None:
    document = _catalog_document()
    document["instances"][0]["secret"]["alphabet"] = [-1, 0]
    _refresh_digest(document)

    with pytest.raises(ValueError, match="secret.*alphabet"):
        Catalog.load(_write_json_catalog(tmp_path, document))

    document = _catalog_document()
    distribution = document["instances"][0]["secret_distribution"]
    distribution["kind"] = "centered_binomial"
    distribution["eta"] = 10**400
    _refresh_digest(document)
    with pytest.raises(ValueError, match="centered_binomial secret eta"):
        Catalog.load(_write_json_catalog(tmp_path, document))

    document = _catalog_document()
    record = document["instances"][0]
    record["q"] = 2 * 10**400 + 3
    distribution = record["secret_distribution"]
    distribution["kind"] = "centered_binomial"
    distribution["eta"] = 10**400
    _refresh_digest(document)
    with pytest.raises(ValueError, match="q.*MAX_Q"):
        Catalog.load(_write_json_catalog(tmp_path, document))


def test_catalog_requires_canonical_full_field_secret_specs(tmp_path: Path) -> None:
    document = _catalog_document()
    del document["instances"][0]["secret_distribution"]["eta"]
    _refresh_digest(document)

    with pytest.raises(ValueError, match="missing secret_distribution fields.*eta"):
        Catalog.load(_write_json_catalog(tmp_path, document))


def test_catalog_rejects_error_distribution_predicate_mismatch(
    tmp_path: Path,
) -> None:
    document = _catalog_document()
    document["instances"][0]["error"]["max_abs"] = 0
    _refresh_digest(document)

    with pytest.raises(ValueError, match="error max_abs.*bound"):
        Catalog.load(_write_json_catalog(tmp_path, document))

    document = _catalog_document()
    distribution = document["instances"][0]["error_distribution"]
    distribution["kind"] = "truncated_discrete_gaussian"
    distribution["sigma"] = 10**400
    _refresh_digest(document)
    with pytest.raises(ValueError, match="error distribution sigma.*finite"):
        Catalog.load(_write_json_catalog(tmp_path, document))


def test_catalog_rejects_tier_cohort_bin_octave_mismatch(tmp_path: Path) -> None:
    document = _catalog_document()
    record = document["instances"][0]
    record["tier"] = "hard"
    record["cohort"] = "paper"
    record["runtime_bin"] = "H3"
    record["octave"] = 2
    _refresh_digest(document)

    with pytest.raises(ValueError, match="tier metadata"):
        Catalog.load(_write_json_catalog(tmp_path, document))

    document = _catalog_document()
    document["instances"][0]["predicted_runtime_seconds"] = 10**400
    _refresh_digest(document)
    with pytest.raises(ValueError, match="predicted_runtime_seconds.*finite"):
        Catalog.load(_write_json_catalog(tmp_path, document))

    document = _catalog_document()
    document["instances"][0]["analysis_path"] = "analysis/embedded\x00nul.md"
    _refresh_digest(document)
    with pytest.raises(ValueError, match="analysis_path.*normalized"):
        Catalog.load(_write_json_catalog(tmp_path, document))


def test_catalog_rejects_instance_digest_mismatch(tmp_path: Path) -> None:
    document = _catalog_document()
    record = document["instances"][0]
    baseline = compute_instance_digest(record)
    excluded_replacements = {
        "instance_digest": "f" * 64,
        "analysis_path": "analysis/relinked.md",
        "calibration_status": "measured",
        "calibration_model_id": "run-2",
        "predicted_runtime_seconds": 5.0,
        "measured_runtime_seconds": 4.0,
    }
    for field, replacement in excluded_replacements.items():
        relinked = copy.deepcopy(record)
        relinked[field] = replacement
        assert compute_instance_digest(relinked) == baseline

    record["generator_version"] = "tampered-generator"
    assert compute_instance_digest(record) != baseline

    with pytest.raises(ValueError, match="instance_digest mismatch"):
        Catalog.load(_write_json_catalog(tmp_path, document))


def test_catalog_loads_one_record_canonical_jsonl(tmp_path: Path) -> None:
    record = _catalog_document()["instances"][0]
    canonical = canonical_record_bytes(record)
    assert canonical == json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    encoded = canonical + b"\n"
    path = tmp_path / "catalog.jsonl"
    path.write_bytes(encoded)

    catalog = Catalog.load(path)

    assert tuple(item.instance_id for item in catalog.instances) == ("toy-uniform",)
    assert catalog.catalog_id == hashlib.sha256(encoded).hexdigest()

    surrogate_record = copy.deepcopy(record)
    surrogate_record["analysis_path"] = "analysis/\ud800.md"
    with pytest.raises(ValueError, match="canonical JSON.*Unicode surrogate"):
        canonical_record_bytes(surrogate_record)


def test_catalog_rejects_noncanonical_jsonl_bytes(tmp_path: Path) -> None:
    record = _catalog_document()["instances"][0]
    path = tmp_path / "catalog.jsonl"
    path.write_bytes(json.dumps(record, sort_keys=True).encode("utf-8") + b"\n")

    with pytest.raises(ValueError, match="canonical"):
        Catalog.load(path)

    document = _catalog_document()
    document["instances"][0]["analysis_path"] = "analysis/\ud800.md"
    _refresh_digest(document)
    path.write_bytes(
        json.dumps(
            document["instances"][0],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        + b"\n"
    )
    with pytest.raises(ValueError, match="Unicode surrogate in JSON string"):
        Catalog.load(path)


def test_catalog_enforces_jsonl_record_and_byte_limits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    empty_json_path = _write_json_catalog(
        tmp_path, {"schema_version": 1, "instances": []}
    )
    with pytest.raises(ValueError, match="at least 1 record"):
        Catalog.load(empty_json_path)

    empty_jsonl_path = tmp_path / "empty.jsonl"
    empty_jsonl_path.write_bytes(b"")
    with pytest.raises(ValueError, match="at least 1 record"):
        Catalog.load(empty_jsonl_path)

    assert schema.MAX_CATALOG_MATRIX_ENTRIES == 2**28
    aggregate_records = []
    for index in range(5):
        document = _catalog_document()
        aggregate_record = document["instances"][0]
        aggregate_record["instance_id"] = f"aggregate-{index}"
        aggregate_record["n"] = schema.MAX_N
        aggregate_record["m"] = schema.MAX_MATRIX_ENTRIES // schema.MAX_N
        aggregate_record["b"] = [0] * aggregate_record["m"]
        _refresh_digest(document)
        aggregate_records.append(aggregate_record)

    aggregate_path = tmp_path / "aggregate.jsonl"
    aggregate_path.write_bytes(
        b"".join(canonical_record_bytes(record) + b"\n" for record in aggregate_records[:4])
    )
    assert len(Catalog.load(aggregate_path).instances) == 4

    aggregate_path.write_bytes(
        b"".join(canonical_record_bytes(record) + b"\n" for record in aggregate_records)
    )
    with pytest.raises(ValueError, match="MAX_CATALOG_MATRIX_ENTRIES"):
        Catalog.load(aggregate_path)

    record = _catalog_document()["instances"][0]
    line = canonical_record_bytes(record) + b"\n"
    path = tmp_path / "catalog.jsonl"
    path.write_bytes(line * 201)

    with pytest.raises(ValueError, match="at most 200 records"):
        Catalog.load(path)

    path.write_bytes(b" " * (64 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="64 MiB"):
        Catalog.load(path)

    real_open = os.open
    real_read = os.read
    real_close = os.close
    open_count = 0
    close_count = 0
    open_flags: list[int] = []
    read_sizes: list[int] = []

    def tracking_open(
        path: object, flags: int, *args: object, **kwargs: object
    ) -> int:
        nonlocal open_count
        open_count += 1
        open_flags.append(flags)
        return real_open(path, flags, *args, **kwargs)

    def tracking_read(fd: int, size: int) -> bytes:
        read_sizes.append(size)
        return real_read(fd, size)

    def tracking_close(fd: int) -> None:
        nonlocal close_count
        close_count += 1
        real_close(fd)

    monkeypatch.setattr(os, "open", tracking_open)
    monkeypatch.setattr(os, "read", tracking_read)
    monkeypatch.setattr(os, "close", tracking_close)
    Catalog.load(FIXTURE_PATH)
    assert open_count == 1
    assert len(read_sizes) >= 2
    assert all(0 < size <= 1024 * 1024 for size in read_sizes)
    assert close_count == 1
    assert open_flags[0] & os.O_NONBLOCK
    if hasattr(os, "O_CLOEXEC"):
        assert open_flags[0] & os.O_CLOEXEC

    if hasattr(os, "mkfifo"):
        fifo_path = tmp_path / "special.json"
        os.mkfifo(fifo_path)
        with pytest.raises(ValueError, match="regular file"):
            Catalog.load(fifo_path)
        assert close_count == 2
