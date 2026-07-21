import errno
import json
from dataclasses import FrozenInstanceError, replace

import pytest

import lwe_challenge.evaluator_core as evaluator_core
import lwe_challenge.verification as verification
from lwe_challenge.evaluator_core import evaluate_bytes, evaluate_path
from lwe_challenge.matrix import matvec_mod
from lwe_challenge.schema import Catalog
from lwe_challenge.strict_json import JsonContractError
from lwe_challenge.submission import MAX_SUBMISSION_BYTES


EXPECTED_METRIC_KEYS = {
    "conflict_count",
    "duplicate_count",
    "instance_count",
    "invalid_count",
    "invalid_examples",
    "rejection_code_counts",
    "solved_count",
    "solved_ids",
    "submitted_count",
    "unknown_count",
}


def test_one_of_two_valid_witnesses_scores_fifty(
    catalog, valid_submission_bytes
) -> None:
    result = evaluate_bytes(valid_submission_bytes, catalog=catalog)

    assert result.score == 50.0
    assert result.score_unbounded == 1.0
    assert result.solved_ids == ("toy-uniform",)
    assert result.metrics["solved_count"] == 1


def test_malformed_whole_submission_scores_zero_with_stable_code(catalog) -> None:
    result = evaluate_bytes(b'{"schema_version":1,"solutions":[', catalog=catalog)

    assert result.score == 0.0
    assert result.score_unbounded == 0.0
    assert result.solved_ids == ()
    assert result.message == "submission_invalid code=invalid_json"


def test_whole_submission_contract_error_uses_code_not_exception_text(
    catalog,
) -> None:
    result = evaluate_bytes(
        b'{"schema_version":2,"solutions":[]}', catalog=catalog
    )

    assert result.score == 0.0
    assert result.message == "submission_invalid code=unsupported_schema_version"
    assert "must be integer" not in repr(result)


def test_direct_json_contract_error_uses_fixed_public_mapping(
    catalog, monkeypatch
) -> None:
    def fail_parse(*_args, **_kwargs):
        raise JsonContractError("PRIVATE-PARSER-DETAIL")

    monkeypatch.setattr(evaluator_core, "parse_submission", fail_parse)

    result = evaluate_bytes(b"{}", catalog=catalog)

    assert result.message == "submission_invalid code=invalid_json"
    assert "PRIVATE-PARSER-DETAIL" not in repr(result)


def test_whole_submission_failure_retains_aggregate_metric_schema(catalog) -> None:
    result = evaluate_bytes(b"not-json", catalog=catalog)

    assert set(result.metrics) == EXPECTED_METRIC_KEYS
    assert result.metrics["instance_count"] == 2
    assert result.metrics["solved_count"] == 0
    assert result.metrics["submitted_count"] == 0
    assert result.metrics["invalid_count"] == 0
    assert result.metrics["rejection_code_counts"] == {}
    assert result.metrics["invalid_examples"] == ()


def test_constructor_created_empty_catalog_is_an_infrastructure_error() -> None:
    empty_catalog = Catalog(1, "empty", ())

    with pytest.raises(ValueError, match="at least one instance"):
        evaluate_bytes(
            b'{"schema_version":1,"solutions":[]}', catalog=empty_catalog
        )


def test_invalid_candidate_does_not_erase_unrelated_valid_score(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[1,0,-1]},'
        b'{"instance_id":"toy-sparse","secret":[0,0,0,0]}]}'
    )

    result = evaluate_bytes(data, catalog=catalog)

    assert result.score == 50.0
    assert result.solved_ids == ("toy-uniform",)
    assert result.metrics["invalid_count"] == 1
    assert result.metrics["rejection_code_counts"] == {"secret_weight": 1}


def test_public_error_predicate_failure_joins_rejection_aggregates(catalog) -> None:
    result = evaluate_bytes(
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[0,0,0]}]}',
        catalog=catalog,
    )

    assert result.score == 0.0
    assert result.metrics["invalid_count"] == 1
    assert result.metrics["rejection_code_counts"] == {"error_linf": 1}
    assert result.metrics["invalid_examples"] == (
        ("toy-uniform", "error_linf"),
    )


def test_malformed_record_does_not_erase_unrelated_valid_score(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'42,{"instance_id":"toy-uniform","secret":[1,0,-1]}]}'
    )

    result = evaluate_bytes(data, catalog=catalog)

    assert result.score == 50.0
    assert result.solved_ids == ("toy-uniform",)
    assert result.metrics["submitted_count"] == 2
    assert result.metrics["invalid_count"] == 1
    assert result.metrics["rejection_code_counts"] == {"record_not_object": 1}


def test_alternate_publicly_valid_witness_is_accepted(catalog) -> None:
    base = catalog.get("toy-uniform")
    first_secret = (1, 0, 0)
    alternate_secret = (0, 1, 0)
    public_error = (1, -1, 0, 1)
    template = replace(
        base,
        instance_id="alternate-witness",
        matrix=replace(
            base.matrix,
            kind="small_alphabet",
            alphabet=(1,),
            row_weight=None,
        ),
        error=replace(
            base.error,
            max_abs=1,
            max_l1=3,
            max_l2_squared=3,
            max_nonzero=3,
        ),
    )
    product = matvec_mod(template, first_secret)
    instance = replace(
        template,
        b=tuple(
            (value + error) % template.q
            for value, error in zip(product, public_error)
        ),
    )
    alternate_catalog = Catalog(1, "alternate-catalog", (instance,))
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"alternate-witness","secret":[0,1,0]}]}'
    )

    result = evaluate_bytes(data, catalog=alternate_catalog)

    assert first_secret != alternate_secret
    assert result.score == 100.0
    assert result.solved_ids == ("alternate-witness",)


def test_duplicate_unknown_and_conflict_aggregates_are_public_counts(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[1,0,-1]},'
        b'{"instance_id":"toy-sparse","secret":[1,-1,0,0]},'
        b'{"instance_id":"toy-sparse","secret":[-1,1,0,0]},'
        b'{"instance_id":"unknown-one","secret":[0]}]}'
    )

    result = evaluate_bytes(data, catalog=catalog)

    assert result.solved_ids == ("toy-uniform",)
    assert result.metrics["submitted_count"] == 4
    assert result.metrics["duplicate_count"] == 1
    assert result.metrics["conflict_count"] == 1
    assert result.metrics["unknown_count"] == 1
    assert result.metrics["invalid_count"] == 3
    assert result.metrics["rejection_code_counts"] == {
        "duplicate_instance_id": 2,
        "unknown_instance_id": 1,
    }


def test_duplicate_poisoned_instance_scores_zero(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[1,0,-1]},'
        b'{"instance_id":"toy-uniform","secret":[1,0,-1]}]}'
    )

    result = evaluate_bytes(data, catalog=catalog)

    assert result.score == 0.0
    assert result.solved_ids == ()
    assert result.metrics["duplicate_count"] == 1
    assert result.metrics["invalid_count"] == 2


def test_private_metadata_does_not_leak_through_public_metrics(catalog) -> None:
    base = catalog.get("toy-uniform")
    secret = (1, 0, -1)
    public_error = (1, -1, 0, 1)

    def with_valid_secret(instance):
        product = matvec_mod(instance, secret)
        return replace(
            instance,
            b=tuple(
                (value + error) % instance.q
                for value, error in zip(product, public_error)
            ),
        )

    instances = (
        with_valid_secret(
            replace(
                base,
                instance_id="easy-ds-bin",
                family="DS_BIN",
                tier="easy",
                cohort="paper",
                octave=None,
                runtime_bin="E0",
            )
        ),
        with_valid_secret(
            replace(
                base,
                instance_id="easy-ds-ter",
                family="DS_TER",
                tier="easy",
                cohort="paper",
                octave=None,
                runtime_bin="E1",
            )
        ),
        with_valid_secret(
            replace(
                base,
                instance_id="hard-sa-q",
                family="SA_Q",
                tier="hard",
                cohort="ladder",
                octave=2,
                runtime_bin="H2",
            )
        ),
        with_valid_secret(
            replace(
                base,
                instance_id="hard-mix-q",
                family="MIX_Q_SPARSE",
                tier="hard",
                cohort="ladder",
                octave=5,
                runtime_bin="H5",
            )
        ),
        with_valid_secret(replace(base, instance_id="synthetic-control")),
    )
    metadata_catalog = Catalog(1, "metadata-catalog", instances)
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"easy-ds-bin","secret":[1,0,-1]},'
        b'{"instance_id":"hard-sa-q","secret":[1,0,-1]},'
        b'{"instance_id":"hard-mix-q","secret":[1,0,-1]}]}'
    )

    result = evaluate_bytes(data, catalog=metadata_catalog)

    assert result.metrics["instance_count"] == 5
    assert result.metrics["solved_count"] == 3
    for private_key in (
        "easy_total",
        "easy_solved_count",
        "paper_total",
        "paper_solved_count",
        "hard_total",
        "hard_solved_count",
        "family_solved_counts",
        "hard_octave_totals",
        "hard_octave_solved_counts",
        "hardest_solved_octave",
    ):
        assert private_key not in result.metrics


def test_invalid_examples_are_capped_without_truncating_aggregates(catalog) -> None:
    data = json.dumps(
        {
            "schema_version": 1,
            "solutions": [
                {"instance_id": f"unknown-{index:02d}", "secret": [0]}
                for index in range(25)
            ],
        },
        separators=(",", ":"),
    ).encode()

    result = evaluate_bytes(data, catalog=catalog)

    assert result.metrics["submitted_count"] == 25
    assert result.metrics["unknown_count"] == 25
    assert result.metrics["invalid_count"] == 25
    assert result.metrics["rejection_code_counts"] == {
        "unknown_instance_id": 25
    }
    assert len(result.metrics["invalid_examples"]) == 20
    assert result.metrics["invalid_examples"][0] == (
        None,
        "unknown_instance_id",
    )
    assert result.metrics["invalid_examples"][-1] == (
        None,
        "unknown_instance_id",
    )


def test_unsafe_submitted_id_is_not_reflected_in_public_examples(catalog) -> None:
    attacker_id = "_PRIVATE-CONTROL-MARKER"
    data = json.dumps(
        {
            "schema_version": 1,
            "solutions": [{"instance_id": attacker_id, "secret": [0]}],
        },
        separators=(",", ":"),
    ).encode()

    result = evaluate_bytes(data, catalog=catalog)

    assert result.metrics["invalid_examples"] == ((None, "invalid_instance_id"),)
    assert attacker_id not in repr(result)


def test_safe_looking_unknown_id_is_not_reflected_in_public_examples(
    catalog,
) -> None:
    attacker_id = "PRIVATE-CONTROL-MARKER"
    data = json.dumps(
        {
            "schema_version": 1,
            "solutions": [{"instance_id": attacker_id, "secret": [0]}],
        },
        separators=(",", ":"),
    ).encode()

    result = evaluate_bytes(data, catalog=catalog)

    assert result.metrics["unknown_count"] == 1
    assert result.metrics["invalid_examples"] == ((None, "unknown_instance_id"),)
    assert attacker_id not in repr(result)


def test_public_result_is_deeply_immutable_and_does_not_leak_witness_data(
    catalog,
) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[8675309,0,0]}]}'
    )

    result = evaluate_bytes(data, catalog=catalog)
    public_text = repr((result.message, result.metrics, result.solved_ids))

    assert result.message == (
        "scored solved=0 submitted=1 invalid=1 duplicates=0 conflicts=0 unknown=0"
    )
    for forbidden in (
        "8675309",
        "analysis/toy-uniform.md",
        "max_abs_error",
        "l1_error",
        "l2_squared_error",
        "residual",
        "Traceback",
    ):
        assert forbidden not in public_text
    with pytest.raises(TypeError):
        result.metrics["solved_count"] = 99
    with pytest.raises(TypeError):
        result.metrics["rejection_code_counts"]["secret_alphabet"] = 99
    with pytest.raises(FrozenInstanceError):
        result.score = 100.0
    assert not hasattr(result, "__dict__")


def test_missing_submission_path_scores_zero_with_stable_code(
    catalog, tmp_path
) -> None:
    result = evaluate_path(tmp_path / "missing.json", catalog=catalog)

    assert result.score == 0.0
    assert result.message == "submission_invalid code=submission_missing"
    assert result.metrics["submitted_count"] == 0


def test_unreadable_submission_path_scores_zero_with_stable_code(
    catalog, monkeypatch, tmp_path
) -> None:
    path = tmp_path / "unreadable.json"
    path.write_bytes(b'{"schema_version":1,"solutions":[]}')

    def deny_open(*_args, **_kwargs):
        raise PermissionError(errno.EACCES, "private operating-system detail")

    monkeypatch.setattr(evaluator_core.os, "open", deny_open)

    result = evaluate_path(path, catalog=catalog)

    assert result.score == 0.0
    assert result.message == "submission_invalid code=submission_unreadable"
    assert "private operating-system detail" not in repr(result)


def test_operation_not_permitted_submission_path_is_stably_unreadable(
    catalog, monkeypatch, tmp_path
) -> None:
    path = tmp_path / "sandbox-denied.json"
    path.write_bytes(b'{"schema_version":1,"solutions":[]}')

    def deny_open(*_args, **_kwargs):
        raise PermissionError(errno.EPERM, "private sandbox detail")

    monkeypatch.setattr(evaluator_core.os, "open", deny_open)

    result = evaluate_path(path, catalog=catalog)

    assert result.score == 0.0
    assert result.message == "submission_invalid code=submission_unreadable"
    assert "private sandbox detail" not in repr(result)


def test_symlink_loop_submission_path_is_stably_unreadable(
    catalog, tmp_path
) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.symlink_to(second)
    second.symlink_to(first)

    result = evaluate_path(first, catalog=catalog)

    assert result.score == 0.0
    assert result.message == "submission_invalid code=submission_unreadable"


def test_non_directory_submission_component_is_stably_unreadable(
    catalog, tmp_path
) -> None:
    component = tmp_path / "not-a-directory"
    component.write_bytes(b"regular file")

    result = evaluate_path(component / "submission.json", catalog=catalog)

    assert result.score == 0.0
    assert result.message == "submission_invalid code=submission_unreadable"


def test_nonregular_submission_path_is_rejected_before_reading(
    catalog, tmp_path
) -> None:
    result = evaluate_path(tmp_path, catalog=catalog)

    assert result.score == 0.0
    assert result.message == "submission_invalid code=submission_not_regular"


def test_fifo_submission_path_is_opened_nonblocking_and_rejected(
    catalog, tmp_path
) -> None:
    path = tmp_path / "submission.fifo"
    evaluator_core.os.mkfifo(path)

    result = evaluate_path(path, catalog=catalog)

    assert result.score == 0.0
    assert result.message == "submission_invalid code=submission_not_regular"


def test_oversize_submission_path_is_bounded_and_rejected(catalog, tmp_path) -> None:
    path = tmp_path / "oversize.json"
    path.write_bytes(b" " * (MAX_SUBMISSION_BYTES + 1))

    result = evaluate_path(path, catalog=catalog)

    assert result.score == 0.0
    assert result.message == "submission_invalid code=submission_too_large"


def test_submission_growth_after_fstat_is_still_capped(
    catalog, monkeypatch, tmp_path, valid_submission_bytes
) -> None:
    path = tmp_path / "growing.json"
    path.write_bytes(valid_submission_bytes)
    original_fstat = evaluator_core.os.fstat
    hook_called = False

    def grow_after_fstat(fd):
        nonlocal hook_called
        metadata = original_fstat(fd)
        with path.open("ab") as output:
            output.write(b" " * MAX_SUBMISSION_BYTES)
        hook_called = True
        return metadata

    monkeypatch.setattr(evaluator_core.os, "fstat", grow_after_fstat)

    result = evaluate_path(path, catalog=catalog)

    assert hook_called is True
    assert result.score == 0.0
    assert result.message == "submission_invalid code=submission_too_large"


def test_regular_submission_read_is_capped_at_protocol_limit_plus_one(
    catalog, monkeypatch, tmp_path, valid_submission_bytes
) -> None:
    path = tmp_path / "submission.json"
    path.write_bytes(valid_submission_bytes)
    original_read = evaluator_core.os.read
    requested_sizes = []

    def recording_read(fd, count):
        requested_sizes.append(count)
        return original_read(fd, count)

    monkeypatch.setattr(evaluator_core.os, "read", recording_read)

    result = evaluate_path(path, catalog=catalog)

    assert result.score == 50.0
    assert requested_sizes[0] == MAX_SUBMISSION_BYTES + 1
    assert requested_sizes[-1] <= MAX_SUBMISSION_BYTES + 1


def test_short_regular_file_reads_are_completed_within_the_cap(
    catalog, monkeypatch, tmp_path, valid_submission_bytes
) -> None:
    path = tmp_path / "submission.json"
    path.write_bytes(valid_submission_bytes)
    original_read = evaluator_core.os.read
    returned_sizes = []

    def short_read(fd, count):
        chunk = original_read(fd, min(count, 7))
        returned_sizes.append(len(chunk))
        return chunk

    monkeypatch.setattr(evaluator_core.os, "read", short_read)

    result = evaluate_path(path, catalog=catalog)

    assert result.score == 50.0
    assert sum(returned_sizes) == len(valid_submission_bytes)
    assert sum(returned_sizes) <= MAX_SUBMISSION_BYTES + 1


def test_unexpected_submission_path_oserror_propagates(
    catalog, monkeypatch, tmp_path
) -> None:
    def fail_open(*_args, **_kwargs):
        raise OSError(errno.EIO, "infrastructure I/O failure")

    monkeypatch.setattr(evaluator_core.os, "open", fail_open)

    with pytest.raises(OSError, match="infrastructure I/O failure"):
        evaluate_path(tmp_path / "submission.json", catalog=catalog)


def test_unexpected_matrix_failure_propagates(catalog, monkeypatch) -> None:
    def fail_matrix(*_args, **_kwargs):
        raise RuntimeError("matrix infrastructure failed")

    monkeypatch.setattr(verification, "matvec_mod", fail_matrix)

    with pytest.raises(RuntimeError, match="matrix infrastructure failed"):
        evaluate_bytes(
            b'{"schema_version":1,"solutions":['
            b'{"instance_id":"toy-uniform","secret":[1,0,-1]}]}',
            catalog=catalog,
        )
