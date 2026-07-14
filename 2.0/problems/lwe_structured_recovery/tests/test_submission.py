import json
import traceback

import pytest

from lwe_challenge.schema import MAX_N
from lwe_challenge.submission import (
    MAX_SUBMISSION_BYTES,
    SubmissionContractError,
    SubmissionRejection,
    parse_submission,
)


def test_conflicting_duplicate_invalidates_only_that_id(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[1,0,-1]},'
        b'{"instance_id":"toy-uniform","secret":[0,0,0]},'
        b'{"instance_id":"toy-sparse","secret":[0,0,0,0]}]}'
    )
    parsed = parse_submission(data, catalog=catalog)
    assert set(parsed.records) == {"toy-sparse"}
    assert parsed.conflicted_ids == ("toy-uniform",)


def test_top_level_fields_are_exact(catalog) -> None:
    data = b'{"schema_version":1,"solutions":[],"ignored":true}'

    with pytest.raises(SubmissionContractError, match="submission fields") as raised:
        parse_submission(data, catalog=catalog)
    assert raised.value.code == "invalid_submission_fields"


@pytest.mark.parametrize("version", [b"true", b"1.0", b"2", b'"1"', b"null"])
def test_schema_version_is_integer_one(catalog, version: bytes) -> None:
    data = b'{"schema_version":' + version + b',"solutions":[]}'

    with pytest.raises(SubmissionContractError, match="schema_version") as raised:
        parse_submission(data, catalog=catalog)
    assert raised.value.code == "unsupported_schema_version"


def test_solutions_is_a_bounded_list(catalog) -> None:
    with pytest.raises(SubmissionContractError, match="solutions.*array") as raised:
        parse_submission(
            b'{"schema_version":1,"solutions":{}}', catalog=catalog
        )
    assert raised.value.code == "invalid_solutions"

    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[]},'
        b'{"instance_id":"toy-sparse","secret":[]}]} '
    )
    with pytest.raises(SubmissionContractError, match="at most 1 record") as raised:
        parse_submission(data, catalog=catalog, max_records=1)
    assert raised.value.code == "too_many_records"


@pytest.mark.parametrize("max_bytes", [True, 0, -1])
def test_max_bytes_must_be_a_positive_exact_integer(catalog, max_bytes: object) -> None:
    with pytest.raises(ValueError, match="max_bytes must be a positive integer"):
        parse_submission(
            b'{"schema_version":1,"solutions":[]}',
            catalog=catalog,
            max_bytes=max_bytes,
        )


@pytest.mark.parametrize("max_records", [True, 0, -1])
def test_max_records_must_be_a_positive_exact_integer(
    catalog, max_records: object
) -> None:
    with pytest.raises(ValueError, match="max_records must be a positive integer"):
        parse_submission(
            b'{"schema_version":1,"solutions":[]}',
            catalog=catalog,
            max_records=max_records,
        )


def test_identical_duplicates_count_every_occurrence_as_invalid(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[1,0,-1]},'
        b'{"instance_id":"toy-uniform","secret":[1,0,-1]},'
        b'{"instance_id":"toy-sparse","secret":[0,0,0,0]}]}'
    )

    parsed = parse_submission(data, catalog=catalog)

    assert dict(parsed.records) == {"toy-sparse": (0, 0, 0, 0)}
    assert parsed.duplicate_ids == ("toy-uniform",)
    assert parsed.conflicted_ids == ()
    assert parsed.invalid_records == 2
    assert parsed.rejections == (
        SubmissionRejection("toy-uniform", "duplicate_instance_id"),
        SubmissionRejection("toy-uniform", "duplicate_instance_id"),
    )


def test_unknown_ids_are_rejected_without_hiding_known_records(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"unknown-z","secret":[1]},'
        b'{"instance_id":"toy-sparse","secret":[0,0,0,0]},'
        b'{"instance_id":"unknown-a","secret":[2]}]}'
    )

    parsed = parse_submission(data, catalog=catalog)

    assert dict(parsed.records) == {"toy-sparse": (0, 0, 0, 0)}
    assert parsed.unknown_ids == ("unknown-a", "unknown-z")
    assert parsed.invalid_records == 2
    assert parsed.rejections == (
        SubmissionRejection("unknown-z", "unknown_instance_id"),
        SubmissionRejection("unknown-a", "unknown_instance_id"),
    )


def test_invalid_ids_are_not_echoed_or_used_for_duplicate_detection(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"_leading","secret":[1]},'
        b'{"instance_id":"_leading","secret":[2]},'
        b'{"instance_id":"toy-uniform","secret":[0,0,0]}]}'
    )

    parsed = parse_submission(data, catalog=catalog)

    assert dict(parsed.records) == {"toy-uniform": (0, 0, 0)}
    assert parsed.duplicate_ids == ()
    assert parsed.unknown_ids == ()
    assert parsed.invalid_records == 2
    assert parsed.rejections == (
        SubmissionRejection(None, "invalid_instance_id"),
        SubmissionRejection(None, "invalid_instance_id"),
    )


def test_boolean_secret_entry_is_rejected_without_hiding_other_records(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[true,0,0]},'
        b'{"instance_id":"toy-sparse","secret":[0,0,0,0]}]}'
    )

    parsed = parse_submission(data, catalog=catalog)

    assert dict(parsed.records) == {"toy-sparse": (0, 0, 0, 0)}
    assert parsed.invalid_records == 1
    assert parsed.rejections == (
        SubmissionRejection("toy-uniform", "invalid_secret"),
    )


def test_record_fields_are_exact(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[0,0,0],"note":"x"},'
        b'{"instance_id":"toy-sparse","secret":[0,0,0,0]}]}'
    )

    parsed = parse_submission(data, catalog=catalog)

    assert dict(parsed.records) == {"toy-sparse": (0, 0, 0, 0)}
    assert parsed.invalid_records == 1
    assert parsed.rejections == (
        SubmissionRejection("toy-uniform", "invalid_record_fields"),
    )


def test_non_object_and_missing_id_records_are_isolated(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'42,{"secret":[1]},'
        b'{"instance_id":"toy-sparse","secret":[0,0,0,0]}]}'
    )

    parsed = parse_submission(data, catalog=catalog)

    assert dict(parsed.records) == {"toy-sparse": (0, 0, 0, 0)}
    assert parsed.invalid_records == 2
    assert parsed.rejections == (
        SubmissionRejection(None, "record_not_object"),
        SubmissionRejection(None, "invalid_instance_id"),
    )


def test_records_are_sorted_and_immutable(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[0,0,0]},'
        b'{"instance_id":"toy-sparse","secret":[0,0,0,0]}]}'
    )

    parsed = parse_submission(data, catalog=catalog)

    assert tuple(parsed.records) == ("toy-sparse", "toy-uniform")
    with pytest.raises(TypeError):
        parsed.records["toy-uniform"] = (1, 1, 1)


def test_malformed_secret_duplicate_poisoning_invalidates_the_first_copy(
    catalog,
) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[1,0,-1]},'
        b'{"instance_id":"toy-uniform","secret":"malformed"},'
        b'{"instance_id":"toy-sparse","secret":[0,0,0,0]}]}'
    )

    parsed = parse_submission(data, catalog=catalog)

    assert dict(parsed.records) == {"toy-sparse": (0, 0, 0, 0)}
    assert parsed.duplicate_ids == ("toy-uniform",)
    assert parsed.conflicted_ids == ()
    assert parsed.invalid_records == 2
    assert parsed.rejections == (
        SubmissionRejection("toy-uniform", "duplicate_instance_id"),
        SubmissionRejection("toy-uniform", "duplicate_instance_id"),
    )


def test_unknown_ids_participate_in_duplicate_and_conflict_tracking(catalog) -> None:
    data = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"unknown-z","secret":[1]},'
        b'{"instance_id":"unknown-z","secret":[2]},'
        b'{"instance_id":"toy-sparse","secret":[0,0,0,0]}]}'
    )

    parsed = parse_submission(data, catalog=catalog)

    assert dict(parsed.records) == {"toy-sparse": (0, 0, 0, 0)}
    assert parsed.duplicate_ids == ("unknown-z",)
    assert parsed.conflicted_ids == ("unknown-z",)
    assert parsed.unknown_ids == ("unknown-z",)
    assert parsed.invalid_records == 2


def test_json_contract_errors_do_not_reflect_attacker_controlled_keys(catalog) -> None:
    attacker_key = "secret-like\nCONTROL"
    data = (
        b'{"schema_version":1,"solutions":[],'
        b'"secret-like\\nCONTROL":1,"secret-like\\nCONTROL":2}'
    )

    with pytest.raises(SubmissionContractError) as raised:
        parse_submission(data, catalog=catalog)

    assert raised.value.code == "invalid_json"
    assert str(raised.value) == "invalid_json"
    assert attacker_key not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None
    assert attacker_key not in "".join(traceback.format_exception(raised.value))


@pytest.mark.parametrize(
    "data",
    [
        b'{"schema_version":1,"schema_version":1,"solutions":[]}',
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","instance_id":"toy-sparse",'
        b'"secret":[]}]}',
        b'{"schema_version":1,"solutions":[],"x":"\xff"}',
        b'{"schema_version":1,"solutions":[',
        b"[]",
    ],
)
def test_ambiguous_or_malformed_json_is_a_whole_ledger_error(
    catalog, data: bytes
) -> None:
    with pytest.raises(SubmissionContractError) as raised:
        parse_submission(data, catalog=catalog)
    assert raised.value.code == "invalid_json"
    assert str(raised.value) == "invalid_json"


def test_byte_depth_and_node_limits_are_whole_ledger_errors(catalog) -> None:
    with pytest.raises(SubmissionContractError) as raised:
        parse_submission(
            b'{"schema_version":1,"solutions":[]}',
            catalog=catalog,
            max_bytes=1,
        )
    assert raised.value.code == "invalid_json"
    assert str(raised.value) == "invalid_json"

    too_deep = (
        b'{"schema_version":1,"solutions":['
        b'{"instance_id":"toy-uniform","secret":[[0]]}]}'
    )
    with pytest.raises(SubmissionContractError) as raised:
        parse_submission(too_deep, catalog=catalog)
    assert raised.value.code == "invalid_json"
    assert str(raised.value) == "invalid_json"

    too_many_nodes = json.dumps(
        {
            "schema_version": 1,
            "solutions": [
                {"instance_id": "toy-uniform", "secret": [0] * (MAX_N + 1)}
            ],
        },
        separators=(",", ":"),
    ).encode()
    with pytest.raises(SubmissionContractError) as raised:
        parse_submission(too_many_nodes, catalog=catalog, max_records=1)
    assert raised.value.code == "invalid_json"
    assert str(raised.value) == "invalid_json"


def test_protocol_record_cap_cannot_be_raised_by_the_caller(catalog) -> None:
    records = [
        {"instance_id": f"unknown-{index}", "secret": []}
        for index in range(201)
    ]
    data = json.dumps(
        {"schema_version": 1, "solutions": records}, separators=(",", ":")
    ).encode()

    with pytest.raises(SubmissionContractError, match="at most 200 records") as raised:
        parse_submission(data, catalog=catalog, max_records=1_000)
    assert raised.value.code == "too_many_records"


def test_protocol_byte_cap_cannot_be_raised_by_the_caller(catalog) -> None:
    data = b" " * (MAX_SUBMISSION_BYTES + 1)

    with pytest.raises(SubmissionContractError) as raised:
        parse_submission(
            data,
            catalog=catalog,
            max_bytes=MAX_SUBMISSION_BYTES + 1,
        )

    assert raised.value.code == "invalid_json"
    assert str(raised.value) == "invalid_json"


@pytest.mark.parametrize(
    "secret",
    [
        [2**63],
        [-(2**63)],
        [1.0],
        ["1"],
        None,
        {},
    ],
)
def test_secret_requires_a_bounded_integer_array(catalog, secret: object) -> None:
    data = json.dumps(
        {
            "schema_version": 1,
            "solutions": [{"instance_id": "toy-uniform", "secret": secret}],
        },
        separators=(",", ":"),
    ).encode()

    parsed = parse_submission(data, catalog=catalog)

    assert dict(parsed.records) == {}
    assert parsed.invalid_records == 1
    assert parsed.rejections == (
        SubmissionRejection("toy-uniform", "invalid_secret"),
    )


def test_secret_integer_magnitude_boundary_is_inclusive(catalog) -> None:
    bound = 2**63 - 1
    data = json.dumps(
        {
            "schema_version": 1,
            "solutions": [
                {"instance_id": "toy-uniform", "secret": [bound]},
                {"instance_id": "toy-sparse", "secret": [-bound]},
            ],
        },
        separators=(",", ":"),
    ).encode()

    parsed = parse_submission(data, catalog=catalog)

    assert dict(parsed.records) == {
        "toy-sparse": (-bound,),
        "toy-uniform": (bound,),
    }


@pytest.mark.parametrize(
    "instance_id",
    ["", "a" * 65, "contains space", "café", True, 1],
)
def test_instance_id_uses_the_catalog_safe_token_grammar(
    catalog, instance_id: object
) -> None:
    data = json.dumps(
        {
            "schema_version": 1,
            "solutions": [{"instance_id": instance_id, "secret": []}],
        },
        separators=(",", ":"),
    ).encode()

    parsed = parse_submission(data, catalog=catalog)

    assert parsed.duplicate_ids == ()
    assert parsed.unknown_ids == ()
    assert parsed.rejections == (
        SubmissionRejection(None, "invalid_instance_id"),
    )


def test_missing_secret_is_an_invalid_record_shape(catalog) -> None:
    data = b'{"schema_version":1,"solutions":[{"instance_id":"toy-uniform"}]}'

    parsed = parse_submission(data, catalog=catalog)

    assert parsed.rejections == (
        SubmissionRejection("toy-uniform", "invalid_record_fields"),
    )
