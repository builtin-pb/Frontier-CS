import pytest

from lwe_challenge.strict_json import JsonContractError, loads_object


def test_nested_duplicate_key_is_rejected() -> None:
    with pytest.raises(JsonContractError, match="duplicate JSON key: instance_id"):
        loads_object(b'{"x":{"instance_id":"a","instance_id":"b"}}', max_bytes=100)


def test_byte_limit_is_enforced() -> None:
    with pytest.raises(JsonContractError, match="JSON exceeds 1 bytes"):
        loads_object(b"{}", max_bytes=1)


def test_non_finite_number_is_rejected() -> None:
    with pytest.raises(JsonContractError, match="non-finite JSON number: NaN"):
        loads_object(b'{"value":NaN}', max_bytes=100)


@pytest.mark.parametrize("number", ["1e999", "-1e999"])
def test_float_overflow_is_rejected(number: str) -> None:
    data = f'{{"value":{number}}}'.encode()

    with pytest.raises(
        JsonContractError,
        match=rf"^non-finite JSON number: {number}$",
    ):
        loads_object(data, max_bytes=100)


def test_finite_float_is_preserved() -> None:
    assert loads_object(b'{"value":1.25}', max_bytes=100) == {"value": 1.25}


def test_malformed_utf8_is_rejected() -> None:
    with pytest.raises(JsonContractError, match="invalid UTF-8 JSON"):
        loads_object(b'{"value":"\xff"}', max_bytes=100)


@pytest.mark.parametrize(
    "data",
    [b'{"value":"\\ud800"}', b'{"\\udfff":0}'],
    ids=["value", "object-key"],
)
def test_unicode_surrogates_are_rejected(data: bytes) -> None:
    with pytest.raises(JsonContractError, match="^Unicode surrogate in JSON string$"):
        loads_object(data, max_bytes=100)


def test_non_object_input_is_rejected() -> None:
    with pytest.raises(JsonContractError, match="top-level JSON value must be an object"):
        loads_object(b"[]", max_bytes=100)


def test_excessive_nesting_is_rejected() -> None:
    with pytest.raises(JsonContractError, match="JSON exceeds depth 1"):
        loads_object(b'{"outer":{"inner":0}}', max_bytes=100, max_depth=1)


def test_excessive_node_count_is_rejected() -> None:
    with pytest.raises(JsonContractError, match="JSON exceeds 2 nodes"):
        loads_object(b'{"x":0}', max_bytes=100, max_nodes=2)


def test_decoder_recursion_error_is_normalized() -> None:
    data = b'{"value":' + (b"[" * 2_000) + (b"]" * 2_000) + b"}"

    with pytest.raises(JsonContractError, match="^invalid UTF-8 JSON$"):
        loads_object(data, max_bytes=len(data))


def test_decoder_integer_limit_error_is_normalized() -> None:
    data = b'{"value":' + (b"9" * 5_000) + b"}"

    with pytest.raises(JsonContractError, match="^invalid UTF-8 JSON$"):
        loads_object(data, max_bytes=len(data))
