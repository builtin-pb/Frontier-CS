from dataclasses import FrozenInstanceError, replace

import pytest

from lwe_challenge.matrix import matvec_mod
from lwe_challenge.verification import (
    WitnessVerdict,
    centered_mod,
    residual,
    validate_secret,
    validate_secret_shape,
)


def _mod_q_instance(catalog):
    base = catalog.get("toy-uniform")
    return replace(
        base,
        secret_distribution=replace(
            base.secret_distribution,
            kind="uniform_mod_q",
            alphabet=(),
            weight=None,
            eta=None,
        ),
        secret=replace(base.secret, kind="mod_q", alphabet=()),
    )


def _multi_witness_instance(catalog):
    base = catalog.get("toy-uniform")
    first_secret = (1, 0, 0)
    second_secret = (0, 1, 0)
    public_error = (1, -1, 0, 1)
    template = replace(
        base,
        instance_id="verification-multiple-witnesses",
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
            (entry + error) % template.q
            for entry, error in zip(product, public_error)
        ),
    )
    return instance, first_secret, second_secret, public_error


def _instance_with_public_error(catalog, public_error, **predicate_updates):
    base = catalog.get("toy-uniform")
    secret = (1, 0, -1)
    template = replace(
        base,
        instance_id="verification-error-predicates",
        error=replace(base.error, **predicate_updates),
    )
    product = matvec_mod(template, secret)
    instance = replace(
        template,
        b=tuple(
            (entry + error) % template.q
            for entry, error in zip(product, public_error)
        ),
    )
    return instance, secret


def test_centered_mod_uses_negative_even_tie() -> None:
    assert tuple(centered_mod(x, 8) for x in range(8)) == (
        0,
        1,
        2,
        3,
        -4,
        -3,
        -2,
        -1,
    )


def test_centered_mod_handles_odd_moduli_negative_values_and_q_one() -> None:
    assert tuple(centered_mod(x, 7) for x in range(7)) == (
        0,
        1,
        2,
        3,
        -3,
        -2,
        -1,
    )
    assert centered_mod(-5, 8) == 3
    assert centered_mod(10**100, 1) == 0


@pytest.mark.parametrize(
    ("value", "q"),
    ((True, 8), (1.5, 8), ("1", 8), (1, True), (1, 8.0), (1, "8")),
)
def test_centered_mod_rejects_booleans_and_nonintegers(value, q) -> None:
    with pytest.raises(TypeError, match="integer"):
        centered_mod(value, q)


@pytest.mark.parametrize("q", (0, -1))
def test_centered_mod_rejects_nonpositive_modulus(q) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        centered_mod(0, q)


def test_validate_secret_reports_wrong_length_without_norms(catalog) -> None:
    verdict = validate_secret(catalog.get("toy-uniform"), (0, 0))

    assert verdict.ok is False
    assert verdict.code == "wrong_length"
    assert verdict.max_abs_error is None
    assert verdict.l1_error is None
    assert verdict.l2_squared_error is None
    assert validate_secret_shape(catalog.get("toy-uniform"), (True,)) == (
        "wrong_length"
    )


@pytest.mark.parametrize(
    "secret",
    ((0, True, 0), (0, 1.5, 0), (0, "1", 0), None),
)
def test_validate_secret_reports_secret_type_for_noninteger_entries(
    catalog, secret
) -> None:
    verdict = validate_secret(catalog.get("toy-uniform"), secret)

    assert verdict.ok is False
    assert verdict.code == "secret_type"
    assert verdict.max_abs_error is None
    assert verdict.l1_error is None
    assert verdict.l2_squared_error is None


def test_validate_secret_reports_secret_alphabet(catalog) -> None:
    verdict = validate_secret(catalog.get("toy-uniform"), (0, 2, 0))

    assert verdict.ok is False
    assert verdict.code == "secret_alphabet"
    assert verdict.max_abs_error is None
    assert verdict.l1_error is None
    assert verdict.l2_squared_error is None


@pytest.mark.parametrize("secret", ((-1, 0, 0), (17, 0, 0)))
def test_validate_secret_reports_secret_mod_q(catalog, secret) -> None:
    verdict = validate_secret(_mod_q_instance(catalog), secret)

    assert verdict.ok is False
    assert verdict.code == "secret_mod_q"
    assert verdict.max_abs_error is None
    assert verdict.l1_error is None
    assert verdict.l2_squared_error is None


@pytest.mark.parametrize("secret", ((1, 0, 0, 0), (1, 1, 1, 0)))
def test_validate_secret_reports_secret_weight(catalog, secret) -> None:
    verdict = validate_secret(catalog.get("toy-sparse"), secret)

    assert verdict.ok is False
    assert verdict.code == "secret_weight"
    assert verdict.max_abs_error is None
    assert verdict.l1_error is None
    assert verdict.l2_squared_error is None


def test_residual_reconstructs_centered_public_error(catalog) -> None:
    instance, secret, _, expected_error = _multi_witness_instance(catalog)

    assert residual(instance, secret) == expected_error


def test_distinct_publicly_valid_witnesses_are_both_accepted(catalog) -> None:
    instance, first_secret, second_secret, expected_error = (
        _multi_witness_instance(catalog)
    )
    assert first_secret != second_secret
    assert residual(instance, second_secret) == expected_error

    first = validate_secret(instance, first_secret)
    second = validate_secret(instance, second_secret)

    for verdict in (first, second):
        assert verdict.ok is True
        assert verdict.code == "ok"
        assert verdict.max_abs_error == 1
        assert verdict.l1_error == 3
        assert verdict.l2_squared_error == 3

        assert type(verdict.max_abs_error) is int
        assert type(verdict.l1_error) is int
        assert type(verdict.l2_squared_error) is int


def test_canonical_mod_q_secret_and_inclusive_weight_bounds_are_accepted(
    catalog,
) -> None:
    mod_q_instance = _mod_q_instance(catalog)
    canonical_secret = (0, mod_q_instance.q - 1, 1)
    mod_q_instance = replace(
        mod_q_instance,
        b=matvec_mod(mod_q_instance, canonical_secret),
    )
    mod_q_verdict = validate_secret(mod_q_instance, canonical_secret)

    weighted_instance = catalog.get("toy-sparse")
    boundary_weight_secret = (1, -1, 0, 0)
    weighted_instance = replace(
        weighted_instance,
        b=matvec_mod(weighted_instance, boundary_weight_secret),
    )
    weighted_verdict = validate_secret(weighted_instance, boundary_weight_secret)

    assert mod_q_verdict == WitnessVerdict(True, "ok", 0, 0, 0)
    assert weighted_verdict == WitnessVerdict(True, "ok", 0, 0, 0)


def test_optional_error_bounds_are_not_implicitly_zero(catalog) -> None:
    instance, secret = _instance_with_public_error(
        catalog,
        (1, -1, 1, -1),
        max_l1=None,
        max_l2_squared=None,
        max_nonzero=None,
    )

    assert validate_secret(instance, secret) == WitnessVerdict(
        True, "ok", 1, 4, 4
    )


def test_validate_secret_reports_error_linf_with_aggregate_norms(catalog) -> None:
    instance, secret = _instance_with_public_error(catalog, (2, 0, 0, 0))

    verdict = validate_secret(instance, secret)

    assert verdict.ok is False
    assert verdict.code == "error_linf"
    assert verdict.max_abs_error == 2
    assert verdict.l1_error == 2
    assert verdict.l2_squared_error == 4


def test_validate_secret_reports_error_l1_with_aggregate_norms(catalog) -> None:
    instance, secret = _instance_with_public_error(
        catalog, (1, -1, 0, 0), max_l1=1
    )

    verdict = validate_secret(instance, secret)

    assert verdict.ok is False
    assert verdict.code == "error_l1"
    assert verdict.max_abs_error == 1
    assert verdict.l1_error == 2
    assert verdict.l2_squared_error == 2


def test_validate_secret_reports_error_l2_with_aggregate_norms(catalog) -> None:
    instance, secret = _instance_with_public_error(
        catalog, (1, -1, 0, 0), max_l1=2, max_l2_squared=1
    )

    verdict = validate_secret(instance, secret)

    assert verdict.ok is False
    assert verdict.code == "error_l2"
    assert verdict.max_abs_error == 1
    assert verdict.l1_error == 2
    assert verdict.l2_squared_error == 2


def test_validate_secret_reports_error_weight_with_aggregate_norms(catalog) -> None:
    instance, secret = _instance_with_public_error(
        catalog,
        (1, -1, 0, 0),
        max_l1=2,
        max_l2_squared=2,
        max_nonzero=1,
    )

    verdict = validate_secret(instance, secret)

    assert verdict.ok is False
    assert verdict.code == "error_weight"
    assert verdict.max_abs_error == 1
    assert verdict.l1_error == 2
    assert verdict.l2_squared_error == 2


def test_error_predicates_use_deterministic_failure_order(catalog) -> None:
    instance, secret = _instance_with_public_error(
        catalog,
        (2, -2, 0, 0),
        max_abs=1,
        max_l1=1,
        max_l2_squared=1,
        max_nonzero=1,
    )

    assert validate_secret(instance, secret).code == "error_linf"


def test_residual_rejects_invalid_witness_without_echoing_it(catalog) -> None:
    invalid_secret = (123456789, 0)

    with pytest.raises(ValueError) as exc_info:
        residual(catalog.get("toy-uniform"), invalid_secret)

    assert str(exc_info.value) == "invalid secret: wrong_length"
    assert repr(invalid_secret) not in str(exc_info.value)


def test_witness_verdict_is_immutable_slotted_and_has_aggregate_only_repr(
    catalog,
) -> None:
    instance, secret, _, _ = _multi_witness_instance(catalog)
    verdict = validate_secret(instance, secret)

    with pytest.raises(FrozenInstanceError):
        verdict.code = "changed"  # type: ignore[misc]

    assert not hasattr(verdict, "__dict__")
    verdict_repr = repr(verdict).lower()
    assert "secret" not in verdict_repr
    assert "residual" not in verdict_repr
    assert set(WitnessVerdict.__dataclass_fields__) == {
        "ok",
        "code",
        "max_abs_error",
        "l1_error",
        "l2_squared_error",
    }
