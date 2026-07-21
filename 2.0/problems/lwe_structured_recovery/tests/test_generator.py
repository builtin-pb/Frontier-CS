from __future__ import annotations

import decimal
import hashlib
import inspect
import json
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

import pytest

import lwe_challenge.generator as generator_module
from lwe_challenge.generator import (
    GeneratedInstance,
    GenerationAttestation,
    GenerationTemplate,
    _discrete_gaussian_table,
    _generate,
    generate_production_instance,
    generate_synthetic_instance,
)
from lwe_challenge.schema import (
    Catalog,
    ErrorDistributionSpec,
    ErrorPredicateSpec,
    MATRIX_EXPANSION_DOMAIN,
    MatrixSpec,
    SecretDistributionSpec,
    SecretPredicateSpec,
    canonical_record_bytes,
    compute_instance_digest,
)
from lwe_challenge.verification import residual, validate_secret


_FIXTURE_PRIVATE_SEEDS = (
    bytes.fromhex("aa" * 32),
    bytes.fromhex("bb" * 32),
)
_GAUSSIAN_TABLE_1_25_BOUND_3 = (
    (-3, 15_800_531_061_396),
    (-2, 78_260_542_669_756),
    (-1, 204_392_783_298_782),
    (0, 281_474_976_710_656),
    (1, 204_392_783_298_782),
    (2, 78_260_542_669_756),
    (3, 15_800_531_061_396),
)


class _IndexDivergentAlphabet:
    def __iter__(self):
        return iter((-1, 0, 1))

    def __len__(self) -> int:
        return 3

    def __getitem__(self, index: int) -> int:
        return (1, 0, -1)[index]


class _SelfMutatingAlphabet:
    def __init__(self) -> None:
        self._values = [-1, 0, 1]
        self.mutated = False

    def __iter__(self):
        snapshot = tuple(self._values)
        yield from snapshot
        self._values[:] = [1, 0, -1]
        self.mutated = True

    def __len__(self) -> int:
        return len(self._values)

    def __getitem__(self, index: int) -> int:
        return self._values[index]


class _IterationBombAlphabet:
    def __init__(self) -> None:
        self.iterated = False

    def __iter__(self):
        self.iterated = True
        raise AssertionError("oversized alphabet was iterated")

    def __len__(self) -> int:
        return 2_000_000_001

    def __getitem__(self, _index: int) -> int:
        raise AssertionError("oversized alphabet was indexed")


class _LengthLiarAlphabet:
    def __init__(self) -> None:
        self.yielded = 0

    def __iter__(self):
        for value in range(10_000):
            self.yielded += 1
            yield value

    def __len__(self) -> int:
        return 1


@pytest.fixture
def toy_template() -> GenerationTemplate:
    return GenerationTemplate(
        instance_id="toy-uniform",
        n=3,
        m=4,
        q=17,
        matrix=MatrixSpec(
            kind="uniform",
            seed_hex="00" * 32,
            expansion_domain=MATRIX_EXPANSION_DOMAIN,
        ),
        secret_distribution=SecretDistributionSpec(
            kind="iid_alphabet",
            alphabet=(-1, 0, 1),
            weight=None,
            eta=None,
        ),
        secret=SecretPredicateSpec(
            kind="alphabet",
            alphabet=(-1, 0, 1),
            min_nonzero=0,
            max_nonzero=3,
        ),
        error_distribution=ErrorDistributionSpec(
            kind="bounded_uniform",
            sigma=None,
            eta=None,
            bound=1,
            weight=None,
        ),
        error=ErrorPredicateSpec(
            max_abs=1,
            max_l1=4,
            max_l2_squared=4,
            max_nonzero=4,
        ),
        family="MIX_DENSE_SMALL",
        tier="synthetic",
        cohort="synthetic",
        octave=None,
        runtime_bin="synthetic",
        analysis_path="analysis/toy-uniform.md",
        generator_version="synthetic-fixture-v1",
        calibration_status="unmeasured",
        calibration_model_id="",
        predicted_runtime_seconds=0.0,
        measured_runtime_seconds=None,
    )


def _template_with_iid_alphabet(
    template: GenerationTemplate,
    alphabet,
) -> GenerationTemplate:
    return replace(
        template,
        n=8,
        secret_distribution=replace(
            template.secret_distribution,
            alphabet=alphabet,
        ),
        secret=replace(
            template.secret,
            alphabet=(-1, 0, 1),
            max_nonzero=8,
        ),
    )


def test_sampling_uses_normalized_alphabet_not_original_indexing(
    toy_template,
) -> None:
    normalized_template = _template_with_iid_alphabet(
        toy_template,
        (-1, 0, 1),
    )
    adversarial_template = _template_with_iid_alphabet(
        toy_template,
        _IndexDivergentAlphabet(),
    )
    seed = bytes.fromhex("2a" * 32)

    expected = generate_synthetic_instance(
        template=normalized_template,
        private_seed=seed,
    )
    generated = generate_synthetic_instance(
        template=adversarial_template,
        private_seed=seed,
    )

    assert generated == expected


def test_sampling_isolated_from_post_normalization_mutation(
    toy_template,
) -> None:
    alphabet = _SelfMutatingAlphabet()
    normalized_template = _template_with_iid_alphabet(
        toy_template,
        (-1, 0, 1),
    )
    mutable_template = _template_with_iid_alphabet(
        toy_template,
        alphabet,
    )
    seed = bytes.fromhex("2b" * 32)

    expected = generate_synthetic_instance(
        template=normalized_template,
        private_seed=seed,
    )
    generated = generate_synthetic_instance(
        template=mutable_template,
        private_seed=seed,
    )

    assert alphabet.mutated is True
    assert generated == expected


@pytest.fixture
def toy_sparse_template(toy_template) -> GenerationTemplate:
    return replace(
        toy_template,
        instance_id="toy-sparse",
        n=4,
        m=3,
        q=19,
        matrix=MatrixSpec(
            kind="sparse_small_alphabet",
            seed_hex="11" * 32,
            expansion_domain=MATRIX_EXPANSION_DOMAIN,
            alphabet=(-1, 1),
            row_weight=2,
        ),
        secret_distribution=SecretDistributionSpec(
            kind="exact_weight_alphabet",
            alphabet=(-1, 1),
            weight=2,
            eta=None,
        ),
        secret=SecretPredicateSpec(
            kind="alphabet",
            alphabet=(-1, 0, 1),
            min_nonzero=2,
            max_nonzero=2,
        ),
        error_distribution=ErrorDistributionSpec(
            kind="sparse_bounded",
            sigma=None,
            eta=None,
            bound=1,
            weight=1,
        ),
        error=ErrorPredicateSpec(
            max_abs=1,
            max_l1=1,
            max_l2_squared=1,
            max_nonzero=1,
        ),
        family="MIX_SMALL_SPARSE",
        analysis_path="analysis/toy-sparse.md",
    )


def test_public_instance_omits_private_seed_and_witness(toy_template) -> None:
    generated = generate_synthetic_instance(
        template=toy_template,
        private_seed=bytes.fromhex("11" * 32),
    )

    public = generated.public_json()

    assert "private_seed" not in public
    assert "private_secret" not in public
    assert "planted_secret" not in public
    assert "private_error" not in public
    assert "planted_error" not in public
    assert public["secret"]
    assert public["error"]
    assert generated.instance.b


def test_uniform_mod_q_secret_is_canonical_and_publicly_valid(
    toy_template,
) -> None:
    template = replace(
        toy_template,
        secret_distribution=SecretDistributionSpec(
            kind="uniform_mod_q",
            alphabet=(),
            weight=None,
            eta=None,
        ),
        secret=SecretPredicateSpec(
            kind="mod_q",
            alphabet=(),
            min_nonzero=0,
            max_nonzero=toy_template.n,
        ),
    )

    generated = generate_synthetic_instance(
        template=template,
        private_seed=bytes.fromhex("12" * 32),
    )

    assert all(0 <= value < template.q for value in generated.private_secret)
    assert validate_secret(generated.instance, generated.private_secret).ok


def test_exact_weight_secret_has_distinct_exact_support(toy_template) -> None:
    template = replace(
        toy_template,
        secret_distribution=SecretDistributionSpec(
            kind="exact_weight_alphabet",
            alphabet=(-1, 1),
            weight=2,
            eta=None,
        ),
        secret=SecretPredicateSpec(
            kind="alphabet",
            alphabet=(-1, 0, 1),
            min_nonzero=2,
            max_nonzero=2,
        ),
    )

    generated = generate_synthetic_instance(
        template=template,
        private_seed=bytes.fromhex("13" * 32),
    )

    assert sum(value != 0 for value in generated.private_secret) == 2
    assert set(generated.private_secret) <= {-1, 0, 1}
    assert validate_secret(generated.instance, generated.private_secret).ok


def test_balanced_exact_weight_signed_secret_is_balanced_and_round_trips(
    toy_template, tmp_path: Path
) -> None:
    template = replace(
        toy_template,
        n=4,
        secret_distribution=SecretDistributionSpec(
            kind="balanced_exact_weight_signed",
            alphabet=(-1, 1),
            weight=4,
            eta=None,
        ),
        secret=SecretPredicateSpec(
            kind="alphabet",
            alphabet=(-1, 0, 1),
            min_nonzero=4,
            max_nonzero=4,
        ),
    )

    generated = generate_synthetic_instance(
        template=template,
        private_seed=bytes.fromhex("14" * 32),
    )

    assert generated.private_secret.count(1) == 2
    assert generated.private_secret.count(-1) == 2
    assert validate_secret(generated.instance, generated.private_secret).ok
    public = generated.public_json()
    assert public["secret_distribution"] == {
        "kind": "balanced_exact_weight_signed",
        "alphabet": [-1, 1],
        "weight": 4,
        "eta": None,
    }
    assert "private_secret" not in public
    assert not {"private_secret", "planted_secret"} & set(_nested_keys(public))

    catalog_path = tmp_path / "balanced.json"
    catalog_path.write_text(
        json.dumps({"schema_version": 1, "instances": [public]}),
        encoding="utf-8",
    )
    round_tripped = Catalog.load(catalog_path).get(template.instance_id)
    assert round_tripped.secret_distribution == generated.instance.secret_distribution
    assert round_tripped.secret == generated.instance.secret


def test_centered_binomial_secret_uses_declared_eta(toy_template) -> None:
    template = replace(
        toy_template,
        secret_distribution=SecretDistributionSpec(
            kind="centered_binomial",
            alphabet=(-2, -1, 0, 1, 2),
            weight=None,
            eta=2,
        ),
        secret=SecretPredicateSpec(
            kind="alphabet",
            alphabet=(-2, -1, 0, 1, 2),
            min_nonzero=0,
            max_nonzero=toy_template.n,
        ),
    )

    generated = generate_synthetic_instance(
        template=template,
        private_seed=bytes.fromhex("14" * 32),
    )

    assert all(-2 <= value <= 2 for value in generated.private_secret)
    assert validate_secret(generated.instance, generated.private_secret).ok


def test_sparse_bounded_error_has_exact_nonzero_support(toy_template) -> None:
    template = replace(
        toy_template,
        error_distribution=ErrorDistributionSpec(
            kind="sparse_bounded",
            sigma=None,
            eta=None,
            bound=2,
            weight=2,
        ),
        error=ErrorPredicateSpec(
            max_abs=2,
            max_l1=4,
            max_l2_squared=8,
            max_nonzero=2,
        ),
    )

    generated = generate_synthetic_instance(
        template=template,
        private_seed=bytes.fromhex("15" * 32),
    )

    assert sum(value != 0 for value in generated.private_error) == 2
    assert all(
        value == 0 or 1 <= abs(value) <= 2
        for value in generated.private_error
    )
    assert validate_secret(generated.instance, generated.private_secret).ok


def test_centered_binomial_error_uses_declared_eta(toy_template) -> None:
    template = replace(
        toy_template,
        error_distribution=ErrorDistributionSpec(
            kind="centered_binomial",
            sigma=None,
            eta=2,
            bound=2,
            weight=None,
        ),
        error=ErrorPredicateSpec(
            max_abs=2,
            max_l1=2 * toy_template.m,
            max_l2_squared=4 * toy_template.m,
            max_nonzero=toy_template.m,
        ),
    )

    generated = generate_synthetic_instance(
        template=template,
        private_seed=bytes.fromhex("16" * 32),
    )

    assert all(-2 <= value <= 2 for value in generated.private_error)
    assert validate_secret(generated.instance, generated.private_secret).ok


def test_truncated_discrete_gaussian_error_uses_finite_support(
    toy_template,
) -> None:
    template = replace(
        toy_template,
        error_distribution=ErrorDistributionSpec(
            kind="truncated_discrete_gaussian",
            sigma=1.25,
            eta=None,
            bound=3,
            weight=None,
        ),
        error=ErrorPredicateSpec(
            max_abs=3,
            max_l1=3 * toy_template.m,
            max_l2_squared=9 * toy_template.m,
            max_nonzero=toy_template.m,
        ),
    )

    generated = generate_synthetic_instance(
        template=template,
        private_seed=bytes.fromhex("17" * 32),
    )

    assert all(-3 <= value <= 3 for value in generated.private_error)
    assert validate_secret(generated.instance, generated.private_secret).ok


def test_synthetic_and_production_entropy_domains_are_separate(
    toy_template,
) -> None:
    seed = bytes.fromhex("18" * 32)

    synthetic = _generate(toy_template, seed, "synthetic")
    production = _generate(toy_template, seed, "production")

    assert synthetic.private_secret != production.private_secret
    assert synthetic.private_error != production.private_error
    assert synthetic.instance.b != production.instance.b


def test_required_production_entropy_domains_are_pinned() -> None:
    assert generator_module._PRODUCTION_SECRET_DOMAIN == (
        b"FCS-STRUCTURED-LWE-PRODUCTION-SECRET-v1"
    )
    assert generator_module._PRODUCTION_ERROR_DOMAIN == (
        b"FCS-STRUCTURED-LWE-PRODUCTION-ERROR-v1"
    )


def test_production_generation_draws_entropy_once_without_synthetic_delegation(
    toy_template, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed = bytes.fromhex("19" * 32)
    requested_sizes: list[int] = []

    def draw_entropy(count: int) -> bytes:
        requested_sizes.append(count)
        return seed

    def reject_synthetic_delegation(**_kwargs) -> None:
        raise AssertionError("production delegated to the synthetic entry point")

    monkeypatch.setattr(generator_module.secrets, "token_bytes", draw_entropy)
    monkeypatch.setattr(
        generator_module,
        "generate_synthetic_instance",
        reject_synthetic_delegation,
    )

    generated = generate_production_instance(template=toy_template)
    expected = _generate(toy_template, seed, "production")

    assert requested_sizes == [32]
    assert generated == expected
    assert validate_secret(generated.instance, generated.private_secret).ok


@pytest.mark.parametrize(
    "invalid_template",
    (
        lambda template: replace(template, n=0),
        lambda template: replace(template, instance_id=""),
        lambda template: replace(
            template,
            matrix=replace(template.matrix, expansion_domain="wrong-domain"),
        ),
    ),
)
def test_generation_rejects_schema_incoherent_templates(
    toy_template, invalid_template
) -> None:
    with pytest.raises(ValueError):
        generate_synthetic_instance(
            template=invalid_template(toy_template),
            private_seed=bytes.fromhex("20" * 32),
        )


def test_synthetic_generation_is_deterministic_and_seed_sensitive(
    toy_template,
) -> None:
    seed = bytes.fromhex("21" * 32)

    first = generate_synthetic_instance(template=toy_template, private_seed=seed)
    repeated = generate_synthetic_instance(
        template=toy_template,
        private_seed=seed,
    )
    changed = generate_synthetic_instance(
        template=toy_template,
        private_seed=bytes.fromhex("22" * 32),
    )

    assert first == repeated
    assert first.instance.b != changed.instance.b
    assert first.public_sha256 != changed.public_sha256


def test_public_digest_hash_and_attestation_bind_generated_instance(
    toy_template,
) -> None:
    generated = generate_synthetic_instance(
        template=toy_template,
        private_seed=bytes.fromhex("23" * 32),
    )
    public = generated.public_json()
    attestation = generated.private_attestation

    assert generated.instance.instance_digest == compute_instance_digest(public)
    assert generated.public_sha256 == hashlib.sha256(
        canonical_record_bytes(public)
    ).hexdigest()
    assert attestation.instance_id == generated.instance.instance_id
    assert attestation.instance_digest == generated.instance.instance_digest
    assert attestation.distribution_checks_passed is True
    assert attestation.planted_witness_valid is True
    assert attestation.secret_nonzero == sum(
        value != 0 for value in generated.private_secret
    )
    assert attestation.error_nonzero == sum(
        value != 0 for value in generated.private_error
    )
    assert attestation.error_max_abs == max(
        abs(value) for value in generated.private_error
    )
    assert residual(generated.instance, generated.private_secret) == (
        generated.private_error
    )


def test_private_material_is_redacted_and_has_no_serialization_surface(
    toy_template,
) -> None:
    generated = generate_synthetic_instance(
        template=toy_template,
        private_seed=bytes.fromhex("24" * 32),
    )

    generated_repr = repr(generated)
    attestation_repr = repr(generated.private_attestation)
    public = generated.public_json()
    public_field_names = set(public)

    assert "private_secret" not in generated_repr
    assert "private_error" not in generated_repr
    assert "private_attestation" not in generated_repr
    assert "secret_nonzero" not in attestation_repr
    assert "error_nonzero" not in attestation_repr
    assert "error_max_abs" not in attestation_repr
    assert not hasattr(generated, "__dict__")
    assert not hasattr(generated.private_attestation, "__dict__")
    for object_type in (GeneratedInstance, GenerationAttestation):
        assert not hasattr(object_type, "serialize")
        assert not hasattr(object_type, "dump")
        assert not hasattr(object_type, "to_json")
    forbidden_public_keys = {
        "private_seed",
        "private_secret",
        "planted_secret",
        "private_error",
        "planted_error",
        "private_attestation",
        "answer_hash",
        "secret_hash",
        "error_hash",
    }
    assert public_field_names.isdisjoint(forbidden_public_keys)
    assert {
        field.name for field in fields(GeneratedInstance)
    }.isdisjoint({"private_seed", "answer_hash", "secret_hash", "error_hash"})

    with pytest.raises(FrozenInstanceError):
        generated.public_sha256 = "0" * 64


def test_generation_entry_points_expose_no_production_seed_parameter() -> None:
    assert tuple(inspect.signature(generate_production_instance).parameters) == (
        "template",
    )
    assert tuple(inspect.signature(generate_synthetic_instance).parameters) == (
        "template",
        "private_seed",
    )


def test_gaussian_table_is_finite_symmetric_and_deterministic() -> None:
    table = _discrete_gaussian_table(1.25, 3)

    assert table == _GAUSSIAN_TABLE_1_25_BOUND_3
    assert table == _discrete_gaussian_table(1.25, 3)
    assert tuple(value for value, _ in table) == tuple(range(-3, 4))
    assert tuple(weight for _, weight in table) == tuple(
        weight for _, weight in reversed(table)
    )
    assert all(type(weight) is int and weight > 0 for _, weight in table)
    assert table[3][1] == max(weight for _, weight in table)


def test_gaussian_table_ignores_ambient_decimal_context() -> None:
    with decimal.localcontext() as ambient:
        ambient.prec = 6
        ambient.rounding = decimal.ROUND_UP
        ambient.Emax = 6
        ambient.Emin = -6
        ambient.traps[decimal.Inexact] = True
        ambient.traps[decimal.Rounded] = True
        ambient.traps[decimal.Subnormal] = True
        ambient.traps[decimal.Underflow] = True
        ambient.traps[decimal.Overflow] = True

        table = _discrete_gaussian_table(1.25, 3)

    assert table == _GAUSSIAN_TABLE_1_25_BOUND_3


def test_huge_gaussian_bound_rejected_before_table_allocation(
    toy_template,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template = replace(
        toy_template,
        n=1,
        m=1,
        q=2_000_000_003,
        secret=replace(toy_template.secret, max_nonzero=1),
        error_distribution=ErrorDistributionSpec(
            kind="truncated_discrete_gaussian",
            sigma=1.25,
            eta=None,
            bound=1_000_000_000,
            weight=None,
        ),
        error=ErrorPredicateSpec(
            max_abs=1_000_000_000,
            max_l1=None,
            max_l2_squared=None,
            max_nonzero=None,
        ),
    )
    table_reached = False

    def reject_table_allocation(*_args):
        nonlocal table_reached
        table_reached = True
        raise AssertionError("Gaussian table allocation was reached")

    monkeypatch.setattr(
        generator_module,
        "_discrete_gaussian_table",
        reject_table_allocation,
    )

    with pytest.raises(ValueError, match="Gaussian bound exceeds"):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("31" * 32),
        )

    assert table_reached is False


def test_huge_secret_eta_rejected_before_alphabet_materialization(
    toy_template,
) -> None:
    alphabet = _IterationBombAlphabet()
    template = replace(
        toy_template,
        n=1,
        m=1,
        q=2_000_000_003,
        secret_distribution=SecretDistributionSpec(
            kind="centered_binomial",
            alphabet=alphabet,
            weight=None,
            eta=1_000_000_000,
        ),
        secret=SecretPredicateSpec(
            kind="alphabet",
            alphabet=alphabet,
            min_nonzero=0,
            max_nonzero=1,
        ),
        error=replace(
            toy_template.error,
            max_l1=1,
            max_l2_squared=1,
            max_nonzero=1,
        ),
    )

    with pytest.raises(ValueError, match="secret eta exceeds"):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("32" * 32),
        )

    assert alphabet.iterated is False


@pytest.mark.parametrize(
    "location",
    ("matrix", "secret_distribution", "secret_predicate"),
)
def test_huge_alphabet_rejected_before_materialization(
    toy_template,
    location: str,
) -> None:
    alphabet = _IterationBombAlphabet()
    if location == "matrix":
        template = replace(
            toy_template,
            matrix=replace(
                toy_template.matrix,
                kind="small_alphabet",
                alphabet=alphabet,
            ),
        )
    elif location == "secret_distribution":
        template = replace(
            toy_template,
            secret_distribution=replace(
                toy_template.secret_distribution,
                alphabet=alphabet,
            ),
        )
    else:
        template = replace(
            toy_template,
            secret=replace(toy_template.secret, alphabet=alphabet),
        )

    with pytest.raises(ValueError, match="alphabet exceeds the generation limit"):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("39" * 32),
        )

    assert alphabet.iterated is False


@pytest.mark.parametrize(
    "location",
    ("matrix", "secret_distribution", "secret_predicate"),
)
def test_lying_alphabet_length_is_bounded_during_snapshot(
    toy_template,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    alphabet = _LengthLiarAlphabet()
    if location == "matrix":
        template = replace(
            toy_template,
            matrix=replace(
                toy_template.matrix,
                kind="small_alphabet",
                alphabet=alphabet,
            ),
        )
    elif location == "secret_distribution":
        template = replace(
            toy_template,
            secret_distribution=replace(
                toy_template.secret_distribution,
                alphabet=alphabet,
            ),
        )
    else:
        template = replace(
            toy_template,
            secret=replace(toy_template.secret, alphabet=alphabet),
        )
    template_instance_reached = False

    def reject_template_instance(*_args):
        nonlocal template_instance_reached
        template_instance_reached = True
        raise AssertionError("template instance allocation was reached")

    monkeypatch.setattr(
        generator_module,
        "_template_instance",
        reject_template_instance,
    )

    with pytest.raises(ValueError, match="alphabet exceeds the generation limit"):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("3c" * 32),
        )

    assert alphabet.yielded == (
        generator_module.MAX_GENERATION_ALPHABET_SIZE + 1
    )
    assert template_instance_reached is False


def test_huge_error_eta_rejected_before_bit_allocation(
    toy_template,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template = replace(
        toy_template,
        n=1,
        m=1,
        q=2_000_000_003,
        secret=replace(toy_template.secret, max_nonzero=1),
        error_distribution=ErrorDistributionSpec(
            kind="centered_binomial",
            sigma=None,
            eta=1_000_000_000,
            bound=1_000_000_000,
            weight=None,
        ),
        error=ErrorPredicateSpec(
            max_abs=1_000_000_000,
            max_l1=None,
            max_l2_squared=None,
            max_nonzero=None,
        ),
    )
    hamming_weight_reached = False

    def reject_bit_allocation(*_args):
        nonlocal hamming_weight_reached
        hamming_weight_reached = True
        raise AssertionError("centered-binomial bit allocation was reached")

    monkeypatch.setattr(
        generator_module,
        "_hamming_weight",
        reject_bit_allocation,
    )

    with pytest.raises(ValueError, match="error eta exceeds"):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("33" * 32),
        )

    assert hamming_weight_reached is False


def test_huge_m_rejected_before_zero_vector_allocation(
    toy_template,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template = replace(toy_template, m=1_000_000_000)
    template_instance_reached = False

    def reject_template_instance(*_args):
        nonlocal template_instance_reached
        template_instance_reached = True
        raise AssertionError("template instance allocation was reached")

    monkeypatch.setattr(
        generator_module,
        "_template_instance",
        reject_template_instance,
    )

    with pytest.raises(ValueError, match="m exceeds"):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("38" * 32),
        )

    assert template_instance_reached is False


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"n": True}, "n must be an integer"),
        ({"m": 1.0}, "m must be an integer"),
        ({"q": 17.0}, "q must be an integer"),
        ({"n": 0}, "n must be at least"),
        ({"n": generator_module.MAX_N + 1}, "n exceeds"),
        ({"m": 0}, "m must be at least"),
        ({"m": generator_module.MAX_M + 1}, "m exceeds"),
        ({"q": 2}, "q must be at least"),
        ({"q": generator_module.MAX_Q + 1}, "q exceeds"),
        (
            {
                "n": generator_module.MAX_N,
                "m": generator_module.MAX_MATRIX_ENTRIES
                // generator_module.MAX_N
                + 1,
            },
            "matrix dimensions exceed",
        ),
    ),
)
def test_invalid_dimensions_rejected_before_template_instance(
    toy_template,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, object],
    message: str,
) -> None:
    template = replace(toy_template, **changes)
    template_instance_reached = False

    def reject_template_instance(*_args):
        nonlocal template_instance_reached
        template_instance_reached = True
        raise AssertionError("template instance allocation was reached")

    monkeypatch.setattr(
        generator_module,
        "_template_instance",
        reject_template_instance,
    )

    with pytest.raises(ValueError, match=message):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("3a" * 32),
        )

    assert template_instance_reached is False


def test_generation_work_envelope_constants_are_pinned() -> None:
    assert generator_module.MAX_CENTERED_BINOMIAL_ETA == 64
    assert generator_module.MAX_GAUSSIAN_BOUND == 4096
    assert generator_module.MAX_GENERATION_ALPHABET_SIZE == 4096


def test_generation_alphabet_exact_limit_is_accepted(toy_template) -> None:
    half = generator_module.MAX_GENERATION_ALPHABET_SIZE // 2
    alphabet = tuple(range(-half, half))
    template = replace(
        toy_template,
        n=1,
        m=1,
        q=10_001,
        secret_distribution=replace(
            toy_template.secret_distribution,
            alphabet=alphabet,
        ),
        secret=replace(
            toy_template.secret,
            alphabet=alphabet,
            max_nonzero=1,
        ),
    )

    generated = generate_synthetic_instance(
        template=template,
        private_seed=bytes.fromhex("3b" * 32),
    )

    assert validate_secret(generated.instance, generated.private_secret).ok


@pytest.mark.parametrize(("eta", "accepted"), ((64, True), (65, False)))
def test_secret_centered_binomial_eta_exact_and_over_cap(
    toy_template,
    eta: int,
    accepted: bool,
) -> None:
    alphabet = tuple(range(-eta, eta + 1))
    template = replace(
        toy_template,
        n=1,
        m=1,
        q=257,
        secret_distribution=SecretDistributionSpec(
            kind="centered_binomial",
            alphabet=alphabet,
            weight=None,
            eta=eta,
        ),
        secret=SecretPredicateSpec(
            kind="alphabet",
            alphabet=alphabet,
            min_nonzero=0,
            max_nonzero=1,
        ),
        error=replace(
            toy_template.error,
            max_l1=1,
            max_l2_squared=1,
            max_nonzero=1,
        ),
    )

    if accepted:
        generated = generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("34" * 32),
        )
        assert validate_secret(
            generated.instance,
            generated.private_secret,
        ).ok
    else:
        with pytest.raises(ValueError, match="secret eta exceeds"):
            generate_synthetic_instance(
                template=template,
                private_seed=bytes.fromhex("34" * 32),
            )


@pytest.mark.parametrize(("eta", "accepted"), ((64, True), (65, False)))
def test_error_centered_binomial_eta_exact_and_over_cap(
    toy_template,
    eta: int,
    accepted: bool,
) -> None:
    template = replace(
        toy_template,
        n=1,
        m=1,
        q=257,
        secret=replace(toy_template.secret, max_nonzero=1),
        error_distribution=ErrorDistributionSpec(
            kind="centered_binomial",
            sigma=None,
            eta=eta,
            bound=eta,
            weight=None,
        ),
        error=ErrorPredicateSpec(
            max_abs=eta,
            max_l1=eta,
            max_l2_squared=eta * eta,
            max_nonzero=1,
        ),
    )

    if accepted:
        generated = generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("35" * 32),
        )
        assert validate_secret(
            generated.instance,
            generated.private_secret,
        ).ok
    else:
        with pytest.raises(ValueError, match="error eta exceeds"):
            generate_synthetic_instance(
                template=template,
                private_seed=bytes.fromhex("35" * 32),
            )


@pytest.mark.parametrize(("bound", "accepted"), ((4096, True), (4097, False)))
def test_gaussian_bound_exact_and_over_cap(
    toy_template,
    bound: int,
    accepted: bool,
) -> None:
    template = replace(
        toy_template,
        n=1,
        m=1,
        q=10_001,
        secret=replace(toy_template.secret, max_nonzero=1),
        error_distribution=ErrorDistributionSpec(
            kind="truncated_discrete_gaussian",
            sigma=1.25,
            eta=None,
            bound=bound,
            weight=None,
        ),
        error=ErrorPredicateSpec(
            max_abs=bound,
            max_l1=bound,
            max_l2_squared=bound * bound,
            max_nonzero=1,
        ),
    )

    if accepted:
        generated = generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("36" * 32),
        )
        assert validate_secret(
            generated.instance,
            generated.private_secret,
        ).ok
    else:
        with pytest.raises(ValueError, match="Gaussian bound exceeds"):
            generate_synthetic_instance(
                template=template,
                private_seed=bytes.fromhex("36" * 32),
            )


@pytest.mark.parametrize("q", (130, 131))
@pytest.mark.parametrize("kind", ("bounded_uniform", "sparse_bounded"))
def test_q_derived_canonical_error_bound_exact_and_over(
    toy_template,
    kind: str,
    q: int,
) -> None:
    canonical_bound = (q - 1) // 2

    def template_for(bound: int) -> GenerationTemplate:
        weight = 1 if kind == "sparse_bounded" else None
        return replace(
            toy_template,
            n=1,
            m=1,
            q=q,
            secret=replace(toy_template.secret, max_nonzero=1),
            error_distribution=ErrorDistributionSpec(
                kind=kind,
                sigma=None,
                eta=None,
                bound=bound,
                weight=weight,
            ),
            error=ErrorPredicateSpec(
                max_abs=bound,
                max_l1=bound,
                max_l2_squared=bound * bound,
                max_nonzero=1,
            ),
        )

    generated = generate_synthetic_instance(
        template=template_for(canonical_bound),
        private_seed=bytes.fromhex("37" * 32),
    )
    assert validate_secret(generated.instance, generated.private_secret).ok

    with pytest.raises(
        ValueError,
        match="error support exceeds the canonical centered range",
    ):
        generate_synthetic_instance(
            template=template_for(canonical_bound + 1),
            private_seed=bytes.fromhex("37" * 32),
        )


def test_generation_rejects_sample_outside_public_predicates(
    toy_template,
) -> None:
    restrictive = replace(
        toy_template,
        secret=replace(toy_template.secret, min_nonzero=2),
    )

    with pytest.raises(ValueError, match="public predicates"):
        generate_synthetic_instance(
            template=restrictive,
            private_seed=bytes.fromhex("11" * 32),
        )


def _raw_error_template(
    template: GenerationTemplate,
    *,
    max_l1: int | None,
    max_l2_squared: int | None,
    max_nonzero: int | None,
) -> GenerationTemplate:
    return replace(
        template,
        n=1,
        m=1,
        q=7,
        secret=replace(
            template.secret,
            min_nonzero=0,
            max_nonzero=1,
        ),
        error_distribution=ErrorDistributionSpec(
            kind="bounded_uniform",
            sigma=None,
            eta=None,
            bound=3,
            weight=None,
        ),
        error=ErrorPredicateSpec(
            max_abs=3,
            max_l1=max_l1,
            max_l2_squared=max_l2_squared,
            max_nonzero=max_nonzero,
        ),
    )


def test_generation_rejects_raw_error_predicate_violation(
    toy_template,
) -> None:
    template = _raw_error_template(
        toy_template,
        max_l1=0,
        max_l2_squared=0,
        max_nonzero=0,
    )

    with pytest.raises(ValueError) as exc_info:
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("01" * 32),
        )

    assert str(exc_info.value) == (
        "generated error violates its public predicates"
    )
    assert "-3" not in str(exc_info.value)


def test_generation_checks_raw_error_l1_predicate(toy_template) -> None:
    template = _raw_error_template(
        toy_template,
        max_l1=0,
        max_l2_squared=None,
        max_nonzero=None,
    )

    with pytest.raises(
        ValueError,
        match="generated error violates its public predicates",
    ):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("01" * 32),
        )


def test_generation_checks_raw_error_l2_predicate(toy_template) -> None:
    template = _raw_error_template(
        toy_template,
        max_l1=None,
        max_l2_squared=0,
        max_nonzero=None,
    )

    with pytest.raises(
        ValueError,
        match="generated error violates its public predicates",
    ):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("01" * 32),
        )


def test_generation_checks_raw_error_nonzero_predicate(toy_template) -> None:
    template = _raw_error_template(
        toy_template,
        max_l1=None,
        max_l2_squared=None,
        max_nonzero=0,
    )

    with pytest.raises(
        ValueError,
        match="generated error violates its public predicates",
    ):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("01" * 32),
        )


def test_generation_rejects_noncanonical_error_support_before_sampling(
    toy_template,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    template = replace(
        _raw_error_template(
            toy_template,
            max_l1=None,
            max_l2_squared=None,
            max_nonzero=None,
        ),
        q=3,
    )
    sampling_reached = False

    def reject_sampling(*_args):
        nonlocal sampling_reached
        sampling_reached = True
        raise AssertionError("error sampling was reached")

    monkeypatch.setattr(generator_module, "_sample_error", reject_sampling)

    with pytest.raises(
        ValueError,
        match="error support exceeds the canonical centered range",
    ):
        generate_synthetic_instance(
            template=template,
            private_seed=bytes.fromhex("01" * 32),
        )

    assert sampling_reached is False


def test_public_json_returns_a_detached_public_record(toy_template) -> None:
    generated = generate_synthetic_instance(
        template=toy_template,
        private_seed=bytes.fromhex("27" * 32),
    )
    public = generated.public_json()

    public["b"][0] = -1
    public["matrix"]["alphabet"].append(99)

    assert generated.public_json()["b"][0] == generated.instance.b[0]
    assert generated.public_json()["matrix"]["alphabet"] == []


@pytest.mark.parametrize(
    ("invalid_seed", "error_type"),
    (
        (b"", ValueError),
        (b"x" * 31, ValueError),
        (b"x" * 33, ValueError),
        (bytearray(b"x" * 32), TypeError),
        (memoryview(b"x" * 32), TypeError),
        ("x" * 32, TypeError),
        (None, TypeError),
    ),
)
def test_synthetic_generation_requires_exactly_32_bytes(
    toy_template, invalid_seed, error_type
) -> None:
    with pytest.raises(error_type) as exc_info:
        generate_synthetic_instance(
            template=toy_template,
            private_seed=invalid_seed,
        )
    assert "private_seed" in str(exc_info.value)
    assert "xxxx" not in str(exc_info.value)


@pytest.mark.parametrize("invalid_mode", ("", "staging", None, 1))
def test_private_generation_seam_restricts_mode(
    toy_template, invalid_mode
) -> None:
    with pytest.raises(ValueError, match="synthetic or production"):
        _generate(toy_template, bytes.fromhex("25" * 32), invalid_mode)


def _template_for_distribution_pair(
    template: GenerationTemplate,
    secret_kind: str,
    error_kind: str,
) -> GenerationTemplate:
    if secret_kind == "uniform_mod_q":
        secret_distribution = SecretDistributionSpec(
            kind="uniform_mod_q", alphabet=(), weight=None, eta=None
        )
        secret = SecretPredicateSpec(
            kind="mod_q",
            alphabet=(),
            min_nonzero=0,
            max_nonzero=template.n,
        )
    elif secret_kind == "iid_alphabet":
        secret_distribution = SecretDistributionSpec(
            kind="iid_alphabet",
            alphabet=(-1, 0, 1),
            weight=None,
            eta=None,
        )
        secret = SecretPredicateSpec(
            kind="alphabet",
            alphabet=(-1, 0, 1),
            min_nonzero=0,
            max_nonzero=template.n,
        )
    elif secret_kind == "exact_weight_alphabet":
        secret_distribution = SecretDistributionSpec(
            kind="exact_weight_alphabet",
            alphabet=(-1, 1),
            weight=2,
            eta=None,
        )
        secret = SecretPredicateSpec(
            kind="alphabet",
            alphabet=(-1, 0, 1),
            min_nonzero=2,
            max_nonzero=2,
        )
    else:
        secret_distribution = SecretDistributionSpec(
            kind="centered_binomial",
            alphabet=(-2, -1, 0, 1, 2),
            weight=None,
            eta=2,
        )
        secret = SecretPredicateSpec(
            kind="alphabet",
            alphabet=(-2, -1, 0, 1, 2),
            min_nonzero=0,
            max_nonzero=template.n,
        )

    if error_kind == "truncated_discrete_gaussian":
        error_distribution = ErrorDistributionSpec(
            kind="truncated_discrete_gaussian",
            sigma=1.25,
            eta=None,
            bound=3,
            weight=None,
        )
        error_bound = 3
        error_nonzero = template.m
    elif error_kind == "centered_binomial":
        error_distribution = ErrorDistributionSpec(
            kind="centered_binomial",
            sigma=None,
            eta=2,
            bound=2,
            weight=None,
        )
        error_bound = 2
        error_nonzero = template.m
    elif error_kind == "bounded_uniform":
        error_distribution = ErrorDistributionSpec(
            kind="bounded_uniform",
            sigma=None,
            eta=None,
            bound=2,
            weight=None,
        )
        error_bound = 2
        error_nonzero = template.m
    else:
        error_distribution = ErrorDistributionSpec(
            kind="sparse_bounded",
            sigma=None,
            eta=None,
            bound=3,
            weight=2,
        )
        error_bound = 3
        error_nonzero = 2

    error = ErrorPredicateSpec(
        max_abs=error_bound,
        max_l1=error_bound * error_nonzero,
        max_l2_squared=error_bound * error_bound * error_nonzero,
        max_nonzero=error_nonzero,
    )
    return replace(
        template,
        secret_distribution=secret_distribution,
        secret=secret,
        error_distribution=error_distribution,
        error=error,
    )


@pytest.mark.parametrize(
    "secret_kind",
    (
        "uniform_mod_q",
        "iid_alphabet",
        "exact_weight_alphabet",
        "centered_binomial",
    ),
)
@pytest.mark.parametrize(
    "error_kind",
    (
        "truncated_discrete_gaussian",
        "centered_binomial",
        "bounded_uniform",
        "sparse_bounded",
    ),
)
def test_every_secret_error_distribution_pair_generates_a_valid_witness(
    toy_template, secret_kind, error_kind
) -> None:
    template = _template_for_distribution_pair(
        toy_template,
        secret_kind,
        error_kind,
    )

    generated = generate_synthetic_instance(
        template=template,
        private_seed=bytes.fromhex("26" * 32),
    )

    assert generated.private_attestation.distribution_checks_passed is True
    assert generated.private_attestation.planted_witness_valid is True
    assert validate_secret(generated.instance, generated.private_secret).ok
    if secret_kind == "exact_weight_alphabet":
        assert sum(value != 0 for value in generated.private_secret) == 2
    if error_kind == "sparse_bounded":
        assert sum(value != 0 for value in generated.private_error) == 2


def _nested_keys(value: object):
    if isinstance(value, dict):
        for key, nested in value.items():
            yield key
            yield from _nested_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _nested_keys(nested)


def _nested_scalar_values(value: object):
    if isinstance(value, dict):
        for nested in value.values():
            yield from _nested_scalar_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _nested_scalar_values(nested)
    else:
        yield value


def test_checked_in_synthetic_catalog_reproduces_without_private_material(
    task_dir: Path,
    toy_template: GenerationTemplate,
    toy_sparse_template: GenerationTemplate,
) -> None:
    generated = (
        generate_synthetic_instance(
            template=toy_template,
            private_seed=_FIXTURE_PRIVATE_SEEDS[0],
        ),
        generate_synthetic_instance(
            template=toy_sparse_template,
            private_seed=_FIXTURE_PRIVATE_SEEDS[1],
        ),
    )
    path = task_dir / "catalog.synthetic.json"

    catalog = Catalog.load(path)
    document = json.loads(path.read_text(encoding="utf-8"))

    assert document == {
        "schema_version": 1,
        "instances": [item.public_json() for item in generated],
    }
    assert catalog.instances == tuple(item.instance for item in generated)
    assert tuple(item.instance_id for item in catalog.instances) == (
        "toy-uniform",
        "toy-sparse",
    )
    assert all(item.cohort is None for item in catalog.instances)
    assert all(item.tier is None for item in catalog.instances)
    assert all(item.runtime_bin is None for item in catalog.instances)
    assert all(
        validate_secret(item.instance, item.private_secret).ok
        for item in generated
    )
    forbidden_keys = {
        "private_seed",
        "private_secret",
        "planted_secret",
        "private_error",
        "planted_error",
        "private_attestation",
        "answer_hash",
        "secret_hash",
        "error_hash",
        "family",
        "tier",
        "cohort",
        "octave",
        "runtime_bin",
        "analysis_path",
        "calibration_status",
        "calibration_model_id",
        "predicted_runtime_seconds",
        "measured_runtime_seconds",
    }
    assert set(_nested_keys(document)).isdisjoint(forbidden_keys)
    assert set(_nested_scalar_values(document)).isdisjoint(
        {seed.hex() for seed in _FIXTURE_PRIVATE_SEEDS}
    )
