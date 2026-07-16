from __future__ import annotations

import hashlib
import math
import secrets
from bisect import bisect_right
from dataclasses import dataclass, field, replace
from decimal import (
    Clamped,
    Context,
    Decimal,
    DivisionByZero,
    FloatOperation,
    Inexact,
    InvalidOperation,
    Overflow,
    ROUND_HALF_EVEN,
    Rounded,
    Subnormal,
    Underflow,
    localcontext,
)
from itertools import islice

from .matrix import matvec_mod
from .schema import (
    MAX_M,
    MAX_MATRIX_ENTRIES,
    MAX_N,
    MAX_Q,
    ErrorDistributionSpec,
    ErrorPredicateSpec,
    InstanceSpec,
    MatrixSpec,
    SecretDistributionSpec,
    SecretPredicateSpec,
    _parse_instance,
    canonical_record_bytes,
    compute_instance_digest,
)
from .shake import ShakeStream
from .verification import residual, validate_secret


_SYNTHETIC_SECRET_DOMAIN = b"FCS-STRUCTURED-LWE-SYNTHETIC-SECRET-v1"
_SYNTHETIC_ERROR_DOMAIN = b"FCS-STRUCTURED-LWE-SYNTHETIC-ERROR-v1"
_PRODUCTION_SECRET_DOMAIN = b"FCS-STRUCTURED-LWE-PRODUCTION-SECRET-v1"
_PRODUCTION_ERROR_DOMAIN = b"FCS-STRUCTURED-LWE-PRODUCTION-ERROR-v1"

# These public operational limits cap deterministic per-coordinate generation
# work.  Bounded-uniform and sparse-bounded errors remain O(1) in their bound
# and may use the full symmetric canonical range derived from q below.
MAX_CENTERED_BINOMIAL_ETA = 64
MAX_GAUSSIAN_BOUND = 4096
MAX_GENERATION_ALPHABET_SIZE = 4096
_GAUSSIAN_WEIGHT_SCALE = 1 << 48
_GAUSSIAN_DECIMAL_PRECISION = 80
_GAUSSIAN_DECIMAL_EMIN = -999_999
_GAUSSIAN_DECIMAL_EMAX = 999_999
_DECIMAL_SIGNALS = (
    Clamped,
    DivisionByZero,
    FloatOperation,
    Inexact,
    InvalidOperation,
    Overflow,
    Rounded,
    Subnormal,
    Underflow,
)


@dataclass(frozen=True, slots=True)
class GenerationTemplate:
    instance_id: str
    n: int
    m: int
    q: int
    matrix: MatrixSpec
    secret_distribution: SecretDistributionSpec
    secret: SecretPredicateSpec
    error_distribution: ErrorDistributionSpec
    error: ErrorPredicateSpec
    family: str
    tier: str
    cohort: str
    octave: int | None
    runtime_bin: str
    analysis_path: str
    generator_version: str
    calibration_status: str
    calibration_model_id: str
    predicted_runtime_seconds: float
    measured_runtime_seconds: float | None


@dataclass(frozen=True, slots=True)
class GenerationAttestation:
    instance_id: str
    instance_digest: str
    distribution_checks_passed: bool
    planted_witness_valid: bool
    secret_nonzero: int = field(repr=False)
    error_nonzero: int = field(repr=False)
    error_max_abs: int = field(repr=False)


@dataclass(frozen=True, slots=True)
class GeneratedInstance:
    instance: InstanceSpec
    private_secret: tuple[int, ...] = field(repr=False)
    private_error: tuple[int, ...] = field(repr=False)
    private_attestation: GenerationAttestation = field(repr=False)
    public_sha256: str

    def public_json(self) -> dict[str, object]:
        return _instance_to_public_record(self.instance)


def generate_synthetic_instance(
    *, template: GenerationTemplate, private_seed: bytes
) -> GeneratedInstance:
    return _generate(template, private_seed, "synthetic")


def generate_production_instance(
    *, template: GenerationTemplate
) -> GeneratedInstance:
    private_seed = secrets.token_bytes(32)
    return _generate(template, private_seed, "production")


def _generate(
    template: GenerationTemplate, private_seed: bytes, mode: str
) -> GeneratedInstance:
    if mode == "synthetic":
        secret_domain = _SYNTHETIC_SECRET_DOMAIN
        error_domain = _SYNTHETIC_ERROR_DOMAIN
    elif mode == "production":
        secret_domain = _PRODUCTION_SECRET_DOMAIN
        error_domain = _PRODUCTION_ERROR_DOMAIN
    else:
        raise ValueError("mode must be synthetic or production")
    if not isinstance(private_seed, bytes):
        raise TypeError("private_seed must be bytes")
    if len(private_seed) != 32:
        raise ValueError("private_seed must contain exactly 32 bytes")

    template_instance = _validated_template_instance(template)

    secret_stream = ShakeStream(
        domain=secret_domain,
        seed=private_seed,
    )
    error_stream = ShakeStream(
        domain=error_domain,
        seed=private_seed,
    )
    secret = _sample_secret(template_instance, secret_stream)
    error = _sample_error(template_instance, error_stream)
    if not _raw_error_satisfies_public_predicates(template_instance, error):
        raise ValueError("generated error violates its public predicates")

    product = matvec_mod(template_instance, secret)
    instance = replace(
        template_instance,
        b=tuple(
            (value + perturbation) % template_instance.q
            for value, perturbation in zip(product, error)
        ),
    )
    record = _instance_to_public_record(instance)
    digest = compute_instance_digest(record)
    record["instance_digest"] = digest
    instance = _parse_instance(record)

    distribution_checks_passed = _distribution_checks(
        template_instance,
        secret,
        error,
    )
    if not distribution_checks_passed:
        raise ValueError("generated values violate their declared distributions")
    try:
        public_residual = residual(instance, secret)
    except ValueError:
        public_residual = None
    if public_residual is None:
        raise ValueError("generated witness violates its public predicates")
    if public_residual != error:
        raise ValueError(
            "generated error differs from its centered public residual"
        )
    verdict = validate_secret(instance, secret)
    if not verdict.ok:
        raise ValueError("generated witness violates its public predicates")

    attestation = GenerationAttestation(
        instance_id=instance.instance_id,
        instance_digest=digest,
        distribution_checks_passed=True,
        planted_witness_valid=True,
        secret_nonzero=sum(value != 0 for value in secret),
        error_nonzero=sum(value != 0 for value in error),
        error_max_abs=max(abs(value) for value in error),
    )
    public_record = _instance_to_public_record(instance)
    public_sha256 = hashlib.sha256(canonical_record_bytes(public_record)).hexdigest()
    return GeneratedInstance(
        instance=instance,
        private_secret=secret,
        private_error=error,
        private_attestation=attestation,
        public_sha256=public_sha256,
    )


def _sample_secret(
    instance: InstanceSpec, stream: ShakeStream
) -> tuple[int, ...]:
    distribution = instance.secret_distribution
    if distribution.kind == "uniform_mod_q":
        return tuple(stream.randbelow(instance.q) for _ in range(instance.n))
    if distribution.kind == "iid_alphabet":
        if not distribution.alphabet:
            raise ValueError("iid_alphabet requires a nonempty alphabet")
        return tuple(
            distribution.alphabet[stream.randbelow(len(distribution.alphabet))]
            for _ in range(instance.n)
        )
    if distribution.kind == "exact_weight_alphabet":
        if distribution.weight is None or not distribution.alphabet:
            raise ValueError("exact_weight_alphabet requires weight and alphabet")
        support = _sample_support(instance.n, distribution.weight, stream)
        secret = [0] * instance.n
        for index in support:
            secret[index] = distribution.alphabet[
                stream.randbelow(len(distribution.alphabet))
            ]
        return tuple(secret)
    if distribution.kind == "balanced_exact_weight_signed":
        if (
            distribution.weight is None
            or distribution.weight % 2
            or distribution.alphabet != (-1, 1)
        ):
            raise ValueError(
                "balanced_exact_weight_signed requires alphabet (-1, 1) and even weight"
            )
        support = _sample_support(instance.n, distribution.weight, stream)
        positive_offsets = frozenset(
            _sample_support(
                distribution.weight,
                distribution.weight // 2,
                stream,
            )
        )
        secret = [0] * instance.n
        for offset, index in enumerate(support):
            secret[index] = 1 if offset in positive_offsets else -1
        return tuple(secret)
    if distribution.kind == "centered_binomial":
        if distribution.eta is None:
            raise ValueError("centered_binomial requires eta")
        return tuple(
            _hamming_weight(stream, distribution.eta)
            - _hamming_weight(stream, distribution.eta)
            for _ in range(instance.n)
        )
    raise ValueError(f"unsupported secret distribution: {distribution.kind}")


def _hamming_weight(stream: ShakeStream, bit_count: int) -> int:
    if bit_count < 1:
        raise ValueError("bit_count must be positive")
    encoded = bytearray(stream.read((bit_count + 7) // 8))
    remainder = bit_count % 8
    if remainder:
        encoded[-1] &= (1 << remainder) - 1
    return sum(value.bit_count() for value in encoded)


def _sample_support(
    length: int, weight: int, stream: ShakeStream
) -> tuple[int, ...]:
    if not 0 <= weight <= length:
        raise ValueError("support weight must be between zero and its dimension")
    indices = list(range(length))
    for start in range(weight):
        selected = start + stream.randbelow(length - start)
        indices[start], indices[selected] = indices[selected], indices[start]
    return tuple(sorted(indices[:weight]))


def _sample_error(
    instance: InstanceSpec, stream: ShakeStream
) -> tuple[int, ...]:
    distribution = instance.error_distribution
    if distribution.kind == "truncated_discrete_gaussian":
        if distribution.sigma is None:
            raise ValueError("truncated_discrete_gaussian requires sigma")
        table = _discrete_gaussian_table(distribution.sigma, distribution.bound)
        cumulative: list[int] = []
        total = 0
        for _, weight in table:
            total += weight
            cumulative.append(total)
        return tuple(
            table[bisect_right(cumulative, stream.randbelow(total))][0]
            for _ in range(instance.m)
        )
    if distribution.kind == "bounded_uniform":
        return tuple(
            stream.randbelow(2 * distribution.bound + 1) - distribution.bound
            for _ in range(instance.m)
        )
    if distribution.kind == "centered_binomial":
        if distribution.eta is None:
            raise ValueError("centered_binomial requires eta")
        return tuple(
            _hamming_weight(stream, distribution.eta)
            - _hamming_weight(stream, distribution.eta)
            for _ in range(instance.m)
        )
    if distribution.kind == "sparse_bounded":
        if distribution.weight is None or distribution.bound < 1:
            raise ValueError("sparse_bounded requires positive bound and weight")
        support = _sample_support(instance.m, distribution.weight, stream)
        error = [0] * instance.m
        for index in support:
            encoded = stream.randbelow(2 * distribution.bound)
            error[index] = (
                -(encoded + 1)
                if encoded < distribution.bound
                else encoded - distribution.bound + 1
            )
        return tuple(error)
    raise ValueError(f"unsupported error distribution: {distribution.kind}")


def _discrete_gaussian_table(
    sigma: float, bound: int
) -> tuple[tuple[int, int], ...]:
    """Build the deterministic finite integer-weight Gaussian table.

    The public decimal spelling of ``sigma`` is evaluated in a fresh context
    with 80 digits of precision, round-half-even, fixed exponent limits, and
    explicitly configured traps.  Each ``exp(-x^2/(2*sigma^2))`` value on
    ``[-bound, bound]`` is scaled by ``2^48``, rounded half-even, and clamped
    to a weight of one.
    """
    if type(sigma) not in {int, float} or not math.isfinite(sigma) or sigma <= 0:
        raise ValueError("Gaussian sigma must be finite and positive")
    if type(bound) is not int or bound < 0:
        raise ValueError("Gaussian bound must be a nonnegative integer")

    with localcontext(_new_gaussian_decimal_context()):
        decimal_sigma = Decimal(str(sigma))
        denominator = Decimal(2) * decimal_sigma * decimal_sigma
        scale = Decimal(_GAUSSIAN_WEIGHT_SCALE)
        return tuple(
            (
                value,
                max(
                    1,
                    int(
                        (
                            (Decimal(-(value * value)) / denominator).exp()
                            * scale
                        ).to_integral_value(rounding=ROUND_HALF_EVEN)
                    ),
                ),
            )
            for value in range(-bound, bound + 1)
        )


def _new_gaussian_decimal_context() -> Context:
    trapped = {DivisionByZero, FloatOperation, InvalidOperation, Overflow}
    return Context(
        prec=_GAUSSIAN_DECIMAL_PRECISION,
        rounding=ROUND_HALF_EVEN,
        Emin=_GAUSSIAN_DECIMAL_EMIN,
        Emax=_GAUSSIAN_DECIMAL_EMAX,
        capitals=1,
        clamp=0,
        flags={signal: False for signal in _DECIMAL_SIGNALS},
        traps={signal: signal in trapped for signal in _DECIMAL_SIGNALS},
    )


def _distribution_checks(
    instance: InstanceSpec,
    secret: tuple[int, ...],
    error: tuple[int, ...],
) -> bool:
    if instance.secret_distribution.kind == "uniform_mod_q":
        secret_valid = all(0 <= value < instance.q for value in secret)
    elif instance.secret_distribution.kind in {
        "exact_weight_alphabet",
        "balanced_exact_weight_signed",
    }:
        secret_valid = (
            all(
                value == 0 or value in instance.secret_distribution.alphabet
                for value in secret
            )
            and sum(value != 0 for value in secret)
            == instance.secret_distribution.weight
        )
        if instance.secret_distribution.kind == "balanced_exact_weight_signed":
            secret_valid = secret_valid and secret.count(1) == secret.count(-1)
    else:
        secret_valid = all(
            value in instance.secret_distribution.alphabet for value in secret
        )
    error_valid = all(
        abs(value) <= instance.error_distribution.bound for value in error
    )
    if instance.error_distribution.kind == "sparse_bounded":
        error_valid = error_valid and sum(value != 0 for value in error) == (
            instance.error_distribution.weight
        )
    return (
        len(secret) == instance.n
        and secret_valid
        and len(error) == instance.m
        and error_valid
    )


def _raw_error_satisfies_public_predicates(
    instance: InstanceSpec,
    error: tuple[int, ...],
) -> bool:
    if len(error) != instance.m or any(type(value) is not int for value in error):
        return False
    if max(abs(value) for value in error) > instance.error.max_abs:
        return False
    if (
        instance.error.max_l1 is not None
        and sum(abs(value) for value in error) > instance.error.max_l1
    ):
        return False
    if (
        instance.error.max_l2_squared is not None
        and sum(value * value for value in error)
        > instance.error.max_l2_squared
    ):
        return False
    if (
        instance.error.max_nonzero is not None
        and sum(value != 0 for value in error) > instance.error.max_nonzero
    ):
        return False
    return True


def _template_instance(template: GenerationTemplate) -> InstanceSpec:
    return InstanceSpec(
        schema_version=1,
        instance_id=template.instance_id,
        n=template.n,
        m=template.m,
        q=template.q,
        matrix=template.matrix,
        b=(0,) * template.m,
        secret_distribution=template.secret_distribution,
        secret=template.secret,
        error_distribution=template.error_distribution,
        error=template.error,
        family=template.family,
        tier=template.tier,
        cohort=template.cohort,
        octave=template.octave,
        runtime_bin=template.runtime_bin,
        analysis_path=template.analysis_path,
        generator_version=template.generator_version,
        calibration_status=template.calibration_status,
        calibration_model_id=template.calibration_model_id,
        predicted_runtime_seconds=template.predicted_runtime_seconds,
        measured_runtime_seconds=template.measured_runtime_seconds,
        instance_digest="",
    )


def _validated_template_instance(template: GenerationTemplate) -> InstanceSpec:
    if not isinstance(template, GenerationTemplate):
        raise TypeError("template must be a GenerationTemplate")
    _preflight_generation_dimensions(template)
    _preflight_generation_work_scalars(template)
    template = _snapshot_generation_alphabets(template)
    record = _instance_to_public_record(_template_instance(template))
    record["instance_digest"] = compute_instance_digest(record)
    instance = _parse_instance(record)
    _validate_generation_work_envelope(instance)
    return instance


def _preflight_generation_dimensions(template: GenerationTemplate) -> None:
    """Reject unsafe dimensions before constructing the placeholder vector."""
    if type(template.n) is not int:
        raise ValueError("n must be an integer")
    if type(template.m) is not int:
        raise ValueError("m must be an integer")
    if type(template.q) is not int:
        raise ValueError("q must be an integer")
    if template.n < 1:
        raise ValueError("n must be at least 1")
    if template.n > MAX_N:
        raise ValueError("n exceeds MAX_N")
    if template.m < 1:
        raise ValueError("m must be at least 1")
    if template.m > MAX_M:
        raise ValueError("m exceeds MAX_M")
    if template.q < 3:
        raise ValueError("q must be at least 3")
    if template.q > MAX_Q:
        raise ValueError("q exceeds MAX_Q")
    if template.m > MAX_MATRIX_ENTRIES // template.n:
        raise ValueError("matrix dimensions exceed MAX_MATRIX_ENTRIES")


def _snapshot_generation_alphabets(
    template: GenerationTemplate,
) -> GenerationTemplate:
    """Take one bounded immutable snapshot of every runtime-untyped alphabet."""
    matrix_alphabet = _bounded_alphabet_snapshot(
        template.matrix.alphabet,
        "matrix",
    )
    distribution_alphabet = _bounded_alphabet_snapshot(
        template.secret_distribution.alphabet,
        "secret distribution",
    )
    predicate_alphabet = _bounded_alphabet_snapshot(
        template.secret.alphabet,
        "secret predicate",
    )
    return replace(
        template,
        matrix=replace(template.matrix, alphabet=matrix_alphabet),
        secret_distribution=replace(
            template.secret_distribution,
            alphabet=distribution_alphabet,
        ),
        secret=replace(template.secret, alphabet=predicate_alphabet),
    )


def _bounded_alphabet_snapshot(
    alphabet: tuple[int, ...],
    context: str,
) -> tuple[int, ...]:
    try:
        advertised_size = len(alphabet)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"{context} alphabet must be a sized sequence") from exc
    if advertised_size > MAX_GENERATION_ALPHABET_SIZE:
        raise ValueError(f"{context} alphabet exceeds the generation limit")
    try:
        iterator = iter(alphabet)
    except TypeError as exc:
        raise ValueError(f"{context} alphabet must be iterable") from exc
    snapshot = tuple(islice(iterator, MAX_GENERATION_ALPHABET_SIZE + 1))
    if len(snapshot) > MAX_GENERATION_ALPHABET_SIZE:
        raise ValueError(f"{context} alphabet exceeds the generation limit")
    return snapshot


def _preflight_generation_work_scalars(template: GenerationTemplate) -> None:
    """Reject unsafe work factors before schema normalization allocates support."""
    secret_distribution = template.secret_distribution
    if (
        secret_distribution.kind == "centered_binomial"
        and type(secret_distribution.eta) is int
        and secret_distribution.eta > MAX_CENTERED_BINOMIAL_ETA
    ):
        raise ValueError("secret eta exceeds the generation limit")
    distribution = template.error_distribution
    if (
        distribution.kind == "centered_binomial"
        and type(distribution.eta) is int
        and distribution.eta > MAX_CENTERED_BINOMIAL_ETA
    ):
        raise ValueError("error eta exceeds the generation limit")
    if (
        distribution.kind == "truncated_discrete_gaussian"
        and type(distribution.bound) is int
        and distribution.bound > MAX_GAUSSIAN_BOUND
    ):
        raise ValueError("Gaussian bound exceeds the generation limit")


def _validate_generation_work_envelope(instance: InstanceSpec) -> None:
    """Validate normalized work caps and symmetric canonical error support."""
    for context, alphabet in (
        ("matrix", instance.matrix.alphabet),
        ("secret distribution", instance.secret_distribution.alphabet),
        ("secret predicate", instance.secret.alphabet),
    ):
        if len(alphabet) > MAX_GENERATION_ALPHABET_SIZE:
            raise ValueError(
                f"{context} alphabet exceeds the generation limit"
            )
    if (
        instance.secret_distribution.kind == "centered_binomial"
        and instance.secret_distribution.eta is not None
        and instance.secret_distribution.eta > MAX_CENTERED_BINOMIAL_ETA
    ):
        raise ValueError("secret eta exceeds the generation limit")
    if (
        instance.error_distribution.kind == "centered_binomial"
        and instance.error_distribution.eta is not None
        and instance.error_distribution.eta > MAX_CENTERED_BINOMIAL_ETA
    ):
        raise ValueError("error eta exceeds the generation limit")
    if (
        instance.error_distribution.kind == "truncated_discrete_gaussian"
        and instance.error_distribution.bound > MAX_GAUSSIAN_BOUND
    ):
        raise ValueError("Gaussian bound exceeds the generation limit")
    if instance.error_distribution.bound > (instance.q - 1) // 2:
        raise ValueError(
            "error support exceeds the canonical centered range"
        )


def _instance_to_public_record(instance: InstanceSpec) -> dict[str, object]:
    return {
        "schema_version": instance.schema_version,
        "instance_id": instance.instance_id,
        "n": instance.n,
        "m": instance.m,
        "q": instance.q,
        "matrix": {
            "kind": instance.matrix.kind,
            "seed_hex": instance.matrix.seed_hex,
            "expansion_domain": instance.matrix.expansion_domain,
            "alphabet": list(instance.matrix.alphabet),
            "row_weight": instance.matrix.row_weight,
        },
        "b": list(instance.b),
        "secret_distribution": {
            "kind": instance.secret_distribution.kind,
            "alphabet": list(instance.secret_distribution.alphabet),
            "weight": instance.secret_distribution.weight,
            "eta": instance.secret_distribution.eta,
        },
        "secret": {
            "kind": instance.secret.kind,
            "alphabet": list(instance.secret.alphabet),
            "min_nonzero": instance.secret.min_nonzero,
            "max_nonzero": instance.secret.max_nonzero,
        },
        "error_distribution": {
            "kind": instance.error_distribution.kind,
            "sigma": instance.error_distribution.sigma,
            "eta": instance.error_distribution.eta,
            "bound": instance.error_distribution.bound,
            "weight": instance.error_distribution.weight,
        },
        "error": {
            "max_abs": instance.error.max_abs,
            "max_l1": instance.error.max_l1,
            "max_l2_squared": instance.error.max_l2_squared,
            "max_nonzero": instance.error.max_nonzero,
        },
        "family": instance.family,
        "tier": instance.tier,
        "cohort": instance.cohort,
        "octave": instance.octave,
        "runtime_bin": instance.runtime_bin,
        "analysis_path": instance.analysis_path,
        "generator_version": instance.generator_version,
        "calibration_status": instance.calibration_status,
        "calibration_model_id": instance.calibration_model_id,
        "predicted_runtime_seconds": instance.predicted_runtime_seconds,
        "measured_runtime_seconds": instance.measured_runtime_seconds,
        "instance_digest": instance.instance_digest,
    }
